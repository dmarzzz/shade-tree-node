//! Device platform layer: heap/stack introspection, chip info, Wi-Fi station bring-up with
//! credentials from NVS, SNTP, the UART0 command console, and the raw `scratch` flash partition.
//!
//! Everything here is board plumbing that both the benchmarks and the node proper use. All
//! machine-readable output is a single line that starts with an upper-case marker
//! (`HEAP`, `CHIP`, `WIFI`, `SCRATCH`, `CONSOLE`, ...) followed by `key=value` pairs.

// This is the platform API the node will build on; not every helper has a caller yet.
#![allow(dead_code)]

use std::ffi::CStr;
use std::io::BufRead;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::modem::Modem;
use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sntp::{EspSntp, SyncStatus};
use esp_idf_svc::sys;
use esp_idf_svc::wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi};

// ---------------------------------------------------------------------------------------------
// Heap / stack / time
// ---------------------------------------------------------------------------------------------

/// Free bytes in the default heap right now.
pub fn heap_free() -> usize {
    unsafe { sys::esp_get_free_heap_size() as usize }
}

/// Largest single allocation the default heap could satisfy right now (fragmentation gauge).
pub fn heap_largest() -> usize {
    unsafe { sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_DEFAULT) }
}

/// ESP-IDF's low-water mark of the free heap since boot. It is the sum of the per-region
/// minimums, which need not have happened at the same time, so it is a pessimistic bound on
/// the real minimum; use [`HeapDipWatch`] to measure one operation.
pub fn heap_min_free() -> usize {
    unsafe { sys::esp_get_minimum_free_heap_size() as usize }
}

/// Measures how far the free heap dips during one operation, counting every allocation in the
/// system (Rust and C, all tasks).
///
/// `heap_min_free()` cannot do this: it never resets, and it is the sum of the low-water marks
/// of the separate heap regions, each possibly reached at a different moment, so it overstates
/// the real peak. This uses ESP-IDF's local low-water monitoring, which restarts the marks.
pub struct HeapDipWatch {
    free_at_start: usize,
}

impl HeapDipWatch {
    pub fn start() -> Self {
        unsafe { sys::heap_caps_monitor_local_minimum_free_size_start() };
        Self {
            free_at_start: heap_free(),
        }
    }

    /// Bytes by which the free heap dropped below its starting level, at worst, since `start`.
    pub fn finish(self) -> usize {
        let low = heap_min_free();
        unsafe { sys::heap_caps_monitor_local_minimum_free_size_stop() };
        self.free_at_start.saturating_sub(low)
    }
}

/// Print one `HEAP` line.
pub fn log_heap(tag: &str) {
    println!(
        "HEAP tag={tag} free={} largest={} min_free={}",
        heap_free(),
        heap_largest(),
        heap_min_free()
    );
}

/// Bytes of the calling task's stack that have never been touched (0 means it overflowed).
pub fn stack_high_water() -> usize {
    unsafe { sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) as usize }
}

/// Never-touched stack bytes of the idle task of `core`.
pub fn idle_stack_high_water(core: i32) -> usize {
    unsafe {
        let idle = sys::xTaskGetIdleTaskHandleForCore(core);
        sys::uxTaskGetStackHighWaterMark(idle) as usize
    }
}

/// Microseconds since boot (64-bit, monotonic, 1 us resolution).
pub fn now_us() -> i64 {
    unsafe { sys::esp_timer_get_time() }
}

/// Restart the chip (does not return).
pub fn reboot() -> ! {
    unsafe { sys::esp_restart() }
}

// ---------------------------------------------------------------------------------------------
// Chip info
// ---------------------------------------------------------------------------------------------

// `esp_chip_info.h` and `esp_private/esp_clk.h` are not part of the generated esp-idf-sys
// bindings, so the few items needed are declared here (ESP-IDF v5.5 layout).
#[repr(C)]
#[derive(Default)]
struct RawChipInfo {
    model: u32,
    features: u32,
    revision: u16,
    cores: u8,
}

extern "C" {
    fn esp_chip_info(out_info: *mut RawChipInfo);
    /// CPU frequency in Hz as tracked by the clock driver.
    fn esp_clk_cpu_freq() -> core::ffi::c_int;
}

const CHIP_FEATURE_EMB_FLASH: u32 = 1 << 0;
const CHIP_FEATURE_WIFI_BGN: u32 = 1 << 1;
const CHIP_FEATURE_BLE: u32 = 1 << 4;
const CHIP_FEATURE_BT: u32 = 1 << 5;

#[derive(Debug, Clone)]
pub struct ChipInfo {
    pub model: &'static str,
    /// Silicon revision as `major * 100 + minor` (301 = v3.1).
    pub revision: u16,
    pub cores: u8,
    /// CPU frequency the clock driver reports as in effect.
    pub cpu_mhz: u32,
    /// CPU frequency measured by counting CPU cycles (CCOUNT) against the 1 MHz system timer,
    /// which runs from the APB clock and is independent of the CPU clock setting.
    pub cpu_mhz_measured: f32,
    /// Size of the main SPI flash as configured in the image header, in bytes.
    pub flash_bytes: u32,
    /// Size of the main SPI flash as reported by the chip's JEDEC ID, in bytes.
    pub flash_physical_bytes: u32,
    pub embedded_flash: bool,
    pub wifi: bool,
    pub bluetooth: bool,
    pub idf_version: String,
}

/// Count CPU cycles over a short busy-wait on the microsecond timer.
fn measure_cpu_mhz() -> f32 {
    const WINDOW_US: i64 = 20_000; // well under the 2^32-cycle wrap (17.9 s at 240 MHz)
    let t0 = now_us();
    let c0 = unsafe { sys::xthal_get_ccount() };
    let mut t1 = now_us();
    while t1 - t0 < WINDOW_US {
        t1 = now_us();
    }
    let c1 = unsafe { sys::xthal_get_ccount() };
    c1.wrapping_sub(c0) as f32 / (t1 - t0) as f32
}

pub fn chip_info() -> ChipInfo {
    let mut raw = RawChipInfo::default();
    unsafe { esp_chip_info(&mut raw) };
    let model = match raw.model {
        1 => "ESP32",
        2 => "ESP32-S2",
        5 => "ESP32-C3",
        9 => "ESP32-S3",
        _ => "unknown",
    };

    let mut flash_bytes = 0u32;
    let mut flash_physical_bytes = 0u32;
    // A null chip pointer means the main (boot) flash chip.
    unsafe {
        sys::esp_flash_get_size(core::ptr::null_mut(), &mut flash_bytes);
        sys::esp_flash_get_physical_size(core::ptr::null_mut(), &mut flash_physical_bytes);
    }

    let idf_version = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_string_lossy()
        .into_owned();

    ChipInfo {
        model,
        revision: raw.revision,
        cores: raw.cores,
        cpu_mhz: (unsafe { esp_clk_cpu_freq() } / 1_000_000) as u32,
        cpu_mhz_measured: measure_cpu_mhz(),
        flash_bytes,
        flash_physical_bytes,
        embedded_flash: raw.features & CHIP_FEATURE_EMB_FLASH != 0,
        wifi: raw.features & CHIP_FEATURE_WIFI_BGN != 0,
        bluetooth: raw.features & (CHIP_FEATURE_BT | CHIP_FEATURE_BLE) != 0,
        idf_version,
    }
}

pub fn log_chip_info() -> ChipInfo {
    let chip = chip_info();
    println!(
        "CHIP model={} rev={}.{} cores={} cpu_mhz={} cpu_mhz_measured={:.1} flash_bytes={} flash_physical_bytes={} emb_flash={} wifi={} bt_capable={} idf={}",
        chip.model,
        chip.revision / 100,
        chip.revision % 100,
        chip.cores,
        chip.cpu_mhz,
        chip.cpu_mhz_measured,
        chip.flash_bytes,
        chip.flash_physical_bytes,
        chip.embedded_flash as u8,
        chip.wifi as u8,
        chip.bluetooth as u8,
        chip.idf_version,
    );
    chip
}

// ---------------------------------------------------------------------------------------------
// Wi-Fi credentials in NVS
// ---------------------------------------------------------------------------------------------

/// NVS namespace of all node settings.
pub const NVS_NAMESPACE: &str = "shadenet";
const KEY_SSID: &str = "ssid";
const KEY_PASS: &str = "pass";

pub struct WifiCredentials {
    pub ssid: String,
    pub pass: String,
}

fn open_nvs(nvs: &EspDefaultNvsPartition) -> Result<EspNvs<NvsDefault>> {
    EspNvs::new(nvs.clone(), NVS_NAMESPACE, true).context("open NVS namespace")
}

/// Read the stored Wi-Fi credentials; `None` if no SSID has been stored.
pub fn wifi_credentials_load(nvs: &EspDefaultNvsPartition) -> Result<Option<WifiCredentials>> {
    let store = open_nvs(nvs)?;
    let mut ssid = [0u8; 33];
    let mut pass = [0u8; 65];
    let Some(ssid) = store.get_str(KEY_SSID, &mut ssid)? else {
        return Ok(None);
    };
    if ssid.is_empty() {
        return Ok(None);
    }
    let pass = store.get_str(KEY_PASS, &mut pass)?.unwrap_or("");
    Ok(Some(WifiCredentials {
        ssid: ssid.to_owned(),
        pass: pass.to_owned(),
    }))
}

pub fn wifi_credentials_store(nvs: &EspDefaultNvsPartition, ssid: &str, pass: &str) -> Result<()> {
    ensure!(
        !ssid.is_empty() && ssid.len() <= 32,
        "SSID must be 1..=32 bytes"
    );
    ensure!(pass.len() <= 64, "password must be at most 64 bytes");
    let store = open_nvs(nvs)?;
    store.set_str(KEY_SSID, ssid)?;
    store.set_str(KEY_PASS, pass)?;
    Ok(())
}

/// Erase the stored credentials. Returns whether there was anything to erase.
pub fn wifi_credentials_clear(nvs: &EspDefaultNvsPartition) -> Result<bool> {
    let store = open_nvs(nvs)?;
    let had_ssid = store.remove(KEY_SSID)?;
    let had_pass = store.remove(KEY_PASS)?;
    Ok(had_ssid || had_pass)
}

// ---------------------------------------------------------------------------------------------
// Wi-Fi station
// ---------------------------------------------------------------------------------------------

/// The Wi-Fi driver in station mode. Creating it initialises and starts the radio; it stays
/// started (and its buffers stay allocated) for as long as this value lives.
pub struct WifiStation {
    wifi: BlockingWifi<EspWifi<'static>>,
}

/// Result of one scan. SSIDs are deliberately not kept: the logs get shared.
pub struct ScanSummary {
    pub access_points: usize,
    pub strongest_rssi: Option<i8>,
}

impl WifiStation {
    /// Initialise the driver, select station mode and start it, without connecting.
    pub fn start(
        modem: Modem<'static>,
        sysloop: EspSystemEventLoop,
        nvs: EspDefaultNvsPartition,
    ) -> Result<Self> {
        let esp_wifi = EspWifi::new(modem, sysloop.clone(), Some(nvs)).context("wifi init")?;
        // Keep the driver's own copy of the station config in RAM: credentials live only under
        // our NVS namespace, and reconfiguring does not wear the flash.
        sys::esp!(unsafe { sys::esp_wifi_set_storage(sys::wifi_storage_t_WIFI_STORAGE_RAM) })?;
        let mut wifi = BlockingWifi::wrap(esp_wifi, sysloop)?;
        // Placeholder station config (no SSID, open) so the driver can start and scan.
        wifi.set_configuration(&Configuration::Client(ClientConfiguration {
            auth_method: AuthMethod::None,
            ..Default::default()
        }))?;
        wifi.start().context("wifi start")?;
        Ok(Self { wifi })
    }

    /// Run one blocking active scan over all channels.
    pub fn scan(&mut self) -> Result<ScanSummary> {
        let found = self.wifi.scan().context("wifi scan")?;
        Ok(ScanSummary {
            access_points: found.len(),
            strongest_rssi: found.iter().map(|ap| ap.signal_strength).max(),
        })
    }

    /// Associate with the given network and wait for DHCP. Returns the station's IPv4 address.
    pub fn connect(&mut self, creds: &WifiCredentials) -> Result<Ipv4Addr> {
        let config = ClientConfiguration {
            ssid: creds
                .ssid
                .as_str()
                .try_into()
                .map_err(|_| anyhow!("SSID longer than 32 bytes"))?,
            password: creds
                .pass
                .as_str()
                .try_into()
                .map_err(|_| anyhow!("password longer than 64 bytes"))?,
            // Threshold, not an exact match: refuse WEP/WPA1 when a password is set.
            auth_method: if creds.pass.is_empty() {
                AuthMethod::None
            } else {
                AuthMethod::WPA2Personal
            },
            ..Default::default()
        };
        self.wifi
            .set_configuration(&Configuration::Client(config))?;
        self.wifi.connect().context("wifi connect")?;
        self.wifi.wait_netif_up().context("wait for DHCP")?;
        let ip = self.wifi.wifi().sta_netif().get_ip_info()?.ip;
        Ok(ip)
    }

    pub fn is_connected(&self) -> bool {
        self.wifi.is_connected().unwrap_or(false)
    }

    /// Associate again with the network already configured by `connect` (after the access
    /// point dropped the station, or a first attempt timed out).
    pub fn reconnect(&mut self) -> Result<Ipv4Addr> {
        let _ = self.wifi.disconnect();
        self.wifi.connect().context("wifi connect")?;
        self.wifi.wait_netif_up().context("wait for DHCP")?;
        Ok(self.wifi.wifi().sta_netif().get_ip_info()?.ip)
    }
}

// ---------------------------------------------------------------------------------------------
// SNTP
// ---------------------------------------------------------------------------------------------

/// Start the SNTP client with the default pool servers. Call once the station has an address.
/// Keep the returned handle alive; dropping it stops the client.
pub fn sntp_start() -> Result<EspSntp<'static>> {
    Ok(EspSntp::new_default()?)
}

/// Wait until the wall clock has been set by SNTP. Returns `false` on timeout.
pub fn sntp_wait_synced(sntp: &EspSntp<'static>, timeout: Duration) -> bool {
    let started = Instant::now();
    while sntp.get_sync_status() != SyncStatus::Completed {
        if started.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

// ---------------------------------------------------------------------------------------------
// Serial console (UART0)
// ---------------------------------------------------------------------------------------------

const CONSOLE_STACK: usize = 6144;
const CONSOLE_HELP: &str = "commands: wifi <ssid> [password] | wifi-clear | set <key> <value> | get <key> | unset <key> | drain on|off | heap | reboot | help";

/// The operator's drain switch (`drain on` / `drain off`), read by the node loop. Not stored:
/// a reboot clears it.
pub static DRAIN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Node settings the console may store (see `node.rs` for what each means). Values take effect
/// at the next boot.
const SETTING_KEYS: [&str; 19] = [
    "members",
    "roots",
    "epoch",
    "allow",
    "deny",
    "bandwidth",
    "intro_points",
    "elders",
    "operator",
    "operator_sig",
    "weight",
    "region",
    "contract",
    "rpc",
    "slash_key",
    "canary",
    "sessions",
    "receipts",
    "conns",
];
/// Settings that are secrets: `get` says whether they are set, never what they are.
const SECRET_KEYS: [&str; 1] = ["slash_key"];

/// Start the line-based command console on UART0 in its own small thread.
///
/// Commands (one per line):
///   `wifi <ssid> [password]`  store credentials in NVS and reboot (no spaces in either)
///   `wifi-clear`              erase stored credentials
///   `heap`                    print heap statistics
///   `reboot`                  restart the chip
pub fn console_start(nvs: EspDefaultNvsPartition) -> Result<()> {
    // Without a UART driver, stdin reads never block (they return 0 bytes immediately) and
    // input is limited to whatever fits the hardware FIFO between polls. Install the driver
    // with a small RX ring buffer and route the VFS through it: reads then block the console
    // thread until a line arrives, at no CPU cost.
    unsafe {
        sys::esp!(sys::uart_driver_install(
            sys::uart_port_t_UART_NUM_0,
            2048,
            0,
            0,
            core::ptr::null_mut(),
            0
        ))
        .context("install UART0 driver")?;
        sys::uart_vfs_dev_use_driver(sys::uart_port_t_UART_NUM_0 as _);
    }

    let previous = ThreadSpawnConfiguration::get().unwrap_or_default();
    ThreadSpawnConfiguration {
        name: Some(c"console"),
        stack_size: CONSOLE_STACK,
        priority: 2,
        ..Default::default()
    }
    .set()?;
    let spawned = std::thread::Builder::new()
        .stack_size(CONSOLE_STACK)
        .spawn(move || console_loop(nvs));
    previous.set()?;
    spawned.context("spawn console thread")?;
    println!("CONSOLE ready {CONSOLE_HELP}");
    Ok(())
}

fn console_loop(nvs: EspDefaultNvsPartition) {
    let stdin = std::io::stdin();
    let mut line = String::with_capacity(128);
    loop {
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(n) if n > 0 => {}
            // Nothing to read (or a transient error): do not spin.
            _ => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        }
        let command = line.trim();
        if command.is_empty() {
            continue;
        }
        if let Err(error) = console_command(command, &nvs) {
            println!("CONSOLE error msg=\"{error:#}\"");
        }
    }
}

fn console_command(command: &str, nvs: &EspDefaultNvsPartition) -> Result<()> {
    let mut words = command.split_whitespace();
    match words.next().unwrap_or("") {
        "wifi" => {
            // Space-separated for typing by hand; tab-separated (what tools/provision.py
            // sends) when the name or the password contains spaces.
            let (ssid, pass) = if command.contains('\t') {
                let mut fields = command.split('\t').skip(1);
                (fields.next().unwrap_or(""), fields.next().unwrap_or(""))
            } else {
                let ssid = words.next().unwrap_or("");
                let pass = words.next().unwrap_or("");
                ensure!(
                    words.next().is_none(),
                    "usage: wifi <ssid> [password] (use tools/provision.py if either has spaces)"
                );
                (ssid, pass)
            };
            ensure!(!ssid.is_empty(), "usage: wifi <ssid> [password]");
            wifi_credentials_store(nvs, ssid, pass)?;
            // Never echo the password.
            println!(
                "CONSOLE ok cmd=wifi ssid_len={} pass_len={} rebooting=1",
                ssid.len(),
                pass.len()
            );
            std::thread::sleep(Duration::from_millis(200));
            reboot();
        }
        "wifi-clear" => {
            let erased = wifi_credentials_clear(nvs)?;
            println!("CONSOLE ok cmd=wifi-clear erased={}", erased as u8);
        }
        "set" => {
            let key = words
                .next()
                .ok_or_else(|| anyhow!("usage: set <key> <value>"))?;
            ensure!(
                SETTING_KEYS.contains(&key),
                "unknown setting {key:?}; one of {SETTING_KEYS:?}"
            );
            let value = command
                .splitn(3, char::is_whitespace)
                .nth(2)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow!("usage: set <key> <value>"))?;
            open_nvs(nvs)?.set_str(key, value)?;
            println!(
                "CONSOLE ok cmd=set key={key} len={} applies=next_boot",
                value.len()
            );
        }
        "get" => {
            let key = words.next().ok_or_else(|| anyhow!("usage: get <key>"))?;
            ensure!(
                SETTING_KEYS.contains(&key),
                "unknown setting {key:?}; one of {SETTING_KEYS:?}"
            );
            let store = open_nvs(nvs)?;
            match store.str_len(key)? {
                Some(len) => {
                    let mut buf = vec![0u8; len + 1];
                    let value = store.get_str(key, &mut buf)?.unwrap_or("");
                    if SECRET_KEYS.contains(&key) {
                        println!("CONSOLE ok cmd=get key={key} set=1 len={}", value.len());
                    } else {
                        println!("CONSOLE ok cmd=get key={key} value={value}");
                    }
                }
                None => println!("CONSOLE ok cmd=get key={key} unset=1"),
            }
        }
        "unset" => {
            let key = words.next().ok_or_else(|| anyhow!("usage: unset <key>"))?;
            ensure!(
                SETTING_KEYS.contains(&key),
                "unknown setting {key:?}; one of {SETTING_KEYS:?}"
            );
            let removed = open_nvs(nvs)?.remove(key)?;
            println!("CONSOLE ok cmd=unset key={key} removed={}", removed as u8);
        }
        "drain" => {
            let on = match words.next() {
                Some("on") => true,
                Some("off") => false,
                _ => bail!("usage: drain on|off"),
            };
            DRAIN.store(on, core::sync::atomic::Ordering::Relaxed);
            println!("CONSOLE ok cmd=drain on={}", on as u8);
        }
        "heap" => {
            println!(
                "CONSOLE ok cmd=heap free={} largest={} min_free={} console_stack_hwm={}",
                heap_free(),
                heap_largest(),
                heap_min_free(),
                stack_high_water()
            );
        }
        "reboot" => {
            println!("CONSOLE ok cmd=reboot");
            std::thread::sleep(Duration::from_millis(200));
            reboot();
        }
        "help" => println!("CONSOLE ok cmd=help {CONSOLE_HELP}"),
        other => bail!("unknown command {other:?}; {CONSOLE_HELP}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Scratch partition
// ---------------------------------------------------------------------------------------------

/// The raw `scratch` data partition (see `partitions.csv`): plain NOR flash with no filesystem
/// and no wear levelling. A byte can only be written after its 4 KB sector has been erased.
pub struct Scratch {
    partition: *const sys::esp_partition_t,
}

// The partition record is a static, immutable table entry owned by ESP-IDF, and the partition
// API takes the flash driver's own lock.
unsafe impl Send for Scratch {}

pub struct ScratchSelfTest {
    pub bytes: usize,
    pub erase_ms: f32,
    pub write_ms: f32,
    pub read_ms: f32,
}

impl Scratch {
    pub const LABEL: &'static CStr = c"scratch";
    /// Erase granularity of the flash chip.
    pub const SECTOR: usize = 4096;

    /// Find the partition by name.
    pub fn open() -> Result<Self> {
        let partition = unsafe {
            sys::esp_partition_find_first(
                sys::esp_partition_type_t_ESP_PARTITION_TYPE_DATA,
                sys::esp_partition_subtype_t_ESP_PARTITION_SUBTYPE_ANY,
                Self::LABEL.as_ptr(),
            )
        };
        ensure!(
            !partition.is_null(),
            "no data partition named \"scratch\" in the partition table"
        );
        Ok(Self { partition })
    }

    /// Size of the partition in bytes.
    pub fn len(&self) -> usize {
        unsafe { (*self.partition).size as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Flash offset of the partition (informational).
    pub fn address(&self) -> usize {
        unsafe { (*self.partition).address as usize }
    }

    fn check_range(&self, offset: usize, len: usize) -> Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("range overflows"))?;
        ensure!(
            end <= self.len(),
            "range {offset:#x}+{len:#x} is outside the scratch partition"
        );
        Ok(())
    }

    /// Erase the whole partition (every byte becomes 0xFF).
    pub fn erase_all(&mut self) -> Result<()> {
        self.erase_range(0, self.len())
    }

    /// Erase `len` bytes at `offset`; both must be multiples of [`Self::SECTOR`].
    pub fn erase_range(&mut self, offset: usize, len: usize) -> Result<()> {
        self.check_range(offset, len)?;
        ensure!(
            offset % Self::SECTOR == 0 && len % Self::SECTOR == 0,
            "erase range must be aligned to {} bytes",
            Self::SECTOR
        );
        sys::esp!(unsafe { sys::esp_partition_erase_range(self.partition, offset, len) })?;
        Ok(())
    }

    /// Program `data` at `offset`. The target bytes must be erased (NOR flash can only clear bits).
    pub fn write(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        self.check_range(offset, data.len())?;
        sys::esp!(unsafe {
            sys::esp_partition_write(self.partition, offset, data.as_ptr().cast(), data.len())
        })?;
        Ok(())
    }

    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<()> {
        self.check_range(offset, buf.len())?;
        sys::esp!(unsafe {
            sys::esp_partition_read(self.partition, offset, buf.as_mut_ptr().cast(), buf.len())
        })?;
        Ok(())
    }

    /// Erase the first 64 KB, check it reads back blank, write a pattern, read it back and
    /// compare. Leaves the pattern in place. Timings are wall-clock.
    pub fn self_test(&mut self) -> Result<ScratchSelfTest> {
        const BYTES: usize = 64 * 1024;
        const CHUNK: usize = Scratch::SECTOR;
        ensure!(
            self.len() >= BYTES,
            "scratch partition is smaller than 64 KB"
        );
        // Heap, not stack: this may run on a small thread.
        let mut expected = vec![0u8; CHUNK];
        let mut actual = vec![0u8; CHUNK];
        let pattern = |offset: usize, out: &mut [u8]| {
            for (i, byte) in out.iter_mut().enumerate() {
                let n = (offset + i) as u32;
                *byte = (n.wrapping_mul(2654435761) >> 24) as u8;
            }
        };

        let t0 = now_us();
        self.erase_range(0, BYTES)?;
        let t1 = now_us();
        for offset in (0..BYTES).step_by(CHUNK) {
            self.read(offset, &mut actual)?;
            ensure!(
                actual.iter().all(|b| *b == 0xFF),
                "sector at {offset:#x} is not blank after erase"
            );
        }

        let t2 = now_us();
        for offset in (0..BYTES).step_by(CHUNK) {
            pattern(offset, &mut expected);
            self.write(offset, &expected)?;
        }
        let t3 = now_us();
        for offset in (0..BYTES).step_by(CHUNK) {
            self.read(offset, &mut actual)?;
            pattern(offset, &mut expected);
            ensure!(
                actual == expected,
                "read-back mismatch in the sector at {offset:#x}"
            );
        }
        let t4 = now_us();

        Ok(ScratchSelfTest {
            bytes: BYTES,
            erase_ms: (t1 - t0) as f32 / 1000.0,
            write_ms: (t3 - t2) as f32 / 1000.0,
            read_ms: (t4 - t3) as f32 / 1000.0,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Rust heap accounting (benchmarks only)
// ---------------------------------------------------------------------------------------------

/// A `#[global_allocator]` wrapper that counts live Rust heap bytes and their peak. ESP-IDF's
/// own low-water mark cannot be reset, so it cannot attribute a peak to one operation; this can.
/// It counts requested sizes (allocator bookkeeping is not included) for Rust allocations only.
#[cfg(feature = "bench")]
pub mod alloc_track {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    static LIVE: AtomicUsize = AtomicUsize::new(0);
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    pub struct TrackingAllocator;

    fn grow(bytes: usize) {
        let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
        PEAK.fetch_max(live, Relaxed);
    }

    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = System.alloc(layout);
            if !ptr.is_null() {
                grow(layout.size());
            }
            ptr
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let ptr = System.alloc_zeroed(layout);
            if !ptr.is_null() {
                grow(layout.size());
            }
            ptr
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            System.dealloc(ptr, layout);
            LIVE.fetch_sub(layout.size(), Relaxed);
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let new_ptr = System.realloc(ptr, layout, new_size);
            if !new_ptr.is_null() {
                LIVE.fetch_sub(layout.size(), Relaxed);
                grow(new_size);
            }
            new_ptr
        }
    }

    /// Rust heap bytes currently allocated.
    pub fn live() -> usize {
        LIVE.load(Relaxed)
    }

    /// Highest value of [`live`] since the last [`reset_peak`].
    pub fn peak() -> usize {
        PEAK.load(Relaxed)
    }

    /// Restart peak tracking from the current live size.
    pub fn reset_peak() {
        PEAK.store(LIVE.load(Relaxed), Relaxed);
    }
}
