//! ShadeNet Shade Tree node firmware for the ESP32 (ESP-IDF, Rust `std`).
//!
//! Boot sequence:
//!   1. chip + heap report, NVS, serial console;
//!   2. `bench` feature: scratch-partition self-test, verifier benchmark without the radio;
//!   3. Wi-Fi driver up in station mode (not connected);
//!   4. `bench` feature: one scan, verifier benchmark beside the running radio;
//!   5. connect with the credentials stored in NVS, if any, and start SNTP;
//!   6. `DONE` marker, then the node (`node::run`), which runs until power-off.
//!
//! Every machine-readable line starts with an upper-case marker followed by `key=value`
//! pairs; see README.md for the list.

mod http;
mod node;
mod platform;

#[cfg(feature = "bench")]
mod bench;
#[cfg(feature = "bench")]
mod rln_verify;

use std::time::Duration;

use anyhow::Result;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::nvs::EspDefaultNvsPartition;

use platform::WifiStation;

// Counts Rust heap bytes so the benchmarks can attribute a peak to one operation.
#[cfg(feature = "bench")]
#[global_allocator]
static ALLOCATOR: platform::alloc_track::TrackingAllocator =
    platform::alloc_track::TrackingAllocator;

fn main() {
    // Required once: keeps esp-idf-sys runtime patches from being discarded by the linker.
    esp_idf_svc::sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    if let Err(error) = run() {
        println!("FATAL msg=\"{error:#}\"");
    }
    // Returning from `main` would end the main task; stay up so the console keeps working.
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn run() -> Result<()> {
    println!(
        "BOOT firmware={} version={} profile={} opt_level={} bench={}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("FW_PROFILE"),
        env!("FW_OPT_LEVEL"),
        cfg!(feature = "bench") as u8,
    );
    platform::log_chip_info();
    platform::log_heap("boot");

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    platform::log_heap("after_event_loop");
    let nvs = EspDefaultNvsPartition::take()?;
    platform::log_heap("after_nvs");
    platform::console_start(nvs.clone())?;
    platform::log_heap("after_console");

    #[cfg(feature = "bench")]
    {
        thread_exit_exercise();
        scratch_self_test();
        report("bench pre_wifi", bench::run("pre_wifi"));
        platform::log_heap("after_bench_pre_wifi");
    }

    // The heap the node lives in: Wi-Fi driver initialised and started, station mode.
    let before_wifi = platform::heap_free();
    let mut wifi = WifiStation::start(peripherals.modem, sysloop, nvs.clone())?;
    println!(
        "WIFI state=started mode=sta connected=0 heap_cost={} free={} largest={} min_free={}",
        before_wifi.saturating_sub(platform::heap_free()),
        platform::heap_free(),
        platform::heap_largest(),
        platform::heap_min_free(),
    );

    #[cfg(feature = "bench")]
    {
        match wifi.scan() {
            Ok(scan) => println!(
                "WIFI state=scanned aps={} strongest_rssi={} free={} largest={} min_free={}",
                scan.access_points,
                scan.strongest_rssi
                    .map_or("none".to_string(), |rssi| rssi.to_string()),
                platform::heap_free(),
                platform::heap_largest(),
                platform::heap_min_free(),
            ),
            Err(error) => println!("WIFI state=scan_failed msg=\"{error:#}\""),
        }
        report("bench wifi_started", bench::run("wifi_started"));
        platform::log_heap("after_bench_wifi_started");
    }

    // Kept alive for as long as the node runs; dropping it stops SNTP.
    let mut _sntp = None;
    match platform::wifi_credentials_load(&nvs)? {
        None => println!(
            "WIFI state=no_credentials action=skipping_connect hint=\"send: wifi <ssid> <password>\""
        ),
        Some(credentials) => {
            // An association attempt can time out for no better reason than a busy channel;
            // a node with credentials keeps trying instead of sitting dark.
            let mut attempt = 0u32;
            let mut result = wifi.connect(&credentials);
            while let Err(error) = &result {
                attempt += 1;
                println!("WIFI state=connect_failed attempt={attempt} msg=\"{error:#}\"");
                std::thread::sleep(Duration::from_secs(u64::from(attempt.min(6)) * 5));
                result = wifi.reconnect();
            }
            if let Ok(ip) = result {
                println!("WIFI state=connected ip={ip} free={}", platform::heap_free());
                let sntp = platform::sntp_start()?;
                let synced = platform::sntp_wait_synced(&sntp, Duration::from_secs(15));
                println!("SNTP synced={} free={}", synced as u8, platform::heap_free());
                _sntp = Some(sntp);
            }
        }
    }

    println!(
        "STACK main_free_min={} idle0_free_min={} idle1_free_min={}",
        platform::stack_high_water(),
        platform::idle_stack_high_water(0),
        platform::idle_stack_high_water(1),
    );
    platform::log_heap("done");
    println!("DONE connected={}", wifi.is_connected() as u8);

    if !wifi.is_connected() {
        println!("NODE state=waiting reason=no_network hint=\"send: wifi <ssid> <password>\"");
        idle_forever(wifi);
    }
    // Does not return while the node is up: `wifi` and `_sntp` stop when dropped.
    node::run(node::Platform {
        wifi,
        nvs,
        scratch: platform::Scratch::open()?,
    })
}

/// No network: keep the radio and the console alive so credentials can be entered.
fn idle_forever(_wifi: WifiStation) -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(feature = "bench")]
fn report(what: &str, result: Result<()>) {
    if let Err(error) = result {
        println!("FAIL what=\"{what}\" msg=\"{error:#}\"");
    }
}

#[cfg(feature = "bench")]
fn scratch_self_test() {
    let result = platform::Scratch::open().and_then(|mut scratch| {
        let test = scratch.self_test()?;
        println!(
            "SCRATCH ok=1 address={:#x} len={} test_bytes={} erase_ms={:.1} write_ms={:.1} read_ms={:.1}",
            scratch.address(),
            scratch.len(),
            test.bytes,
            test.erase_ms,
            test.write_ms,
            test.read_ms,
        );
        Ok(())
    });
    report("scratch self-test", result);
}

/// Spawn and join one `std::thread` that uses a thread-local with a destructor, so the stack
/// high-water marks printed at the end include whatever thread teardown costs (on ESP-IDF part
/// of it can run on the idle task).
#[cfg(feature = "bench")]
fn thread_exit_exercise() {
    use std::cell::RefCell;
    thread_local!(static SCRATCHPAD: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) });

    let before = platform::heap_free();
    let spawned = std::thread::Builder::new().stack_size(4096).spawn(|| {
        SCRATCHPAD.with(|pad| pad.borrow_mut().extend_from_slice(&[0xA5; 64]));
        platform::stack_high_water()
    });
    let joined = spawned.map_err(anyhow::Error::from).and_then(|handle| {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("thread panicked"))
    });
    // Give the idle task a moment to reclaim the finished thread's stack.
    std::thread::sleep(Duration::from_millis(50));
    match joined {
        Ok(stack_free_min) => println!(
            "THREAD ok=1 stack_size=4096 stack_free_min={stack_free_min} heap_not_returned={}",
            before.saturating_sub(platform::heap_free())
        ),
        Err(error) => println!("FAIL what=\"thread exercise\" msg=\"{error:#}\""),
    }
}
