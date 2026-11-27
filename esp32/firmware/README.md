# shadenet-esp32 firmware

ESP-IDF `std` Rust firmware that runs a ShadeNet "Shade Tree node" on an ESP32. It supplies the
device platform (boot, heap accounting, Wi-Fi station, NVS keys and settings, serial console,
raw flash partition) and runs the portable node (`../crates/microtor`, `../crates/shadenode`)
on it; `src/node.rs` is the glue. The project README one level up describes the node and what
has been verified end to end.

The rest of this file documents the platform and the on-device benchmark of the stock
arkworks Groth16 verifier, which is behind the `bench` cargo feature
(`cargo build --release --features bench`). Those numbers were taken before the node was
integrated; the node itself now uses a table-free pairing (`shadenode::rln`) that trades
about 250 ms per proof for roughly 110 KB less heap, and its image is 1.56 MB.

Everything below was measured on one board: ESP32-D0WD-V3 rev 3.1, 2 cores at 240 MHz, 4 MB
flash, no PSRAM, CP2102 USB bridge on `/dev/cu.usbserial-0001`, macOS host.

## Benchmark results (stock arkworks verifier, `--features bench`)

| | |
|---|---|
| Groth16 RLN verification, 240 MHz, `opt-level = "s"` | **862 ms** (median of 5, spread < 1 ms) |
| ... the same with the Wi-Fi driver started | 862 ms |
| ... the same at `opt-level = 3` | 4783 ms (5.5x slower, see below) |
| Proof parsing (JSON + curve/subgroup checks), per request | 96 ms |
| Verification key parse + prepare, once at boot | 798 ms |
| Free heap at boot / largest block | 243.9 KB / 114.7 KB |
| Free heap with Wi-Fi started (STA, not connected) / largest block | 195.6 KB / 110.6 KB |
| Heap held by the prepared verification key | 33.8 KB (49.6 KB before `shrink_to_fit`) |
| Extra heap during one verification | 58.3 KB |
| Lowest free heap seen while verifying beside the radio | 85.3 KB |
| Main-task stack used by key preparation + verification | 21.7 KB of 32 KB |
| Application image | 1,047,392 bytes = 40.0 % of the 2.5 MB factory partition |

Verification fits beside the radio with room to spare, and `opt-level = "s"` is both the
fastest and (bar `"z"`) the smallest build.

## Layout

```
Cargo.toml            standalone project (own empty [workspace]); feature: bench (off by default)
.cargo/config.toml    target xtensa-esp32-espidf, build-std, ESP-IDF version, cargo runner
rust-toolchain.toml   channel = "esp"
build.rs              embuild glue; exports the cargo profile name to the firmware
sdkconfig.defaults    every non-default ESP-IDF option, with the reason for each
partitions.csv        4 MB partition table
src/main.rs           boot sequence, then node::run()
src/node.rs           the node on the device: NVS keys and settings, flash scratch, status line
src/http.rs           HTTPS for chain reads and the canary (ESP-IDF client, certificate bundle)
src/platform.rs       heap/stack helpers, chip info, Wi-Fi STA, NVS credentials, SNTP,
                      UART0 console, Scratch partition, counting allocator
src/bench.rs          verifier benchmark                         (feature "bench")
src/rln_verify.rs     vendored upstream verify.rs, MIT           (feature "bench")
fixtures/             proof.json, envelope.json, gen/ (host generator)
tools/flash.sh        flash a build (also the cargo runner)
tools/capture.py      reset the board and capture UART0 to a file
tools/provision.py    store Wi-Fi credentials and node settings over the serial console
```

## Toolchain

| Component | Version |
|---|---|
| Rust | `esp` toolchain from espup: rustc 1.97.0-nightly (8ea53bcd7 2026-07-08), LLVM 21.1.3 |
| Target | `xtensa-esp32-espidf`, `-Z build-std=std,panic_abort` |
| ESP-IDF | v5.5.5, fetched by embuild into `./.embuild` (4.3 GB) with its own gcc `esp-14.2.0_20260121`, cmake 3.30.2, ninja 1.12.1 |
| Python for the IDF tooling | Homebrew 3.14 worked as is (`idf5.5_py3.14_env`); no uv-provided interpreter was needed |
| esp-idf-svc / esp-idf-hal / esp-idf-sys | 0.54.2 / 0.48.0 / 0.39.0 |
| embedded-svc / embuild | 0.29.0 / 0.33.7 |
| ark-groth16 / ark-bn254 / ark-ec / ark-ff | 0.5.0 each, `default-features = false` |
| num-bigint / serde_json / thiserror / anyhow | 0.4.8 / 1.0.154 / 2.0.21 / 1.0.105 |
| ldproxy | 0.3.5 (`cargo +stable install ldproxy`) |
| espflash | 4.7.0 |

The arkworks crates built for Xtensa unchanged. They are used without the `parallel` (rayon)
and `asm` (x86-64 only) features, which is also how upstream uses `ark-groth16`.

## Build, flash, capture

All commands run from this directory, with `espflash` (4.x) and `ldproxy` on `PATH` and the
`esp` Rust toolchain installed by `espup install --targets esp32`.

```sh
# once per shell: LIBCLANG_PATH + the Xtensa gcc on PATH (written by `espup install`)
. ~/export-esp.sh

# build (the first build clones ESP-IDF v5.5.5 into ./.embuild; 3.5 min here, 40 s afterwards
# whenever sdkconfig.defaults changes, 5 s for Rust-only changes)
cargo build --release

# flash: IDF-built bootloader + partitions.csv + app; NVS and scratch are left alone
tools/flash.sh release
# ... which runs:
#   espflash flash --chip esp32 --port /dev/cu.usbserial-0001 --baud 460800 \
#     --non-interactive --skip-update-check --flash-size 4mb --flash-mode dio --flash-freq 80mhz \
#     --bootloader target/xtensa-esp32-espidf/release/bootloader.bin \
#     --partition-table partitions.csv target/xtensa-esp32-espidf/release/shadenet-esp32
# `cargo run --release` does build + flash in one step (same script as the cargo runner).

# reset the board and capture its output until the DONE marker (about 20 s)
uv run --with pyserial tools/capture.py --port /dev/cu.usbserial-0001 \
    --out release.log --timeout 90

# the same, also driving the console
uv run --with pyserial tools/capture.py --out release.log --timeout 90 \
    --send heap --send-after "CONSOLE ready" --send help --send-after DONE
```

Image size: `espflash flash` prints `App/part. size: 1,047,392/2,621,440 bytes, 39.95%`
(`espflash save-image --chip esp32 <elf> app.bin` gives the same number without a board).

Other profiles: `cargo build --profile release-o3` / `--profile release-crypto3`, then
`tools/flash.sh release-o3`. Opt-levels without a profile of their own were built with
`CARGO_PROFILE_RELEASE_O3_OPT_LEVEL=z cargo build --profile release-o3`.

`capture.py` resets the chip by pulsing EN through RTS, starts the log at the ROM banner and
replaces MAC addresses with `xx:xx:xx:xx:xx:xx`. `espflash monitor --non-interactive` was not
tried.

## Partition table (4 MB)

| Name | Type | Subtype | Offset | Size |
|---|---|---|---|---|
| (bootloader) | | | 0x1000 | |
| (partition table) | | | 0x8000 | 0x1000 |
| `nvs` | data | nvs | 0x9000 | 0x6000 (24 KB) |
| `phy_init` | data | phy | 0xf000 | 0x1000 (4 KB) |
| `factory` | app | factory | 0x10000 | 0x280000 (2560 KB) |
| `scratch` | data | undefined (0x06) | 0x290000 | 0x170000 (1472 KB) |

No OTA. `scratch` is raw NOR flash (no filesystem, no wear levelling), found by name.

Two things differ from what one might expect:

* `scratch` uses the `undefined` data subtype, not a numeric one such as `0x40`. espflash 4.7.0
  panics on a numeric subtype for a `data` partition (`esp-idf-part` only accepts the named
  ones); ESP-IDF's own `gen_esp32part.py` accepts both. `undefined` is ESP-IDF's subtype for
  data in no particular format.
* The table reaches the device through `espflash --partition-table`, not through sdkconfig.
  esp-idf-sys builds ESP-IDF in `target/`, where a relative
  `CONFIG_PARTITION_TABLE_CUSTOM_FILENAME` does not resolve, so sdkconfig keeps the stock
  single-app table. That only affects an unused `partition-table.bin`; the bootloader and the
  application read the table from flash at run time.

## Serial output

UART0, 115200 8N1. ESP-IDF log lines (`I (123) tag: ...`) are interleaved with single-line
`MARKER key=value ...` records:

| Marker | Meaning |
|---|---|
| `BOOT` | firmware name/version, cargo profile, opt-level, whether `bench` is on |
| `CHIP` | model, revision, cores, CPU MHz (reported and measured), flash size |
| `HEAP tag=...` | free heap, largest free block, IDF low-water mark, at a named point |
| `THREAD` | spawn + join of one `std::thread` (stack use, heap not returned) |
| `SCRATCH` | scratch partition self-test timings |
| `BENCH_ROUND` | one verification: time, heap dip |
| `BENCH phase=...` | timings of one benchmark pass (`verify_ms` is the median) |
| `BENCH_MEM phase=...` | heap and stack figures of that pass, in bytes |
| `WIFI state=...` | `started`, `scanned`, `no_credentials`, `connected`, `connect_failed` |
| `SNTP` | whether the clock was set (only after a successful connect) |
| `STACK` | never-used stack bytes of the main task and the two idle tasks |
| `CONSOLE` | console replies |
| `FAIL` / `FATAL` | a step failed / start-up aborted |
| `DONE` | end of the boot sequence |

Console commands (one line each): `wifi <ssid> [password]` stores credentials in NVS namespace
`shadenet` (keys `ssid`, `pass`) and reboots; `wifi-clear`; `set <key> <value>`, `get <key>`
and `unset <key>` for the node settings listed in the project README; `drain on|off`; `heap`;
`reboot`; `help`. The console has its own thread and answers while the main task is busy.

## Results

Final configuration unless stated: `release` profile (`opt-level = "s"`, fat LTO, 1 codegen
unit, `panic = "abort"`), flash at 80 MHz QIO.

### Verifier timing

| Step | Without radio | Wi-Fi started |
|---|---|---|
| Verify one proof (median of 5; min to max) | 862.2 ms (862.2 to 862.2) | 862.4 ms (862.2 to 862.9) |
| Reject a proof with a tampered public input | 803.0 ms | 803.2 ms |
| Parse the proof and public signals (per request) | 96.2 ms | 96.2 ms |
| Parse + prepare the verification key (once) | 797.7 ms | 796.1 ms |
| ... of which JSON parsing | 1.8 ms | 1.8 ms |
| Build one G2 line-coefficient table | 59.9 ms | 59.9 ms |

A request therefore costs about 0.96 s of one core (parse + verify). The reported CPU
frequency is 240 MHz, and counting CPU cycles against the microsecond timer gives 240.0 MHz.

### opt-level trade-off

Same source, same sdkconfig, flash at 80 MHz QIO:

| Build | Verify | Proof parse | Key prepare | Image bytes | Of factory | Log |
|---|---|---|---|---|---|---|
| `release`: `"s"` | **862 ms** | 96 ms | 798 ms | 1,047,392 | 40.0 % | `release.log` |
| `"z"` | 973 ms | 98 ms | 806 ms | 1,006,512 | 38.4 % | `opt-z.log` |
| `release-crypto3`: `"s"`, arkworks crates at 3 | 1475 ms | 273 ms | 1679 ms | 1,225,648 | 46.8 % | `release-crypto3.log` |
| 2 | 2054 ms | 154 ms | 1927 ms | 1,428,976 | 54.5 % | `opt-2.log` |
| `release-o3`: 3 | 4783 ms | 351 ms | 4021 ms | 1,680,112 | 64.1 % | `release-o3.log` |

The same three profiles with the flash at the default 40 MHz DIO:

| Build | Verify | Proof parse | Key prepare | Log |
|---|---|---|---|---|
| `"s"` | 905 ms | 106 ms | 843 ms | `dio40-release.log` |
| `"s"`, arkworks crates at 3 | 3013 ms | 709 ms | 3833 ms | `dio40-release-crypto3.log` |
| 3 | 13854 ms | 946 ms | 11528 ms | `dio40-release-o3.log` |

Higher optimisation levels are slower here, and the slowdown tracks flash read speed:
speeding up flash reads alone makes the `opt-level = 3` build 2.9x faster but the `"s"` build
only 5 % faster. The likely cause (inferred from that, not profiled) is the ESP32's 32 KB
flash cache: all code executes from SPI flash through it, the inlined and unrolled field
arithmetic of the bigger builds no longer fits, and every miss is a flash read. Keep
`opt-level = "s"` for the whole firmware; do not raise it for the crypto crates.

### Heap

The ESP32 heap is several separate regions (here 6 KB, 157 KB, 14 KB and 111 KB), so the
largest possible allocation is far below the free total.

| Point | Free | Largest block |
|---|---|---|
| Boot (before `main` does anything) | 243,904 | 114,688 |
| + system event loop | 238,000 | 110,592 |
| + NVS | 236,072 | 110,592 |
| + console (UART driver, 4 KB thread) | 228,544 | 110,592 |
| + Wi-Fi driver initialised and started, STA, not connected (costs 32,752) | 195,580 | 110,592 |
| ... after one scan (26 to 36 access points seen across runs) | 195,556 | 110,592 |
| ... holding the prepared verification key | 161,728 | 110,592 |
| ... lowest during a verification (worst seen) | 85,256 | |

The 32 KB main-task stack is already taken out of the boot figure.

| Verifier memory | Bytes |
|---|---|
| Prepared key as arkworks builds it | 49,584 |
| Prepared key after `shrink_to_fit` on its vectors | 33,840 |
| `serde_json::Value` of the key file (dropped right after parsing) | 6,294 |
| Peak Rust heap while building the key (JSON tree still alive) | 56,454 |
| Extra Rust heap during one verification | 58,336 |
| Free-heap dip during one verification, whole system, no radio | 58,352 |
| Free-heap dip during one verification, Wi-Fi started (typical; worst) | 59,728; 76,436 |
| Main-task stack used (key preparation + verification) | 21,716 of 32,768 |

What helps steady-state RAM:

* `shrink_to_fit` returns 15.7 KB. The two G2 line-coefficient tables hold 87 entries of
  192 bytes each, but arkworks grows them by pushing, which leaves a capacity of 128.
* Dropping the JSON `Value` before the pairing work lowers the start-up peak by 6.3 KB; it
  does not change the steady state.
* The 58 KB needed per verification is two clones of those tables (arkworks' Miller loop takes
  them by value) plus the table for the proof's own G2 point. Avoiding it means not using
  `Groth16::verify_proof`. Not done.
* Not measured, only derived: a node could keep just the 1 KB unprepared key and rebuild both
  tables per verification. That would free 33 KB of steady-state heap for about 120 ms more
  per verification (2 x 59.9 ms).

Two caveats on the numbers. `esp_get_minimum_free_heap_size()` (the `min_free` fields) is the
sum of each region's own low-water mark; the regions need not bottom out at the same moment,
so it overstates peak use. The `heap_dip` fields use ESP-IDF's resettable low-water marks
around one operation and are tighter, but still an upper bound for the same reason. The
"Rust heap" rows come from a counting `#[global_allocator]` and are exact for Rust
allocations.

### sdkconfig choices that were measured

| Change | Effect | Log |
|---|---|---|
| Flash 40 MHz DIO to 80 MHz QIO | verify 905 to 862 ms; 64 KB scratch read 19.0 to 13.5 ms | `dio40-release.log` |
| Wi-Fi static RX buffers 10 to 4 (with the dynamic limits and BA window) | 10.1 KB more free heap with the driver started (cost 42,836 to 32,752) | `exp-wifi-buffers-idf-default.log` |
| No soft-AP, no WPA-Enterprise | 53.3 KB less flash, 0.8 KB more heap | `exp-softap-enterprise-on.log` |
| Idle task stacks 4096 (template value) to 2048 | 4 KB more heap; 0.6 KB of each is used | `initial-config.log` |

The two `exp-*` control builds were made by appending a file with the overriding lines:
`ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;/abs/path/overrides" cargo build ...`.

The dynamic RX/TX buffer limits (32 to 16) and the block-ack window (6 to 4) only matter
under traffic and could not be measured without a connection. `initial-config.log` is the very
first working configuration (flash at 40 MHz DIO, soft-AP compiled in, 4 KB idle stacks):
boot heap 239,648, Wi-Fi started 190,924, verify 915 ms, image 1,100,032 bytes.

### Scratch partition

64 KB at offset 0: erase 100.2 ms, write 143.1 ms, read back 13.5 ms, contents verified.

## What had to change along the way

Nothing crashed: no panic, stack overflow, out-of-memory or watchdog reset in any run, and the
initial 32 KB main stack was enough. The adjustments were about tooling and measurement:

1. `partitions.csv`: `data, 0x40` to `data, undefined` (espflash panic, see above).
2. `esp_chip_info()` and `esp_clk_cpu_freq()` are not in the esp-idf-sys bindings; `platform.rs`
   declares them itself.
3. Blocking line input on stdin needs the UART driver (`uart_driver_install` +
   `uart_vfs_dev_use_driver`); without it reads return immediately.
4. espflash rewrites the image header's flash frequency to 40 MHz unless `--flash-freq 80mhz`
   is passed, whatever sdkconfig says. Check the boot log for `SPI Speed : 80MHz`.
5. The task watchdog stays at its 5 s default. The slow opt-level 2 and 3 variants (up to 14 s
   per verification, about 26 s without yielding) were run with
   `CONFIG_ESP_TASK_WDT_TIMEOUT_S=30`.
6. Serial capture on macOS with the CP210x driver: `tcflush` made later reads repeat the last
   received chunk, so the script drains by reading. The first capture right after flashing can
   still show a garbled line in the ROM banner; the firmware's own lines were never affected.

## Not verified

* A successful Wi-Fi connection, DHCP and SNTP: no credentials were available. That code is
  compiled and the connect path ran up to a timeout against a non-existent SSID.
* Heap with an associated station and traffic. All "Wi-Fi" figures are for a started,
  unassociated driver.
* The cache explanation for the opt-level results is an inference from the flash-speed
  comparison.

## The node

`src/main.rs` brings up the platform, joins Wi-Fi (retrying until it succeeds), starts SNTP
and calls `node::run`, which does not return. `src/node.rs` builds the portable node with the
device's limits, with keys and settings from NVS and the `scratch` partition as the Tor
directory's working storage, then runs the event loop and prints a `STATUS` line every 30 s.
The benchmarks, the vendored arkworks verifier and the counting allocator are only compiled
with `--features bench`.

## Fixtures

* `fixtures/verification_key.json`: copy of upstream `circuits/rln/verification_key.json`
  (sha256 `ae43614cd02ebe95...`, artifact id `rln-ae43614cd02ebe95`).
* `fixtures/proof.json`: `{proof, publicSignals}` in snarkjs form plus `publicInputsOrder`
  (`y, root, nullifier, x, externalNullifier`), for identity secret 111, message limit 8, a
  depth-20 tree with one member, target `example.com:443`, epoch 7, RLN identifier 1.
* `fixtures/envelope.json`: the same proof framed as a v4 wire envelope, one line, as the
  upstream client sends it.

`fixtures/gen` builds the proof with the `shadenet-rln` prover and checks it with the
`shadenet-rln` verifier (valid proof accepted, tampered `x` rejected) before writing. It is a
host tool (stable Rust 1.98, compiles wasmer, about 3 minutes and 1.3 GB of build output):

```sh
cd fixtures/gen && CARGO_TARGET_DIR=/some/scratch/dir cargo run -- ..
```

Groth16 proofs are randomised, so a regenerated `proof.json` differs from the committed one.

## Licence

MIT. `src/rln_verify.rs` is vendored from ShadeNet's `crates/shadenet-rln/src/verify.rs`
(MIT, copyright 2026 dmarzzz); the header of that file lists the changes.
