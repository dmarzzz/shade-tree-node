#!/bin/sh
# Flash the firmware to the board.
#
#   tools/flash.sh [profile | path/to/elf] [extra espflash args...]
#
# With a cargo profile name (default: release) it flashes that profile's build. It is also the
# cargo runner (.cargo/config.toml), in which case cargo passes the ELF path:
#   cargo run --release              # build + flash
#   cargo run --release -- --monitor # build + flash + espflash's serial monitor
#
# Environment: ESPFLASH (default: espflash on PATH), PORT (default: /dev/cu.usbserial-0001),
# BAUD (default: 460800).
#
# The image header says DIO/80 MHz: the ROM loads the bootloader in dual I/O, and the bootloader
# (built with CONFIG_ESPTOOLPY_FLASHMODE_QIO) then switches the flash to quad I/O. Without
# --flash-freq, espflash rewrites the header to its 40 MHz default.
#
# Writes the ESP-IDF bootloader that the build produced (so it matches sdkconfig.defaults),
# our partition table and the application. Nothing else on the flash is touched: NVS and the
# scratch partition keep their contents.
set -eu
cd "$(dirname "$0")/.."
target="${1:-release}"
[ $# -gt 0 ] && shift
if [ -f "$target" ]; then
    elf="$target"
    out="$(dirname "$target")"
else
    out="target/xtensa-esp32-espidf/$target"
    elf="$out/shadenet-esp32"
fi
exec "${ESPFLASH:-espflash}" flash \
    --chip esp32 \
    --port "${PORT:-/dev/cu.usbserial-0001}" \
    --baud "${BAUD:-460800}" \
    --non-interactive \
    --skip-update-check \
    --flash-size 4mb \
    --flash-mode dio \
    --flash-freq 80mhz \
    --bootloader "$out/bootloader.bin" \
    --partition-table partitions.csv \
    "$@" \
    "$elf"
