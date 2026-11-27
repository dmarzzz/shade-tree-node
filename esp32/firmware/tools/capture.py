#!/usr/bin/env python3
"""Reset the board and capture its UART0 output to a log file.

Usage (pyserial is pulled in by uv; nothing to install):

    uv run --with pyserial tools/capture.py --port /dev/cu.usbserial-0001 \
        --out bench-logs/run.log --timeout 90

The board is reset by pulsing EN through RTS (DTR stays released so the chip boots the
application, not the ROM serial bootloader). Reading stops at the first line that starts with
the `--until` marker (default `DONE`), or after `--timeout` seconds.

`--send TEXT` writes TEXT + newline to the board; with `--send-after MARKER` it is sent when a
line containing MARKER has been seen (otherwise right after reset). May be given several times;
commands are sent in order, each waiting for its own marker. After the last command the capture
keeps reading for `--linger` seconds.

MAC addresses in the output (the Wi-Fi driver logs the station MAC) are replaced with
xx:xx:xx:xx:xx:xx before anything is written, so logs can be shared; `--keep-mac` disables that.
"""
import argparse
import re
import sys
import time

import serial


MAC = re.compile(rb"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/cu.usbserial-0001")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", required=True, help="log file to write")
    ap.add_argument("--timeout", type=float, default=90.0, help="overall limit in seconds")
    ap.add_argument("--until", default="DONE", help="stop at the first line starting with this")
    ap.add_argument("--no-reset", action="store_true", help="do not pulse EN before reading")
    ap.add_argument("--send", action="append", default=[], help="console line to send")
    ap.add_argument("--send-after", action="append", default=[],
                    help="marker to wait for before the matching --send (same position)")
    ap.add_argument("--keep-mac", action="store_true", help="do not redact MAC addresses")
    ap.add_argument("--linger", type=float, default=3.0,
                    help="seconds to keep reading after the stop marker / last command")
    args = ap.parse_args()

    port = serial.Serial()
    port.port = args.port
    port.baudrate = args.baud
    port.timeout = 0.2
    # Set the control lines before opening so that opening the port does not itself reset the
    # chip into the bootloader (DTR low = GPIO0 low on the usual auto-reset circuit).
    port.dtr = False
    port.rts = False
    port.open()

    if not args.no_reset:
        port.dtr = False
        port.rts = True   # EN low
        # Drain whatever arrived before the reset by reading it. (Do not use
        # reset_input_buffer() here: with the macOS CP210x driver, tcflush made the next reads
        # return the last received chunk over and over.)
        drain_until = time.monotonic() + 0.3
        while time.monotonic() < drain_until:
            port.read(4096)
        port.rts = False  # EN high: boot the app
    sends = list(zip(args.send, args.send_after + [None] * len(args.send)))
    started = time.monotonic()
    stop_at = None
    seen_marker = False
    buf = b""
    # The first bytes read after the reset can be leftovers: stale junk from the USB bridge
    # (right after flashing at a higher baud rate) or the start of a boot that opening the port
    # triggered and our reset then cut short. Hold output back for a moment, then start the log
    # at the last ROM banner seen.
    banner = b"ets "
    settle = 0.6
    pending = b"" if not args.no_reset else None
    with open(args.out, "wb") as log:
        while True:
            now = time.monotonic()
            if now - started > args.timeout:
                print(f"[capture] timeout after {args.timeout:.0f}s", file=sys.stderr)
                break
            if stop_at is not None and now > stop_at:
                break
            chunk = port.read(4096)
            if pending is not None:
                pending += chunk
                if now - started < settle:
                    continue
                at = pending.rfind(banner)
                if at >= 0:
                    chunk, pending = pending[at:], None
                elif now - started > 3.0:
                    chunk, pending = pending, None
                else:
                    continue
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not args.keep_mac:
                    line = MAC.sub(b"xx:xx:xx:xx:xx:xx", line)
                log.write(line + b"\n")
                log.flush()
                sys.stdout.write(line.decode("utf-8", "replace") + "\n")
                sys.stdout.flush()
                text = line.decode("utf-8", "replace").strip()
                if sends and (sends[0][1] is None or sends[0][1] in text):
                    cmd, _ = sends.pop(0)
                    time.sleep(0.2)
                    port.write(cmd.encode() + b"\n")
                    port.flush()
                    if not sends and seen_marker:
                        stop_at = time.monotonic() + args.linger
                if text.startswith(args.until):
                    seen_marker = True
                    if not sends:
                        stop_at = time.monotonic() + args.linger
        if buf:  # an unterminated last line
            log.write(buf if args.keep_mac else MAC.sub(b"xx:xx:xx:xx:xx:xx", buf))
    port.close()
    return 0 if seen_marker else 1


if __name__ == "__main__":
    sys.exit(main())
