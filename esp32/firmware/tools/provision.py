#!/usr/bin/env python3
"""Store Wi-Fi credentials (and optionally node settings) on the board over its serial console.

    uv run --with pyserial tools/provision.py                # prompts for network and password
    uv run --with pyserial tools/provision.py --set epoch=120 --set members=<leaf>[,<leaf>]

The password is read without echo and is never printed or logged; the board stores it in its
NVS partition and reboots. Settings given with --set are stored first. The ESP32 radio is
2.4 GHz only.
"""
import argparse
import getpass
import sys
import time

import serial


def send(port, line, wait_for, timeout=8.0):
    port.reset_input_buffer()
    port.write(line.encode() + b"\n")
    port.flush()
    deadline = time.time() + timeout
    seen = b""
    while time.time() < deadline:
        seen += port.read(256)
        for row in seen.split(b"\n"):
            if row.startswith(b"CONSOLE") and (wait_for.encode() in row or b"error" in row):
                return row.decode(errors="replace").strip()
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/cu.usbserial-0001")
    ap.add_argument("--ssid", help="network name (prompted if omitted)")
    ap.add_argument("--password-env", help="read the password from this environment variable")
    ap.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="node setting to store")
    ap.add_argument("--unset", action="append", default=[], metavar="KEY", help="node setting to remove")
    ap.add_argument("--set-file", action="append", default=[], metavar="KEY=PATH",
                    help="node setting whose value is read from a file (for secrets)")
    ap.add_argument("--no-wifi", action="store_true", help="only store settings, then reboot")
    args = ap.parse_args()

    port = serial.Serial()
    port.port = args.port
    port.baudrate = 115200
    port.timeout = 0.2
    port.dtr = False
    port.rts = False
    port.open()

    # Opening the port can reset the board; wait until its console answers.
    deadline = time.time() + 40
    while not send(port, "help", "cmd=help", timeout=3.0):
        if time.time() > deadline:
            print("the board's console did not answer (is the firmware flashed and running?)", file=sys.stderr)
            return 1

    settings = [tuple(item.partition("=")[::2]) for item in args.set]
    for item in args.set_file:
        key, _, path = item.partition("=")
        settings.append((key, open(path).read().strip()))
    for key, value in settings:
        reply = send(port, f"set {key} {value}", "cmd=set")
        print(reply or f"no reply to set {key}")
        if not reply or "error" in reply:
            return 1
    for key in args.unset:
        reply = send(port, f"unset {key}", "cmd=unset")
        print(reply or f"no reply to unset {key}")
        if not reply or "error" in reply:
            return 1

    if args.no_wifi:
        print(send(port, "reboot", "cmd=reboot") or "no reply to reboot")
        return 0

    ssid = args.ssid or input("Wi-Fi network name (2.4 GHz): ").strip()
    if args.password_env:
        import os
        password = os.environ.get(args.password_env, "")
    else:
        password = getpass.getpass("Wi-Fi password (not shown): ")
    if "\t" in ssid or "\t" in password:
        print("tabs are not supported in the name or password", file=sys.stderr)
        return 1
    reply = send(port, f"wifi\t{ssid}\t{password}", "cmd=wifi")
    print(reply or "no reply from the board (is the firmware running?)")
    return 0 if reply and "error" not in reply else 1


if __name__ == "__main__":
    sys.exit(main())
