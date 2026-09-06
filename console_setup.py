"""
console_setup.py - drive the CHR serial console (qemu telnet) to prepare the lab.

Usage: python3 console_setup.py <host> <port> [keyfile]

Assumes fresh CHR boot: admin / blank password. Fetches the victim public key
from the QEMU user-net gateway (10.0.2.2 = host) where a plain HTTP server
must already serve the keyfile, imports it for admin, enables SSH.
"""

import socket
import sys
import time


def main() -> int:
    host, port = sys.argv[1], int(sys.argv[2])
    keyfile = sys.argv[3] if len(sys.argv) > 3 else "victim.pub"

    s = socket.create_connection((host, port), timeout=10)
    s.settimeout(2)
    buf = b""

    def read_until(patterns, timeout):
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            try:
                chunk = s.recv(4096)
                if chunk:
                    buf += bytes(b for b in chunk if b < 0xF0)  # strip telnet IAC
            except socket.timeout:
                pass
            for pat in patterns:
                if pat in buf:
                    out, buf = buf, b""
                    return pat, out
        raise TimeoutError(f"none of {patterns} within {timeout}s; tail={buf[-200:]!r}")

    def cmd(c, timeout=30):
        s.sendall(c.encode() + b"\n")
        _, out = read_until([b"> "], timeout)
        return out.decode(errors="replace")

    print("[*] waiting for RouterOS login prompt ...")
    read_until([b"Login:"], 240)
    s.sendall(b"admin\n")
    read_until([b"Password:"], 20)
    s.sendall(b"\n")
    pat, out = read_until([b"> ", b"icense"], 30)
    if pat == b"icense":
        s.sendall(b"n\n")
        read_until([b"> "], 30)

    print("[*] fetching victim key into CHR ...")
    print(
        cmd(f'/tool fetch url="http://10.0.2.2:8069/{keyfile}" dst-path={keyfile}')
        .strip()[-120:]
    )
    print("[*] importing key for admin ...")
    print(cmd(f"/user ssh-keys import public-key-file={keyfile} user=admin").strip()[-200:])
    print("[*] ensuring ssh service enabled ...")
    print(cmd("/ip service enable ssh").strip()[-80:])
    print("[*] key table:")
    print(cmd("/user ssh-keys print").strip()[-300:])
    print("[*] version:")
    ver = cmd("/system resource print").strip()
    print(ver[: ver.find("uptime") if "uptime" in ver else 200])
    s.close()
    print("[+] console setup done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
