"""
mon_type.py - type text into a QEMU HMP console via sendkey and screendump.

Usage: python3 mon_type.py <monitor.sock> <literal1> <literal2> ... -- <dumpname>
Each literal is typed followed by Enter; after the last one a screendump
<dumpname>.ppm is written next to the socket. Pure stdlib.
"""

import socket
import sys
import time

KEYMAP = {
    " ": "spc", "/": "slash", "-": "minus", ".": "dot", "=": "equal",
    ",": "comma", "'": "apostrophe", ";": "semi",
}


def send_literal(s, text, delay=0.06):
    for ch in text:
        if ch == "\n":
            key = "ret"
        elif ch.isdigit() or ch.isalpha():
            key = ch.lower()
        elif ch in KEYMAP:
            key = KEYMAP[ch]
        else:
            raise ValueError(f"unmapped char {ch!r}")
        s.sendall(f"sendkey {key}\n".encode())
        time.sleep(delay)
    if not text.endswith("\n"):
        s.sendall(b"sendkey ret\n")
        time.sleep(delay)


def main() -> int:
    sock_path = sys.argv[1]
    literals = sys.argv[2:]
    dump = "screen"
    if literals and literals[-1].startswith("--dump="):
        dump = literals[-1].split("=", 1)[1]
        literals = literals[:-1]

    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    time.sleep(0.5)
    try:
        s.setblocking(False)
        s.recv(65536)
    except BlockingIOError:
        pass
    s.setblocking(True)

    for lit in literals:
        send_literal(s, lit)
        time.sleep(1.2)

    out_path = sock_path.rsplit("/", 1)[0] + f"/{dump}.ppm"
    s.sendall(f"screendump {out_path}\n".encode())
    time.sleep(2.5)
    s.close()
    print(f"[*] dumped {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
