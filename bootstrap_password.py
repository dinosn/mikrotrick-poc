"""
bootstrap_password.py - complete RouterOS forced password-change over SSH.

For a factory CHR (admin / blank password) the first login forces a
"Change your password" dialog. This drives it over an invoke_shell channel,
READING actual output (no blind typing), and verifies the resulting prompt.

Usage: python3 bootstrap_password.py <host> <port> <new-password>
"""

import sys
import time

import paramiko


def main() -> int:
    host, port, newpw = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    t = paramiko.Transport((host, port))
    t.start_client(timeout=20)
    t.auth_password("admin", "")
    assert t.is_authenticated(), "admin/blank auth rejected"
    chan = t.invoke_shell()
    buf = b""

    def read_until(pats, timeout=30):
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            if chan.recv_ready():
                buf += chan.recv(4096)
                for p in pats:
                    if p in buf:
                        return p
            time.sleep(0.2)
        raise TimeoutError(f"none of {pats}; tail={buf[-300:]!r}")

    pat = read_until([b"new password>", b"] >"], 40)
    if pat == b"new password>":
        chan.sendall(newpw.encode() + b"\n")
        read_until([b"repeat new password>"], 20)
        chan.sendall(newpw.encode() + b"\n")
        pat = read_until([b"] >", b"new password>"], 20)
        if pat == b"new password>":
            print("password dialog did not accept; tail:", buf[-300:])
            return 1
        print("[+] password set via forced-change dialog")
    else:
        print("[*] no forced dialog; already at prompt")

    time.sleep(1)
    buf = b""
    chan.sendall(b"/ip address print\n")
    read_until([b"] >"], 20)
    print(buf.decode(errors="replace")[-400:])
    chan.close()
    t.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
