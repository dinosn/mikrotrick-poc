"""
run_cmd.py - run RouterOS commands over SSH with the REAL victim key.

Usage: python3 run_cmd.py <host> <port> <keyfile> <user> <cmd1> [cmd2 ...]
"""

import sys

import paramiko


def main() -> int:
    host, port, keyfile, user = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    key = paramiko.RSAKey.from_private_key_file(keyfile)
    t = paramiko.Transport((host, port))
    t.start_client(timeout=20)
    t._preferred_pubkeys = ["rsa-sha2-256"]
    t.auth_publickey(user, key)
    assert t.is_authenticated(), "real-key auth failed"
    for cmd in sys.argv[5:]:
        chan = t.open_session(timeout=20)
        chan.exec_command(cmd)
        out = b""
        while True:
            while chan.recv_ready():
                out += chan.recv(4096)
            if chan.exit_status_ready() and not chan.recv_ready():
                break
        while chan.recv_ready():
            out += chan.recv(4096)
        print(f"$ {cmd}\n{out.decode(errors='replace')}\n")
        chan.close()
    t.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
