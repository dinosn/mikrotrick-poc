"""
import_key.py - stage the victim authorized key onto a lab CHR over SSH.

Uses password auth (admin / labpass123) to SFTP-upload victim.pub and import
it as an authorized key for the target user. Stock CHR first boot forces a
password change on console; set it to labpass123 first (see README).

Usage: python3 import_key.py <host> <user> <password> <pubkey-file>
"""

import sys

import paramiko


def main() -> int:
    host, user, password, pubkey = (
        sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    )
    port = int(sys.argv[5]) if len(sys.argv) > 5 else 22
    t = paramiko.Transport((host, port))
    t.start_client(timeout=20)
    t.auth_password(user, password)
    assert t.is_authenticated(), "password auth failed"
    sftp = paramiko.SFTPClient.from_transport(t)
    sftp.put(pubkey, "victim.pub")
    sftp.close()
    for cmd in (
        "/user ssh-keys import public-key-file=victim.pub user=" + user,
        "/user ssh-keys print",
    ):
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
        print(f"$ {cmd}\n{out.decode(errors='replace')}")
    t.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
