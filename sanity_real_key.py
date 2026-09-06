"""
sanity_real_key.py - control check: NORMAL public-key auth must succeed
against the lab CHR before running the PoC. If this fails, the authorized
key is not installed correctly and a PoC failure is meaningless.

Usage: python3 sanity_real_key.py <host> <port> [keyfile] [username]
"""

import sys

import paramiko


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.119"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2222
    keyfile = sys.argv[3] if len(sys.argv) > 3 else "victim_rsa"
    username = sys.argv[4] if len(sys.argv) > 4 else "admin"

    key = paramiko.RSAKey.from_private_key_file(keyfile)
    t = paramiko.Transport((host, port))
    t.start_client(timeout=20)
    print("[*] hostkey:", t.get_remote_server_key().get_name())
    t._preferred_pubkeys = ["rsa-sha2-256"]  # paramiko 5 dropped ssh-rsa signing
    t.auth_publickey(username, key)
    ok = t.is_authenticated()
    t.close()
    print(f"[{'+' if ok else '-'}] real-key auth as {username!r}: "
          f"{'SUCCEEDED (lab baseline OK)' if ok else 'FAILED - fix key import first'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
