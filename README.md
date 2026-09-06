# MikroTrick lab PoC — CVE-2026-67276 (RouterOS SSH public-key auth bypass)

**Lab use only.** Run exclusively against RouterOS instances you own.
Attacking devices you do not own is a crime (CFAA, Polish art. 267, equivalents).

## Background

CERT PL (2026-09-05) disclosed six RouterOS vulnerabilities, actively exploited
in the wild as the chain **"MikroTrick"** (unauthenticated full device takeover
when SSH is internet-reachable). Fixed by MikroTik on **2026-09-03** in
7.25beta3 / 7.24.2 / 7.23.4 / 6.49.21.

| CVE | Type | Core defect |
|---|---|---|
| **2026-67276** | CWE-347 (this PoC) | SSH userauth key match checks (key type, modulus) but **omits the exponent**; signature verify uses the **client-supplied** key ⇒ e=1 forgery |
| 2026-86060 | CWE-88 | Argument injection via username starting with a prohibited character (`-2` seen in attack logs) ⇒ policy-mask change ⇒ privilege escalation |
| 2026-67279 | CWE-841 | SSH enters connection protocol after client-requested rekey without completed userauth ⇒ unauthenticated exec in file namespace |
| 2026-67277 | CWE-306 | bandwidth-test pre-auth state + uninit buffer disclosure + size-underflow ⇒ kernel memory leak / restart |
| 2026-67278 | CWE-347 | X.509 accepts malformed RSA/PKCS#1v1.5 signatures; e=3 trust anchor ⇒ trusted intermediate forgery |
| 2026-67281 | CWE-824 | WebFig `/jsproxy` stale uninitialized principal pointer + path escape ⇒ root file read |

Vulnerable ranges (all six): `[7.24, 7.24.2)`, `[7.0.0, 7.23.4)`, `[6.0.0, 6.49.21)`.

## CVE-2026-67276 mechanism

1. RouterOS matches the presented SSH public-key blob against the user's
   authorized key by **(key type, modulus)** — the exponent is not compared.
2. Signature verification uses the **client-supplied** key, i.e. the exponent
   from the attacker's blob.
3. Presenting `{ssh-rsa, e=1, n=victim}` makes `sig^1 mod n == sig`, so the
   valid "signature" is simply `EMSA-PKCS1-v1_5(hash, authdata)` — computable
   by anyone who knows the victim's public modulus. No private key needed.
4. Result: an SSH command channel **as the target user**.

Preconditions (the disclosure's own minimum): target username + that user's
authorized RSA public modulus.

## Minimum information needed to reproduce

1. **Target**: any RouterOS in the vulnerable ranges, SSH reachable (lab: CHR
   image in QEMU with KVM; real hardware equivalent).
2. **Username** of an account with an authorized RSA key.
3. **The RSA modulus `n`** of that authorized key (from a leaked/captured
   `.pub`, provisioning records, or `--modulus-hex`). This is the only
   secret-adjacent input; the private key is never needed.
4. **Disclosure-confirmed server behavior** (the defect itself, from CERT PL):
   match = (type, n), verify exponent = client-supplied.
5. **A client that can present an arbitrary key blob and arbitrary signature
   bytes** (paramiko + `ForgeKey` hook — stock OpenSSH cannot).
6. Signature algorithm the server accepts (`ssh-rsa` on 6.x, `rsa-sha2-256`
   also on 7.x).

## Files

- `forge_67276.py` — primitive: OpenSSH pubkey parsing, RFC 8017 EMSA encoder,
  forged blob/signature builders, reference RFC 8017 verifier.
- `selftest.py` — local proof, no router: encoder byte-identical to OpenSSL
  (via real-signature inversion), forged sig verifies at e=1 and NOT at 65537,
  full RFC 4252 §7 wire-shape sim. All 15 checks PASS.
- `poc_67276.py` — paramiko client performing the bypass (per-connection
  algorithm pinning; `--lab-i-own-this-target` required).
- `console_setup.py` — one-time CHR prep over qemu serial telnet
  (fetch victim key via 10.0.2.2, import for admin, enable ssh).
- `sanity_real_key.py` — control: normal pubkey auth must succeed first.
- `victim_rsa` / `victim.pub` — generated throwaway 2048-bit "victim" keypair;
  deliberately excluded from Git.

## Local setup

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
ssh-keygen -q -t rsa -b 2048 -N '' -C victim-key -f victim_rsa
```

## Lab (provisioned on root@192.168.1.119)

- Kali x86_64, QEMU 11.0.1 + KVM, `/root/mikrotrick-lab/`, host bridge `br0`
  (192.168.100.1/24) with taps tap0-tap3; dnsmasq on br0 with per-MAC leases.

| VM | Image | Guest IP | MAC | Mac-side tunnel |
|---|---|---|---|---|
| chr-6.49.20 | vulnerable 6.x | 192.168.100.11 | 52:54:00:aa:00:11 | 127.0.0.1:2222 |
| chr-6.49.21 | patched 6.x | 192.168.100.12 | 52:54:00:aa:00:12 | 127.0.0.1:2223 |
| chr-7.23.3 | vulnerable 7.x | 192.168.100.13 | 52:54:00:aa:00:13 | 127.0.0.1:2224 |
| chr-7.23.4 | patched 7.x | 192.168.100.14 | 52:54:00:aa:00:14 | 127.0.0.1:2225 |

- Intended guest state: e1000 NIC, static guest IP, admin password
  `labpass123`, and victim key imported for admin. First-login forced password
  changes were driven over SSH (`bootstrap_password.py` reads the dialog) or
  QEMU monitor `sendkey` (`mon_type.py`) — CHR's serial console is dead by
  default; the VGA console is only readable via monitor `screendump`.
- Tunnel from the Mac:
  `ssh -N -L 2222:192.168.100.11:22 -L 2223:192.168.100.12:22 -L 2224:192.168.100.13:22 -L 2225:192.168.100.14:22 root@192.168.1.119`

Re-run (example, VM3):

```bash
qemu-system-x86_64 -enable-kvm -m 512 -smp 2 -name chr-7.23.3 \
  -drive file=/root/mikrotrick-lab/chr-7.23.3.img,format=raw,if=virtio \
  -netdev tap,id=n2,ifname=tap2,script=no,downscript=no \
  -device e1000,netdev=n2,mac=52:54:00:aa:00:13 \
  -display none -monitor unix:/root/mikrotrick-lab/mon3.sock,server,nowait &
```

```bash
./.venv/bin/python import_key.py 127.0.0.1 admin labpass123 victim.pub 2224
./.venv/bin/python sanity_real_key.py 127.0.0.1 2224 victim_rsa admin   # baseline
./.venv/bin/python poc_67276.py --host 127.0.0.1 --port 2224 \
    --username admin --pubkey victim.pub --algos rsa-sha2-256,ssh-rsa \
    --exp-enc aligned --exec '/system resource print' --lab-i-own-this-target
```

## Observed results (2026-09-06 independent revalidation)

| Target | real private key (baseline) | forged e=1 key (PoC) |
|---|---|---|
| 7.23.3 | auth OK | **auth OK + `/system resource print` exec — CVE confirmed** |
| 7.23.4 (patched) | auth OK | rejected |
| 6.49.20 | auth OK | rejected (see nuance) |
| 6.49.21 (patched) | **invalid baseline** | **not interpretable; guest accepted SSH `none` auth** |

For the 7.x pair, the real-key baseline succeeds on both builds, SSH `none`
authentication is rejected, a wrong-modulus forgery is rejected by 7.23.3,
and the correct-modulus forgery succeeds only on 7.23.3. This is a valid
vulnerable-versus-patched comparison.

The 6.49.21 guest was not provisioned as documented during the independent
revalidation: `admin` remained expired, `/user ssh-keys print detail` was
empty, and a credential-free SSH `none` request executed commands. Unrelated
real RSA keys and wrong-modulus e=1 keys therefore also appeared to succeed.
Reprovision this guest and verify that `none` and an unrelated key are rejected
before using it as a patched control.

**Version nuance:** on 6.49.20 the server-side match rejects the e=1 blob
(`/log` ssh,debug: `can't find matching key for user: admin`) — the disclosed
exponent-omission was not observable in 6.x's matcher although CERT's blanket
range lists `[6.0.0, 6.49.21)`. Confirmed vulnerable: 7.23.3. Confirmed
patched: 7.23.4. The current 6.49.21 lab state proves neither result. The
in-the-wild MikroTrick activity also targeted 7.x devices.

**Wire-format finding (RFC 8332):** the blob's inner type string stays
`ssh-rsa` even for `rsa-sha2-256/512` signature algorithms; the sig algorithm
goes only in the outer algorithm field. Ignoring this makes the server
disconnect mid-userauth (blob parse error) — observed on both 6.x and 7.x.
The PoC's `ForgeKey` handles this, and `--exp-enc aligned|canonical` toggles
the e=1 mpint width (1 vs 3 bytes). On 7.23.3 BOTH widths authenticate — the
matcher parses the exponent and truly ignores its value. On 6.49.20 NEITHER
authenticates (`can't find matching key`) — see the version nuance above.
Server-side `/system logging add topics=ssh,debug` + `/log print` packet
hexdumps surfaced all of this.

Source image archive SHA-256 values used by this lab:

```text
a954ab0002a83de5e4c02110f560d0bf622e7d21916088aaacda6baaba88cf4a  chr-6.49.20.img.zip
6dcfb8674fa7964bf92ce849fbb0ba8147a5cf3d7a1ba595e24ce3e615569188  chr-6.49.21.img.zip
646764fb0a53e9b5a056cb9cf7420eb1629031096c7268c99fb9216c07f8e98c  chr-7.23.3.img.zip
0d32a8da0950dee71e751281c39063f2bebee4b542291aedecc9dbfbe5d60c9d  chr-7.23.4.img.zip
```

## Defensive notes (CERT PL)

- Patch immediately: 7.25beta3 / 7.24.2 / 7.23.4 / 6.49.21.
- Interim: restrict SSH/WWW/bandwidth-test to trusted management networks;
  avoid RouterOS-initiated SSH/TLS from unpatched devices.
- IOCs: log lines `login failure for user -2 via ssh`,
  `user <name> added by ssh:-2@<ip>`; unknown highly-privileged user `ops`;
  `/system/device-mode/print` "Flagged" marker (indicates compromise, its
  absence proves nothing). Observed attacker IPs: 82.192.72.4, 103.102.31.18.

## Sources

- CERT PL advisory: https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/
- CERT PL CVE page: https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/
- MikroTik bulletin (2026-09-03): https://mikrotik.com/supportsec/september-2026-vulnerability/
- "Flagged" mechanism: https://manual.mikrotik.com/docs/system-information-and-utilities/device-mode#flagged-status
