#!/usr/bin/env python3
"""
encrypt.py — M-of-N threshold file encryption

Usage:
    python3 encrypt.py -m M -k key1.pem key2.pem ... keyN.pem -i plaintext -o encrypted.bin

What it does:
  1. Generates a random 256-bit AES key.
  2. Encrypts the input file with AES-256-GCM (authenticated encryption).
  3. Splits the AES key into N Shamir shares with threshold M.
  4. Encrypts each share symmetrically using a key derived from the
     corresponding TLS key file (HKDF-SHA256).
  5. Writes a self-contained bundle: header JSON + encrypted shares + ciphertext.

The TLS key files never leave the machine — only the HKDF-derived share
encryption keys are used, and they are not stored anywhere.
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys

from shamir import split_secret

# --------------------------------------------------------------------------- #
# AES-256-GCM (pure stdlib via hazmat-lite wrapper)
# We use the 'cryptography' library which is already in your Alpine rootfs
# via the cryptsetup/gnupg dependency chain. Fall back instructions below.
# --------------------------------------------------------------------------- #

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False


def _require_cryptography() -> None:
    if not _HAVE_CRYPTOGRAPHY:
        sys.exit(
            "ERROR: 'cryptography' package not found.\n"
            "Install with: pip install cryptography --break-system-packages\n"
            "Or on Alpine:  apk add py3-cryptography"
        )


# --------------------------------------------------------------------------- #
# Key derivation from a TLS PEM key file
# --------------------------------------------------------------------------- #

def derive_key_from_pem(pem_path: str, salt: bytes, info: bytes) -> bytes:
    """
    Derive a 32-byte encryption key from the raw bytes of a PEM file.
    Uses HKDF-SHA256 so that the derived key is domain-separated by `info`.
    The PEM file is the IKM (input key material); it is never stored or sent.
    """
    with open(pem_path, "rb") as f:
        ikm = f.read()

    if _HAVE_CRYPTOGRAPHY:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(ikm)
    else:
        # Fallback: manual HKDF (RFC 5869) using hmac+sha256
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        t = b""
        okm = b""
        for i in range(1, 3):   # ceil(32/32) = 1 iteration needed; 2 for safety
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        return okm[:32]


# --------------------------------------------------------------------------- #
# AES-256-GCM helpers
# --------------------------------------------------------------------------- #

def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple:
    """Returns (nonce, ciphertext_with_tag)."""
    _require_cryptography()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    _require_cryptography()
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# --------------------------------------------------------------------------- #
# Bundle format
# --------------------------------------------------------------------------- #
#
# File layout (all lengths are 4-byte little-endian uint32):
#
#   MAGIC (8 bytes)          b"SSMENC01"
#   header_len (4 bytes)     length of JSON header in bytes
#   JSON header              UTF-8 encoded JSON (see below)
#   share_len (4 bytes)      length of each encrypted share blob (all equal)
#   share_blob * N           encrypted share blobs, one per key file
#   ct_len (4 bytes)         length of encrypted file ciphertext
#   nonce (12 bytes)         AES-GCM nonce for file ciphertext
#   ciphertext               AES-GCM ciphertext + tag (plaintext + 16 bytes)
#
# JSON header fields:
#   m         - threshold
#   n         - total shares
#   keys      - list of key file basenames (for UX only, not security)
#   salt_hex  - hex-encoded 32-byte HKDF salt (same for all shares)
#   share_nonces_hex - list of 12-byte hex nonces, one per share
#
MAGIC = b"SSMENC01"


def write_bundle(
    out_path: str,
    m: int,
    n: int,
    key_basenames: list,
    salt: bytes,
    encrypted_shares: list,   # list of (nonce, ciphertext) tuples
    file_nonce: bytes,
    file_ciphertext: bytes,
) -> None:
    header = {
        "m": m,
        "n": n,
        "keys": key_basenames,
        "salt_hex": salt.hex(),
        "share_nonces_hex": [nonce.hex() for nonce, _ in encrypted_shares],
    }
    header_bytes = json.dumps(header).encode()

    # All encrypted shares must be the same length (they are, since the AES key
    # is fixed-length and AESGCM adds a 16-byte tag)
    share_blobs = [ct for _, ct in encrypted_shares]
    share_len = len(share_blobs[0])
    for sb in share_blobs:
        if len(sb) != share_len:
            raise RuntimeError("Share blobs differ in length — bug in encrypt path")

    ct_len = len(file_ciphertext)

    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<I", len(header_bytes)))
        f.write(header_bytes)
        f.write(struct.pack("<I", share_len))
        for blob in share_blobs:
            f.write(blob)
        f.write(struct.pack("<I", ct_len))
        f.write(file_nonce)
        f.write(file_ciphertext)


def read_bundle(in_path: str) -> dict:
    with open(in_path, "rb") as f:
        magic = f.read(8)
        if magic != MAGIC:
            raise ValueError("Not a valid encrypted bundle (bad magic bytes)")

        (header_len,) = struct.unpack("<I", f.read(4))
        header = json.loads(f.read(header_len))

        (share_len,) = struct.unpack("<I", f.read(4))
        raw_shares = [f.read(share_len) for _ in range(header["n"])]

        (ct_len,) = struct.unpack("<I", f.read(4))
        file_nonce = f.read(12)
        file_ciphertext = f.read(ct_len)

    return {
        "header": header,
        "raw_shares": raw_shares,
        "file_nonce": file_nonce,
        "file_ciphertext": file_ciphertext,
    }


# --------------------------------------------------------------------------- #
# Main: encrypt
# --------------------------------------------------------------------------- #

def cmd_encrypt(args) -> None:
    _require_cryptography()

    key_files = args.keys
    n = len(key_files)
    m = args.m

    if not (1 <= m <= n):
        sys.exit(f"ERROR: threshold M={m} must satisfy 1 <= M <= N={n}")
    if n > 255:
        sys.exit("ERROR: maximum 255 key files supported")

    # Read plaintext
    with open(args.input, "rb") as f:
        plaintext = f.read()

    print(f"[*] Encrypting '{args.input}' with {m}-of-{n} threshold")

    # 1. Generate random AES key
    aes_key = os.urandom(32)

    # 2. Encrypt the file
    file_nonce, file_ciphertext = aes_gcm_encrypt(aes_key, plaintext)
    print(f"[+] File encrypted ({len(plaintext)} bytes → {len(file_ciphertext)} bytes)")

    # 3. Split the AES key into N Shamir shares
    shares = split_secret(aes_key, n, m)
    print(f"[+] AES key split into {n} shares (threshold {m})")

    # 4. Derive per-key encryption keys and encrypt each share
    salt = os.urandom(32)
    info_prefix = b"shamir-threshold-share-v1:"
    encrypted_shares = []

    for i, (key_file, share) in enumerate(zip(key_files, shares)):
        info = info_prefix + str(i).encode()
        enc_key = derive_key_from_pem(key_file, salt, info)
        nonce, ct = aes_gcm_encrypt(enc_key, share)
        encrypted_shares.append((nonce, ct))
        basename = os.path.basename(key_file)
        print(f"    Share {i+1}/{n} → encrypted with key derived from '{basename}'")

    # 5. Write bundle
    key_basenames = [os.path.basename(k) for k in key_files]
    write_bundle(
        args.output, m, n, key_basenames, salt, encrypted_shares,
        file_nonce, file_ciphertext,
    )
    print(f"[+] Bundle written to '{args.output}'")
    print(f"\nTo decrypt, provide any {m} of these {n} key files:")
    for i, k in enumerate(key_files):
        print(f"    [{i}] {os.path.basename(k)}")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def parse_args():
    p = argparse.ArgumentParser(
        description="M-of-N threshold file encryption using Shamir's Secret Sharing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt with 3-of-5 threshold
  python3 encrypt.py -m 3 -k alice.pem bob.pem carol.pem dave.pem eve.pem \\
      -i secret.txt -o secret.txt.enc

  # Encrypt with 2-of-3 threshold
  python3 encrypt.py -m 2 -k node1.key node2.key node3.key \\
      -i archive.tar.gz -o archive.tar.gz.enc
""",
    )
    p.add_argument("-m", type=int, required=True,
                   help="Minimum shares required to decrypt (threshold)")
    p.add_argument("-k", "--keys", nargs="+", required=True,
                   metavar="KEY_FILE",
                   help="PEM key files, one per share holder")
    p.add_argument("-i", "--input", required=True, help="Input file to encrypt")
    p.add_argument("-o", "--output", required=True, help="Output encrypted bundle")
    return p.parse_args()


if __name__ == "__main__":
    cmd_encrypt(parse_args())
