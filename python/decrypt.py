#!/usr/bin/env python3
"""
decrypt.py — M-of-N threshold file decryption

Usage:
    python3 decrypt.py -k key1.pem key3.pem key5.pem -i encrypted.bin -o plaintext

Provide any M (or more) of the original N key files used during encryption.
The script figures out which slots each key maps to automatically.
"""

import argparse
import os
import sys

# Reuse bundle reader and crypto from encrypt.py
sys.path.insert(0, os.path.dirname(__file__))
from encrypt import (
    read_bundle,
    derive_key_from_pem,
    aes_gcm_decrypt,
    _require_cryptography,
)
from shamir import recover_secret

try:
    from cryptography.exceptions import InvalidTag
except ImportError:
    InvalidTag = Exception  # fallback; will still raise on bad decrypt


def cmd_decrypt(args) -> None:
    _require_cryptography()

    bundle = read_bundle(args.input)
    header = bundle["header"]
    raw_shares = bundle["raw_shares"]

    m = header["m"]
    n = header["n"]
    salt = bytes.fromhex(header["salt_hex"])
    share_nonces = [bytes.fromhex(h) for h in header["share_nonces_hex"]]
    key_names = header["keys"]

    print(f"[*] Bundle: {m}-of-{n} threshold")
    print(f"    Original key slots: {', '.join(key_names)}")
    print(f"[*] Trying {len(args.keys)} provided key file(s)...")

    info_prefix = b"shamir-threshold-share-v1:"

    # Try each provided key file against every slot, collect successful shares
    recovered_shares = []
    used_slots = set()

    for key_file in args.keys:
        basename = os.path.basename(key_file)
        matched = False
        for slot_idx in range(n):
            if slot_idx in used_slots:
                continue
            info = info_prefix + str(slot_idx).encode()
            try:
                enc_key = derive_key_from_pem(key_file, salt, info)
                share_blob = aes_gcm_decrypt(
                    enc_key, share_nonces[slot_idx], raw_shares[slot_idx]
                )
                # Decryption succeeded — this key matches this slot
                recovered_shares.append(share_blob)
                used_slots.add(slot_idx)
                slot_name = key_names[slot_idx] if slot_idx < len(key_names) else f"slot {slot_idx}"
                print(f"    [+] '{basename}' → slot {slot_idx} ({slot_name}) ✓")
                matched = True
                break
            except (InvalidTag, Exception):
                continue
        if not matched:
            print(f"    [-] '{basename}' did not match any remaining slot")

    print(f"\n[*] Successfully unlocked {len(recovered_shares)} of {m} required shares")

    if len(recovered_shares) < m:
        sys.exit(
            f"ERROR: Need {m} shares to decrypt, only recovered {len(recovered_shares)}.\n"
            f"       Provide at least {m - len(recovered_shares)} more key file(s)."
        )

    # Use exactly m shares (Shamir is defined for m, more is fine but we pass m)
    shares_to_use = recovered_shares[:m]

    # Recover the AES key
    try:
        aes_key = recover_secret(shares_to_use)
    except Exception as e:
        sys.exit(f"ERROR: Failed to recover AES key from shares: {e}")

    if len(aes_key) != 32:
        sys.exit(f"ERROR: Recovered key has wrong length {len(aes_key)}, expected 32")

    # Decrypt the file
    try:
        plaintext = aes_gcm_decrypt(aes_key, bundle["file_nonce"], bundle["file_ciphertext"])
    except (InvalidTag, Exception) as e:
        sys.exit(
            "ERROR: File decryption failed — the recovered key is wrong.\n"
            "       This usually means one or more key files are corrupted or incorrect.\n"
            f"       Details: {e}"
        )

    with open(args.output, "wb") as f:
        f.write(plaintext)

    print(f"[+] Decrypted {len(plaintext)} bytes → '{args.output}'")


def parse_args():
    p = argparse.ArgumentParser(
        description="M-of-N threshold file decryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt using 3 of the original 5 keys (any 3 work)
  python3 decrypt.py -k alice.pem carol.pem eve.pem \\
      -i secret.txt.enc -o secret.txt

  # You can provide more than M keys — extras are ignored
  python3 decrypt.py -k node1.key node2.key node3.key \\
      -i archive.tar.gz.enc -o archive.tar.gz
""",
    )
    p.add_argument("-k", "--keys", nargs="+", required=True,
                   metavar="KEY_FILE",
                   help="PEM key files to attempt (need at least M matching ones)")
    p.add_argument("-i", "--input", required=True, help="Encrypted bundle to decrypt")
    p.add_argument("-o", "--output", required=True, help="Output file")
    return p.parse_args()


if __name__ == "__main__":
    cmd_decrypt(parse_args())
