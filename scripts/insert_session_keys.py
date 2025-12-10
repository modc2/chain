#!/usr/bin/env python3
"""
Insert session keys (Aura and GRANDPA) into a running node by decrypting
previously saved key files and calling author_insertKey over JSON-RPC.

Usage examples:
  # Prompt for password and insert both keys
  ./scripts/insert_session_keys.py \
    --rpc http://127.0.0.1:9933 \
    --aura-file ~/.modnet/keys/20250912-013146-aura-sr25519.json \
    --grandpa-file ~/.modnet/keys/20250912-013146-grandpa-ed25519.json \
    --prompt

  # Non-interactive (password as env or argument)
  ./scripts/insert_session_keys.py \
    --rpc http://127.0.0.1:9933 \
    --aura-file ~/.modnet/keys/aura.json \
    --grandpa-file ~/.modnet/keys/grandpa.json \
    --password 'your-strong-password'

Notes:
- The key files are those produced by key_tools.py key-save/gen/gen-all.
- They contain the mnemonic (secret_phrase) encrypted with scrypt + AES-GCM.
- This script decrypts them and submits author_insertKey calls.
"""
import argparse
import json
import os
import sys
from typing import Optional

import requests

# Import Key model from key_tools in the same directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from key_tools import Key  # type: ignore


def read_key(path: str, password: Optional[str]) -> Key:
    return Key.load(os.path.expanduser(path), password)


def insert_key(rpc_url: str, key_type: str, secret_phrase: str, public_hex: str) -> dict:
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "author_insertKey",
        "params": [key_type, secret_phrase, public_hex],
    }
    resp = requests.post(rpc_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
    resp.raise_for_status()
    return resp.json()


def main():
    p = argparse.ArgumentParser(description="Insert session keys (Aura/GRANDPA) via JSON-RPC")
    p.add_argument("--rpc", default="http://127.0.0.1:9933", help="Node RPC endpoint")
    p.add_argument("--aura-file", required=True, help="Path to encrypted Aura key file (sr25519)")
    p.add_argument("--grandpa-file", required=True, help="Path to encrypted GRANDPA key file (ed25519)")
    p.add_argument("--password", help="Password to decrypt key files (omit to prompt)")
    p.add_argument("--prompt", action="store_true", help="Prompt for password instead of passing via arg")

    args = p.parse_args()
    password = None if args.prompt else args.password

    # Load keys
    aura = read_key(args.aura_file, password)
    grandpa = read_key(args.grandpa_file, password)

    if not aura.secret_phrase or not aura.public_key_hex:
        print("Aura key file is missing secret_phrase or public_key_hex", file=sys.stderr)
        sys.exit(1)
    if not grandpa.secret_phrase or not grandpa.public_key_hex:
        print("Grandpa key file is missing secret_phrase or public_key_hex", file=sys.stderr)
        sys.exit(1)

    # Insert keys
    print(f"Inserting AURA (sr25519) key to {args.rpc}...")
    res_aura = insert_key(args.rpc, "aura", aura.secret_phrase, aura.public_key_hex)
    print("AURA result:", res_aura)

    print(f"Inserting GRANDPA (ed25519) key to {args.rpc}...")
    res_gran = insert_key(args.rpc, "gran", grandpa.secret_phrase, grandpa.public_key_hex)
    print("GRANDPA result:", res_gran)

    print("Done. The node should start authoring immediately if running as a validator.")


if __name__ == "__main__":
    main()
