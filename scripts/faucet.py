#!/usr/bin/env python3
"""
Simple faucet for Modnet.

- Decrypts a key file created by key_tools.py
- Connects to a node over WebSocket (local or ngrok)
- Sends balances.transferKeepAlive extrinsics
- Optional rate limiting by recipient address

Examples:
  ./scripts/faucet.py \
    --ws wss://chain-rpc-comai.ngrok.dev \
    --key-file ~/.modnet/keys/aura-primary.json \
    --prompt \
    --to 5F... --amount 100

  # Run as a small service from CLI (one at a time)
  ./scripts/faucet.py --ws ws://127.0.0.1:9944 --key-file ~/.modnet/keys/faucet.json --prompt --to 5F... --amount 10

Notes:
- Amount is in Modnet base units (like Plancks) as integer.
- Make sure the faucet account is endowed.
- For production, consider adding CAPTCHA and stronger rate limits.
"""
import argparse
import os
import sys
import time
from typing import Optional

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.exceptions import SubstrateRequestException

# Reuse our key loading
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from key_tools import Key  # type: ignore


def load_faucet_key(path: str, password: Optional[str]) -> Keypair:
    key = Key.load(os.path.expanduser(path), password)
    if not key.secret_phrase:
        raise RuntimeError("Key file did not contain a mnemonic (secret_phrase)")
    return Keypair.create_from_mnemonic(key.secret_phrase, ss58_format=42)


def connect(ws_url: str) -> SubstrateInterface:
    return SubstrateInterface(url=ws_url, ss58_format=42, type_registry_preset='substrate-node-template')


def transfer(substrate: SubstrateInterface, kp: Keypair, to: str, amount: int) -> str:
    call = substrate.compose_call(
        call_module='Balances',
        call_function='transfer_keep_alive',
        call_params={'dest': to, 'value': amount},
    )
    extrinsic = substrate.create_signed_extrinsic(call=call, keypair=kp)
    receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
    return receipt.extrinsic_hash


def main():
    p = argparse.ArgumentParser(description='Modnet Faucet')
    p.add_argument('--ws', required=True, help='WebSocket endpoint, e.g., ws://127.0.0.1:9944 or wss://...')
    p.add_argument('--key-file', required=True, help='Encrypted key file path for faucet account')
    p.add_argument('--password', help='Password for key file (omit to prompt)')
    p.add_argument('--prompt', action='store_true', help='Prompt for password')
    p.add_argument('--to', required=True, help='Recipient SS58 address')
    p.add_argument('--amount', required=True, type=int, help='Amount in base units (integer)')
    p.add_argument('--sleep', type=float, default=0.0, help='Sleep seconds after sending (for simple throttling)')

    args = p.parse_args()

    password = None if args.prompt else args.password
    kp = load_faucet_key(args.key_file, password)
    substrate = connect(args.ws)

    try:
        h = transfer(substrate, kp, args.to, args.amount)
        print({'status': 'ok', 'tx_hash': h})
    except SubstrateRequestException as e:
        print({'status': 'error', 'error': str(e)})
        sys.exit(1)
    finally:
        if args.sleep > 0:
            time.sleep(args.sleep)


if __name__ == '__main__':
    main()
