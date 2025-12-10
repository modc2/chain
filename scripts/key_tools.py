#!/usr/bin/env python3
"""
Key utilities for Modnet:
- Generate Aura (sr25519) and GRANDPA (ed25519) keys via `subkey`.
- Inspect/convert public keys to SS58 addresses.
- Derive multisig address (2-of-3, or any threshold) using substrate-interface.

Requirements:
- subkey installed and on PATH (from Substrate).
- Python deps (for multisig): see scripts/requirements.txt

Usage examples:
  # Generate fresh Aura and GRANDPA keypairs
  ./scripts/key_tools.py gen-all --network substrate

  # Generate Aura only
  ./scripts/key_tools.py gen --scheme sr25519 --network substrate

  # Generate GRANDPA only
  ./scripts/key_tools.py gen --scheme ed25519 --network substrate

  # Inspect a public key to SS58
  ./scripts/key_tools.py inspect --public 0x<hex> --network substrate --scheme sr25519

  # Compute multisig address (2-of-3)
  ./scripts/key_tools.py multisig --threshold 2 \
    --signer 5F3sa2TJ... --signer 5DAAnrj7... --signer 5H3K8Z... \
    --ss58-prefix 42

  # Derive public SS58 address from secret phrase
  ./scripts/key_tools.py derive --phrase <phrase> --scheme sr25519 --network substrate

  # Save key to file (encrypted). If --out is omitted, saves to ~/.modnet/keys/<timestamp>-<scheme>.json
  ./scripts/key_tools.py key-save --scheme sr25519 --network substrate --phrase <phrase> --prompt
  ./scripts/key_tools.py key-save --scheme sr25519 --network substrate --phrase <phrase> --out /tmp/key.json --password <password>

  # Load key from file (encrypted)
  ./scripts/key_tools.py key-load --file /tmp/key.json --password <password>
"""
import argparse
import json
import shutil
import subprocess
import sys

from rich.console import Console
from rich.json import JSON
from rich_argparse import RichHelpFormatter
from pydantic import BaseModel, Field, field_validator, ConfigDict

console = Console()

# -----------------------------
# Key object + crypto helpers
# -----------------------------
from getpass import getpass
import os
import base64
from typing import Literal
from datetime import datetime, UTC

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_OK = True
except Exception:
    _CRYPTO_OK = False

DEFAULT_KEYS_DIR = os.path.expanduser("~/.modnet/keys")

def ensure_keys_dir() -> None:
    """Create the default keys directory if it doesn't already exist."""
    os.makedirs(DEFAULT_KEYS_DIR, exist_ok=True)


def resolve_key_path(path_or_name: str) -> str:
    """Resolve a key file path.

    If `path_or_name` is an absolute path or contains a path separator, expand and return as-is.
    Otherwise, look for it under DEFAULT_KEYS_DIR, appending .json if needed.
    """
    p = os.path.expanduser(path_or_name)
    if os.path.isabs(p) or os.sep in path_or_name:
        return p
    ensure_keys_dir()
    if not path_or_name.endswith(".json"):
        path_or_name += ".json"
    return os.path.join(DEFAULT_KEYS_DIR, path_or_name)

def _require_crypto():
    """Raise if crypto dependencies are missing."""
    if not _CRYPTO_OK:
        raise RuntimeError("Missing crypto deps. Install with: pip install -r scripts/requirements.txt")

def _kdf_scrypt(password: str, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1, length: int = 32) -> bytes:
    """Derive a symmetric key from `password` and `salt` using scrypt."""
    kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> dict:
    """Encrypt `plaintext` using AES-GCM with the provided key and AAD."""
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, associated_data)
    return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}


def _aesgcm_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, associated_data: bytes = b"") -> bytes:
    """Decrypt AES-GCM `ciphertext_b64` with `key` and return plaintext bytes."""
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, associated_data)


def _json_default(obj):
    """Helper for json.dumps to serialize non-JSON types like datetime."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class Key(BaseModel):
    model_config = ConfigDict(frozen=False)
    scheme: str = Field(description="Key scheme: sr25519 or ed25519")
    network: str = Field(default="substrate", description="Substrate network id for subkey")
    byte_array: bytes | None = Field(default=None, description="Raw key bytes (if available)")
    mnemonic_phrase: str | None = Field(default=None, description="BIP39 mnemonic (alias)")
    secret_phrase: str | None = Field(default=None, description="Secret phrase / mnemonic")
    public_key_hex: str | None = Field(default=None, description="0x-prefixed public key hex")
    private_key_hex: str | None = Field(default=None, description="0x-prefixed private key hex (if available)")
    ss58_address: str | None = Field(default=None, description="Derived SS58 address")
    key_type: Literal["sr25519", "ed25519", "ss58"] | None = None
    is_pair: bool = False
    is_multisig: bool = False
    threshold: int | None = None
    signers: list[str] | None = None
    multisig_address: str | None = None
    created_at: datetime | None = None

    @field_validator("scheme")
    @classmethod
    def _validate_scheme(cls, scheme_value: str) -> str:
        if scheme_value not in {"sr25519", "ed25519"}:
            raise ValueError("scheme must be 'sr25519' or 'ed25519'")
        return scheme_value

    @staticmethod
    def from_secret_phrase(phrase: str, scheme: str, network: str = "substrate") -> "Key":
        """Build a specific Key subclass from a secret phrase via `subkey inspect`."""
        require_subkey()
        # subkey inspect will print public + ss58 for the phrase
        out = run(["subkey", "inspect", "--scheme", scheme, "--network", network, phrase])
        parsed = parse_subkey_generate(out)
        base_kwargs = dict(
            scheme=scheme,
            network=network,
            secret_phrase=phrase,
            public_key_hex=parsed.get("public_key_hex"),
            ss58_address=parsed.get("ss58_address"),
            key_type=scheme,
            is_pair=True,
            created_at=datetime.now(UTC),
        )
        if scheme == "sr25519":
            return AuraSR25519Key(**base_kwargs)
        else:
            return GrandpaED25519Key(**base_kwargs)

    @staticmethod
    def from_public(public_hex: str, scheme: str, network: str = "substrate") -> "Key":
        """Build a ModNetSS58Key from a 0x-prefixed public key hex by deriving SS58 via `subkey`."""
        parsed = subkey_inspect(public_hex, network, scheme)
        return ModNetSS58Key(
            scheme=scheme,
            network=network,
            public_key_hex=public_hex,
            ss58_address=parsed.get("ss58_address"),
            key_type="ss58" if parsed.get("ss58_address") else scheme,
            is_pair=False,
            created_at=datetime.now(UTC),
        )

    def derive_public_ss58(self) -> "Key":
        """Ensure `public_key_hex` and `ss58_address` are set, deriving from phrase if needed."""
        if self.public_key_hex and self.ss58_address:
            return self
        if self.secret_phrase:
            derived = Key.from_secret_phrase(self.secret_phrase, self.scheme, self.network)
            self.public_key_hex = derived.public_key_hex
            self.ss58_address = derived.ss58_address
            return self
        raise ValueError("No data available to derive from; provide secret_phrase or public_key_hex")

    def to_json(self, include_secret: bool = False) -> dict:
        """Return a JSON-serializable dict of this key. Optionally include the secret.

        Uses Pydantic's JSON mode so datetimes are converted to ISO strings.
        """
        data = self.model_dump(mode="json")
        if not include_secret:
            data.pop("secret_phrase", None)
        return data

    # Encryption format: JSON with scrypt params, salt, nonce, ciphertext (base64)
    def encrypt(self, password: str) -> dict:
        """Encrypt this key with the given `password` and return an encrypted JSON blob."""
        _require_crypto()
        payload = json.dumps(self.to_json(include_secret=True), default=_json_default).encode()
        salt = os.urandom(16)
        key = _kdf_scrypt(password, salt)
        enc = _aesgcm_encrypt(key, payload)
        return {
            "version": 1,
            "kdf": "scrypt",
            "salt": base64.b64encode(salt).decode(),
            "params": {"n": 16384, "r": 8, "p": 1},
            **enc,
        }

    @staticmethod
    def decrypt(encrypted_blob: dict, password: str) -> "Key":
        """Decrypt a previously saved key blob using `password` and reconstruct a Key."""
        _require_crypto()
        if encrypted_blob.get("kdf") != "scrypt":
            raise ValueError("Unsupported KDF")
        params = encrypted_blob.get("params") or {}
        n, r, p = params.get("n", 16384), params.get("r", 8), params.get("p", 1)
        salt = base64.b64decode(encrypted_blob["salt"]) if isinstance(encrypted_blob.get("salt"), str) else encrypted_blob.get("salt")
        key = _kdf_scrypt(password, salt, n=n, r=r, p=p)
        plaintext_bytes = _aesgcm_decrypt(key, encrypted_blob["nonce"], encrypted_blob["ciphertext"])  # type: ignore
        decrypted_data = json.loads(plaintext_bytes.decode())
        return Key(
            scheme=decrypted_data["scheme"],
            network=decrypted_data.get("network", "substrate"),
            secret_phrase=decrypted_data.get("secret_phrase"),
            public_key_hex=decrypted_data.get("public_key_hex"),
            ss58_address=decrypted_data.get("ss58_address"),
            key_type=decrypted_data.get("key_type"),
            is_pair=decrypted_data.get("is_pair", False),
            is_multisig=decrypted_data.get("is_multisig", False),
            threshold=decrypted_data.get("threshold"),
            signers=decrypted_data.get("signers"),
            multisig_address=decrypted_data.get("multisig_address"),
            created_at=datetime.now(UTC),
        )

    def save(self, path: str, password: str | None = None) -> None:
        """Encrypt and write the key to `path`. If no password is provided, prompt securely."""
        if password is None:
            pw1 = getpass("Set password for key file: ")
            pw2 = getpass("Confirm password: ")
            if pw1 != pw2:
                raise ValueError("Passwords do not match")
            password = pw1
        blob = self.encrypt(password)
        # Ensure the parent directory exists
        parent = os.path.dirname(os.path.expanduser(path)) or "."
        os.makedirs(parent, exist_ok=True)
        with open(os.path.expanduser(path), "w") as file:
            json.dump(blob, file, indent=2)

    @staticmethod
    def load(path: str, password: str | None = None) -> "Key":
        """Load and decrypt a key from `path`. If no password is provided, prompt securely."""
        if password is None:
            password = getpass("Password for key file: ")
        with open(os.path.expanduser(path), "r") as file:
            encrypted_blob = json.load(file)
        return Key.decrypt(encrypted_blob, password)


class AuraSR25519Key(Key):
    secret_phrase: str


class GrandpaED25519Key(Key):
    secret_phrase: str


class ModNetSS58Key(Key):
    public_key_hex: str
    ss58_address: str


def subkey_inspect(public_hex: str, network: str, scheme: str) -> dict:
    """Call `subkey inspect` to derive SS58 address info for a public key."""
    require_subkey()
    # subkey inspect --network substrate --public --scheme sr25519 0x<hex>
    out = run(["subkey", "inspect", "--network", network, "--public", "--scheme", scheme, public_hex])
    return parse_subkey_generate(out)


def multisig_address(signers: list[str], threshold: int, ss58_prefix: int) -> dict:
    """Compute a deterministic pallet-multisig address from signers and threshold."""
    try:
        from substrateinterface.utils.ss58 import ss58_encode, ss58_decode
        from hashlib import blake2b
    except Exception as e:
        sys.stderr.write("Error: Python deps missing. Install from scripts/requirements.txt\n")
        raise

    # The multisig account id in pallet-multisig is constructed deterministically from sorted signers and threshold.
    # Reference (pallet-multisig): multi_account_id = AccountId::from(blake2_256(b"modlpy/utilisig" ++ sorted_signers ++ threshold LE));
    # We implement the same here to ensure exact match.
    tag = b"modlpy/utilisig"

    # Decode SS58 to raw pubkey bytes (AccountId32)
    signer_pubkeys = [bytes.fromhex(ss58_decode(signer)) for signer in signers]
    # Sort lexicographically as per pallet
    signer_pubkeys.sort()

    # threshold as little endian u16
    threshold_le = threshold.to_bytes(2, byteorder="little")

    hasher = blake2b(digest_size=32)
    hasher.update(tag)
    for public_key in signer_pubkeys:
        hasher.update(public_key)
    hasher.update(threshold_le)
    account_id = hasher.digest()

    address = ss58_encode(account_id.hex(), ss58_format=ss58_prefix)
    return {"account_id_hex": account_id.hex(), "ss58_address": address}


def _print_json(data_obj: dict):
    """Pretty-print JSON to terminal if TTY, otherwise emit raw JSON for piping."""
    # If stdout is a TTY, use rich pretty JSON; otherwise raw JSON for piping
    if sys.stdout.isatty():
        console.print(JSON.from_data(data_obj))
    else:
        sys.stdout.write(json.dumps(data_obj, indent=2, default=_json_default) + "\n")


def _default_out_path(scheme: str, role_hint: str | None = None) -> str:
    """Compute a default output path in DEFAULT_KEYS_DIR with timestamp and scheme.

    If role_hint is provided (e.g., "aura" or "grandpa"), include it in the filename.
    """
    ensure_keys_dir()
    timestamp_str = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    if role_hint:
        filename = f"{timestamp_str}-{role_hint}-{scheme}.json"
    else:
        filename = f"{timestamp_str}-{scheme}.json"
    return os.path.join(DEFAULT_KEYS_DIR, filename)


def _save_key_with_password(key_obj: "Key", out_path: str | None, scheme: str, password: str | None, role_hint: str | None = None) -> str:
    """Save key_obj to out_path (or default), using provided password (non-interactive) or prompting if None."""
    target_path = os.path.expanduser(out_path) if out_path else _default_out_path(scheme, role_hint)
    key_obj.save(target_path, password)
    return target_path


def cmd_gen(args):
    """Handle `gen` subcommand: generate a single keypair and save it encrypted."""
    key_obj = subkey_generate(args.scheme, args.network)
    saved_path = _save_key_with_password(key_obj, args.out, args.scheme, args.password)
    console.print(f"[green]Saved generated key to[/green] {saved_path}")
    _print_json(key_obj.to_json(include_secret=False))


def cmd_gen_all(args):
    """Handle `gen-all` subcommand: generate Aura and GRANDPA keypairs and save them encrypted."""
    aura_key = subkey_generate("sr25519", args.network)
    grandpa_key = subkey_generate("ed25519", args.network)
    # Determine out directory
    out_dir = os.path.expanduser(args.out_dir) if getattr(args, "out_dir", None) else DEFAULT_KEYS_DIR
    os.makedirs(out_dir, exist_ok=True)
    timestamp_str = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    aura_filename = os.path.join(out_dir, f"{timestamp_str}-aura-sr25519.json")
    grandpa_filename = os.path.join(out_dir, f"{timestamp_str}-grandpa-ed25519.json")
    aura_key.save(aura_filename, args.password)
    grandpa_key.save(grandpa_filename, args.password)
    console.print(f"[green]Saved Aura key to[/green] {aura_filename}")
    console.print(f"[green]Saved GRANDPA key to[/green] {grandpa_filename}")
    _print_json({
        "aura": aura_key.to_json(include_secret=False),
        "grandpa": grandpa_key.to_json(include_secret=False),
        "network": args.network,
        "saved": {"aura": aura_filename, "grandpa": grandpa_filename},
    })


def cmd_inspect(args):
    """Handle `inspect` subcommand: map a public key to SS58 address."""
    key_obj = Key.from_public(args.public, args.scheme, args.network)
    _print_json(key_obj.to_json(include_secret=False))


def cmd_multisig(args):
    """Handle `multisig` subcommand: compute multisig account from signers/threshold."""
    result = multisig_address(args.signer, args.threshold, args.ss58_prefix)
    _print_json({"threshold": args.threshold, "ss58_prefix": args.ss58_prefix, **result, "signers": args.signer})


def cmd_derive(args):
    """Handle `derive` subcommand: derive public/SS58 from phrase or public key."""
    if args.phrase:
        key_obj = Key.from_secret_phrase(args.phrase, args.scheme, args.network)
    elif args.public:
        key_obj = Key.from_public(args.public, args.scheme, args.network)
    else:
        raise ValueError("Provide --phrase or --public")
    key_obj = key_obj.derive_public_ss58()
    _print_json(key_obj.to_json(include_secret=args.with_secret))


def cmd_key_save(args):
    """Handle `key-save` subcommand: encrypt a key and save it to disk."""
    if args.phrase:
        key_obj = Key.from_secret_phrase(args.phrase, args.scheme, args.network)
    elif args.public:
        key_obj = Key.from_public(args.public, args.scheme, args.network)
    else:
        raise ValueError("Provide --phrase or --public")
    # Determine output path
    if args.out:
        out_path = os.path.expanduser(args.out)
    else:
        ensure_keys_dir()
        if args.name:
            filename = args.name
            if not filename.endswith(".json"):
                filename += ".json"
        else:
            timestamp_str = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
            filename = f"{timestamp_str}-{args.scheme}.json"
        out_path = os.path.join(DEFAULT_KEYS_DIR, filename)
    key_obj.save(out_path, None if args.prompt else args.password)
    console.print(f"[green]Saved encrypted key to[/green] {out_path}")


def cmd_key_load(args):
    """Handle `key-load` subcommand: decrypt a key file and print fields."""
    path = resolve_key_path(args.file)
    key_obj = Key.load(path, None if args.prompt else args.password)
    _print_json(key_obj.to_json(include_secret=args.with_secret))





def require_subkey():
    """Ensure the `subkey` binary is available on PATH, or exit with an error."""
    if not shutil.which("subkey"):
        sys.stderr.write("Error: 'subkey' not found on PATH. Install Substrate subkey tool.\n")
        sys.exit(1)

def run(cmd: list[str]) -> str:
    """Run a subprocess command and return stdout, raising if non-zero exit."""
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nSTDERR:\n{proc.stderr}")
    return proc.stdout

def parse_subkey_generate(output: str) -> dict:
    """Parse `subkey generate/inspect` output for secret phrase, public key, and SS58."""
    # subkey generate --scheme <scheme> prints a well-known format
    # We'll extract: Secret phrase, Public key (hex), SS58 Address
    data = {
        "secret_phrase": None,
        "public_key_hex": None,
        "ss58_address": None,
    }
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("secret phrase"):
            # e.g., Secret phrase:      equip will roof ...
            data["secret_phrase"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("public key (hex)"):
            data["public_key_hex"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("ss58 address"):
            data["ss58_address"] = line.split(":", 1)[1].strip()
    return data

def subkey_generate(scheme: str, network: str) -> Key:
    """Generate a new keypair via `subkey generate` and return a Key object."""
    require_subkey()
    out = run(["subkey", "generate", "--scheme", scheme, "--network", network])
    parsed = parse_subkey_generate(out)
    secret = parsed.get("secret_phrase")
    if scheme == "sr25519":
        return AuraSR25519Key(
            scheme=scheme,
            network=network,
            secret_phrase=secret,
            public_key_hex=parsed.get("public_key_hex"),
            ss58_address=parsed.get("ss58_address"),
            key_type="sr25519",
            is_pair=True,
            created_at=datetime.now(UTC),
        )
    else:
        return GrandpaED25519Key(
            scheme=scheme,
            network=network,
            secret_phrase=secret,
            public_key_hex=parsed.get("public_key_hex"),
            ss58_address=parsed.get("ss58_address"),
            key_type="ed25519",
            is_pair=True, 
            created_at=datetime.now(UTC),
        )

class HelpOnErrorParser(argparse.ArgumentParser):
    def error(self, message):
        """Override to show help text along with the error message."""
        console.print(f"[red]Error:[/red] {message}")
        self.print_help()
        self.exit(2)


def main():
    """CLI entrypoint for key utilities."""
    p = HelpOnErrorParser(description="Key tools for Modnet", formatter_class=RichHelpFormatter)
    sub = p.add_subparsers(dest="command")

    p_gen = sub.add_parser("gen", help="Generate a single keypair via subkey")
    p_gen.add_argument("--scheme", choices=["sr25519", "ed25519"], required=True)
    p_gen.add_argument("--network", default="substrate")
    p_gen.add_argument("--out", help="Output file path (default: ~/.modnet/keys/<timestamp>-<scheme>.json)")
    p_gen.add_argument("--password", help="Encrypt without prompting using this password")
    p_gen.set_defaults(func=cmd_gen)

    p_gen_all = sub.add_parser("gen-all", help="Generate Aura (sr25519) and GRANDPA (ed25519) keypairs")
    p_gen_all.add_argument("--network", default="substrate")
    p_gen_all.add_argument("--out-dir", help="Directory to save both keys (default: ~/.modnet/keys/)")
    p_gen_all.add_argument("--password", help="Encrypt without prompting using this password for both keys")
    p_gen_all.set_defaults(func=cmd_gen_all)

    p_inspect = sub.add_parser("inspect", help="Inspect a public key to SS58 address")
    p_inspect.add_argument("--public", required=True, help="0x<hex public key>")
    p_inspect.add_argument("--scheme", choices=["sr25519", "ed25519"], required=True)
    p_inspect.add_argument("--network", default="substrate")
    p_inspect.set_defaults(func=cmd_inspect)

    p_multi = sub.add_parser("multisig", help="Compute multisig address from signers and threshold")
    p_multi.add_argument("--signer", action="append", required=True, help="SS58 signer address; pass multiple --signer")
    p_multi.add_argument("--threshold", type=int, required=True)
    p_multi.add_argument("--ss58-prefix", type=int, default=42)
    p_multi.set_defaults(func=cmd_multisig)

    p_derive = sub.add_parser("derive", help="Derive public/SS58 from a secret phrase or public key")
    p_derive.add_argument("--scheme", choices=["sr25519", "ed25519"], required=True)
    p_derive.add_argument("--network", default="substrate")
    p_derive.add_argument("--phrase", help="Secret phrase (mnemonic)")
    p_derive.add_argument("--public", help="0x<hex public key>")
    p_derive.add_argument("--with-secret", action="store_true", help="Include secret in output (if available)")
    p_derive.set_defaults(func=cmd_derive)

    p_save = sub.add_parser("key-save", help="Encrypt and save a key file (scrypt+AES-GCM)")
    p_save.add_argument("--scheme", choices=["sr25519", "ed25519"], required=True)
    p_save.add_argument("--network", default="substrate")
    p_save.add_argument("--phrase", help="Secret phrase (mnemonic)")
    p_save.add_argument("--public", help="0x<hex public key>")
    p_save.add_argument("--out", help="Output file path (default: ~/.modnet/keys/<timestamp>-<scheme>.json)")
    p_save.add_argument("--name", help="Filename to use under ~/.modnet/keys (e.g., aura-sr25519.json)")
    p_save.add_argument("--password", help="Password (omit to be prompted)")
    p_save.add_argument("--prompt", action="store_true", help="Prompt for password (recommended)")
    p_save.set_defaults(func=cmd_key_save)

    # Short alias: save
    p_save2 = sub.add_parser("save", help="Alias for key-save")
    p_save2.add_argument("--scheme", choices=["sr25519", "ed25519"], required=True)
    p_save2.add_argument("--network", default="substrate")
    p_save2.add_argument("--phrase", help="Secret phrase (mnemonic)")
    p_save2.add_argument("--public", help="0x<hex public key>")
    p_save2.add_argument("--out", help="Output file path (default: ~/.modnet/keys/<timestamp>-<scheme>.json)")
    p_save2.add_argument("--name", help="Filename to use under ~/.modnet/keys (e.g., aura-sr25519.json)")
    p_save2.add_argument("--password", help="Password (omit to be prompted)")
    p_save2.add_argument("--prompt", action="store_true", help="Prompt for password (recommended)")
    p_save2.set_defaults(func=cmd_key_save)

    p_load = sub.add_parser("key-load", help="Decrypt a saved key file and print fields")
    p_load.add_argument("--file", required=True, help="Path or filename in ~/.modnet/keys")
    p_load.add_argument("--password", help="Password (omit to be prompted)")
    p_load.add_argument("--prompt", action="store_true", help="Prompt for password")
    p_load.add_argument("--with-secret", action="store_true", help="Include secret in output")
    p_load.set_defaults(func=cmd_key_load)

    # Short alias: load
    p_load2 = sub.add_parser("load", help="Alias for key-load")
    p_load2.add_argument("--file", required=True, help="Path or filename in ~/.modnet/keys")
    p_load2.add_argument("--password", help="Password (omit to be prompted)")
    p_load2.add_argument("--prompt", action="store_true", help="Prompt for password")
    p_load2.add_argument("--with-secret", action="store_true", help="Include secret in output")
    p_load2.set_defaults(func=cmd_key_load)


    if len(sys.argv) == 1:
        p.print_help()
        sys.exit(2)

    args = p.parse_args()
    if not hasattr(args, "func"):
        p.print_help()
        sys.exit(2)
    try:
        args.func(args)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        p.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
