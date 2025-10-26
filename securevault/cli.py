"""Command-line interface for SecureVault.

Milestone two adds real TOTP provisioning and verification alongside the
password-derived AES-GCM flow introduced earlier.
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path
from typing import Optional

from .crypto import crypto_utils
from .otp import otp_utils
from .io import file_utils


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securevault", description="Encrypt/decrypt files with AES-256 and TOTP.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file with AES-GCM.")
    encrypt_parser.add_argument("--input", required=True, help="Path to input file.")
    encrypt_parser.add_argument("--out", required=True, help="Path to output encrypted file.")
    encrypt_parser.add_argument("--password-prompt", action="store_true", help="Prompt for the encryption password.")
    encrypt_parser.add_argument(
        "--format",
        choices=["binary", "json"],
        default="binary",
        help="Output file format (binary is compact, json is beginner-friendly).",
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a previously encrypted file.")
    decrypt_parser.add_argument("--input", required=True, help="Path to encrypted file.")
    decrypt_parser.add_argument("--out", required=True, help="Path for decrypted output.")
    decrypt_parser.add_argument("--password-prompt", action="store_true", help="Prompt for the decryption password.")
    decrypt_parser.add_argument("--otp", action="store_true", help="Prompt for a TOTP code during decryption.")
    decrypt_parser.add_argument(
        "--otp-meta",
        help="Path to the TOTP metadata JSON (defaults to <input>.totp.json).",
    )

    provision_parser = subparsers.add_parser("provision-totp", help="Create a new TOTP secret and metadata file.")
    provision_parser.add_argument("--output", required=True, help="Where to store the metadata JSON.")
    provision_parser.add_argument("--account", required=True, help="Account label shown in the authenticator app.")
    provision_parser.add_argument("--issuer", default="SecureVault", help="Issuer label (defaults to SecureVault).")
    provision_parser.add_argument(
        "--no-qr",
        action="store_true",
        help="Skip ASCII QR output (provisioning URI will still be printed).",
    )

    return parser


def _prompt_password(flag: bool, prompt_text: str) -> str:
    if not flag:
        raise ValueError("Password prompt required for secure operation.")
    password = getpass.getpass(prompt_text)
    if not password:
        raise ValueError("Password may not be empty.")
    return password


def _prompt_totp(enabled: bool) -> str:
    if not enabled:
        raise ValueError("Decryption requires OTP verification. Use --otp to enable prompts.")
    code = input("Enter 6-digit TOTP: ").strip()
    if len(code) != 6 or not code.isdigit():
        raise ValueError("TOTP codes must be 6 digits.")
    return code


def handle_encrypt(input_path: str, output_path: str, password_prompt: bool, output_format: str) -> None:
    password = _prompt_password(password_prompt, "Enter password for encryption: ")
    plaintext, is_archive = file_utils.read_source(input_path)
    flags = crypto_utils.HEADER_FLAG_ARCHIVE if is_archive else 0
    encrypted_blob, _meta = crypto_utils.encrypt_bytes(
        password,
        plaintext,
        flags=flags,
        output_format=output_format,
    )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    mode = "wb"
    if output_format == "json":
        mode = "w"
    with open(output_path, mode) as output_file:
        if output_format == "json":
            output_file.write(encrypted_blob.decode("utf-8"))
        else:
            output_file.write(encrypted_blob)
    if is_archive:
        print("Input directory was zipped before encryption. Decrypt to a folder destination.")


def handle_decrypt(input_path: str, output_path: str, password_prompt: bool, otp_prompt: bool, otp_meta: Optional[str]) -> None:
    password = _prompt_password(password_prompt, "Enter password for decryption: ")
    code = _prompt_totp(otp_prompt)

    metadata_path = Path(otp_meta) if otp_meta else Path(f"{input_path}.totp.json")
    if not metadata_path.exists():
        raise FileNotFoundError(
            f"TOTP metadata not found at {metadata_path}. Run 'securevault provision-totp --output <file>' first."
        )
    metadata = otp_utils.load_totp_metadata(metadata_path)
    if not otp_utils.verify_totp(metadata, code):
        raise ValueError("Invalid or expired TOTP code.")
    with open(input_path, "rb") as input_file:
        payload = input_file.read()
    plaintext, payload_meta = crypto_utils.decrypt_bytes(password, payload)
    is_archive = bool(payload_meta.flags & crypto_utils.HEADER_FLAG_ARCHIVE)
    file_utils.materialize_output(output_path, plaintext, is_archive)
    if is_archive:
        print(f"Archive extracted to {output_path}.")


def handle_provision(output_path: str, account: str, issuer: str, show_qr: bool) -> None:
    metadata = otp_utils.create_totp_metadata(
        output_path=output_path,
        account_name=account,
        issuer=issuer,
        show_qr=show_qr,
    )
    print(f"Metadata written to {output_path}.")
    print("Provisioning URI (store securely, do not share):")
    print(metadata.provisioning_uri)


def main(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            handle_encrypt(args.input, args.out, args.password_prompt, args.format)
            return 0
        if args.command == "decrypt":
            handle_decrypt(args.input, args.out, args.password_prompt, args.otp, args.otp_meta)
            return 0
        if args.command == "provision-totp":
            handle_provision(args.output, args.account, args.issuer, not args.no_qr)
            return 0
    except (ValueError, FileNotFoundError) as exc:
        print(f"Error: {exc}")
        return 1

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
