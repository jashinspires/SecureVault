"""Utilities handling key derivation and AES-GCM encryption/decryption for SecureVault.

This module keeps milestone one intentionally focused on password-based encryption. TOTP
capabilities are stubbed at the CLI layer until milestone two introduces real OTP flows.
"""

from __future__ import annotations

import os
import base64
import json
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants chosen to satisfy the project security requirements.
PBKDF2_ITERATIONS_DEFAULT: int = 200_000
PBKDF2_SALT_LEN: int = 16
AES_GCM_NONCE_LEN: int = 12
AES_GCM_TAG_LEN: int = 16
HEADER_MAGIC: bytes = b"SVLT"
HEADER_VERSION: int = 1
HEADER_FLAG_ARCHIVE: int = 0x01


@dataclass
class PayloadMetadata:
    """Metadata captured alongside ciphertext in SecureVault payloads."""

    salt: bytes
    nonce: bytes
    tag: bytes
    ciphertext: bytes
    flags: int
    format: str = "binary"


class HeaderParseError(Exception):
    """Raised when an encrypted payload header fails validation."""


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS_DEFAULT) -> bytes:
    """Derive a 256-bit key from the user password using PBKDF2-HMAC-SHA256.

    PBKDF2 deliberately slows down brute-force attempts at the password. 200k
    iterations keeps the CLI responsive on modern hardware while making GPUs/ASICs
    work harder. Users can tune the iteration count later if required.
    """

    if not password:
        raise ValueError("Password must not be empty.")
    if len(salt) != PBKDF2_SALT_LEN:
        raise ValueError("Salt must be exactly 16 bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-256
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password.encode("utf-8"))
    return key


def _split_ciphertext_and_tag(payload: bytes) -> Tuple[bytes, bytes]:
    if len(payload) < AES_GCM_TAG_LEN:
        raise HeaderParseError("Encrypted payload truncated before tag.")
    return payload[:-AES_GCM_TAG_LEN], payload[-AES_GCM_TAG_LEN:]


def encrypt_bytes(password: str, plaintext: bytes, *, flags: int = 0, output_format: str = "binary") -> Tuple[bytes, PayloadMetadata]:
    """Encrypt arbitrary bytes with AES-GCM keyed by the password-derived key."""

    salt = os.urandom(PBKDF2_SALT_LEN)
    key = derive_key(password, salt)
    nonce = os.urandom(AES_GCM_NONCE_LEN)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    ciphertext, tag = _split_ciphertext_and_tag(ciphertext_with_tag)
    payload = PayloadMetadata(salt=salt, nonce=nonce, tag=tag, ciphertext=ciphertext, flags=flags, format=output_format)
    if output_format == "json":
        return _build_json_payload(payload), payload
    if output_format != "binary":
        raise ValueError("Unsupported output format. Choose 'binary' or 'json'.")
    header = _build_header(salt, nonce, tag, flags)
    return header + ciphertext, payload


def decrypt_bytes(password: str, payload: bytes) -> Tuple[bytes, PayloadMetadata]:
    """Decrypt bytes previously produced by :func:`encrypt_bytes`."""

    metadata = parse_header(payload)
    salt, nonce, tag, ciphertext = metadata.salt, metadata.nonce, metadata.tag, metadata.ciphertext
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    except Exception as exc:  # cryptography raises InvalidTag for any auth failure
        raise ValueError("Decryption failed. Password or file integrity incorrect.") from exc
    return plaintext, metadata


def _build_header(salt: bytes, nonce: bytes, tag: bytes, flags: int) -> bytes:
    if len(salt) != PBKDF2_SALT_LEN:
        raise ValueError("Salt must be 16 bytes.")
    if len(nonce) > 255 or len(tag) > 255:
        raise ValueError("Nonce and tag lengths must fit in one byte for the header format.")
    if not 0 <= flags <= 255:
        raise ValueError("Header flags must fit in one byte.")
    components = [
        HEADER_MAGIC,
        HEADER_VERSION.to_bytes(1, "big"),
        flags.to_bytes(1, "big"),
        salt,
        len(nonce).to_bytes(1, "big"),
        nonce,
        len(tag).to_bytes(1, "big"),
        tag,
    ]
    return b"".join(components)


def _build_json_payload(metadata: PayloadMetadata) -> bytes:
    data = {
        "svlt_format": "securevault-json",
        "magic": HEADER_MAGIC.decode("ascii"),
        "version": HEADER_VERSION,
        "flags": metadata.flags,
        "salt": base64.b64encode(metadata.salt).decode("ascii"),
        "nonce": base64.b64encode(metadata.nonce).decode("ascii"),
        "tag": base64.b64encode(metadata.tag).decode("ascii"),
        "ciphertext": base64.b64encode(metadata.ciphertext).decode("ascii"),
    }
    return (json.dumps(data, indent=2) + "\n").encode("utf-8")


def parse_header(payload: bytes) -> PayloadMetadata:
    """Extract metadata and ciphertext from an encrypted payload.

    Automatically detects whether the payload is binary or JSON-wrapped.
    """

    stripped = payload.lstrip()
    if stripped.startswith(b"{"):
        return _parse_json_payload(payload)
    return _parse_binary_header(payload)


def _parse_binary_header(payload: bytes) -> PayloadMetadata:
    if len(payload) < len(HEADER_MAGIC) + 2 + PBKDF2_SALT_LEN + 2:
        raise HeaderParseError("Encrypted payload is too short to contain header.")
    idx = 0
    magic = payload[idx : idx + len(HEADER_MAGIC)]
    if magic != HEADER_MAGIC:
        raise HeaderParseError("Magic bytes do not match SecureVault format.")
    idx += len(HEADER_MAGIC)

    version = payload[idx]
    if version != HEADER_VERSION:
        raise HeaderParseError("Unsupported SecureVault header version.")
    idx += 1

    flags = payload[idx]
    idx += 1

    salt = payload[idx : idx + PBKDF2_SALT_LEN]
    idx += PBKDF2_SALT_LEN

    nonce_len = payload[idx]
    idx += 1
    nonce = payload[idx : idx + nonce_len]
    idx += nonce_len

    tag_len = payload[idx]
    idx += 1
    tag = payload[idx : idx + tag_len]
    idx += tag_len

    ciphertext = payload[idx:]
    if len(nonce) != nonce_len or len(tag) != tag_len:
        raise HeaderParseError("Header declared lengths do not match payload.")
    if len(tag) != AES_GCM_TAG_LEN:
        raise HeaderParseError("Unexpected GCM tag length.")
    return PayloadMetadata(
        salt=salt,
        nonce=nonce,
        tag=tag,
        ciphertext=ciphertext,
        flags=flags,
        format="binary",
    )


def _parse_json_payload(payload: bytes) -> PayloadMetadata:
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - should be caught in tests
        raise HeaderParseError("JSON payload could not be decoded.") from exc

    if data.get("svlt_format") != "securevault-json":
        raise HeaderParseError("JSON payload missing SecureVault marker.")
    if data.get("magic") != HEADER_MAGIC.decode("ascii"):
        raise HeaderParseError("JSON payload magic does not match SecureVault format.")
    if int(data.get("version", -1)) != HEADER_VERSION:
        raise HeaderParseError("Unsupported SecureVault JSON payload version.")

    try:
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        tag = base64.b64decode(data["tag"])
        ciphertext = base64.b64decode(data["ciphertext"])
    except Exception as exc:  # pragma: no cover - base64 errors handled here
        raise HeaderParseError("JSON payload contains invalid base64 data.") from exc

    flags = int(data.get("flags", 0))
    if len(salt) != PBKDF2_SALT_LEN:
        raise HeaderParseError("JSON payload salt has incorrect length.")
    if len(tag) != AES_GCM_TAG_LEN:
        raise HeaderParseError("JSON payload tag has incorrect length.")

    return PayloadMetadata(
        salt=salt,
        nonce=nonce,
        tag=tag,
        ciphertext=ciphertext,
        flags=flags,
        format="json",
    )


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    *,
    flags: int = 0,
    output_format: str = "binary",
) -> PayloadMetadata:
    """Encrypt a file on disk and persist the SecureVault payload."""

    with open(input_path, "rb") as f_in:
        plaintext = f_in.read()
    encrypted_blob, result = encrypt_bytes(password, plaintext, flags=flags, output_format=output_format)
    with open(output_path, "wb") as f_out:
        f_out.write(encrypted_blob)
    # Wipe sensitive material where feasible (best effort for CPython)
    plaintext = b""  # type: ignore[unreachable]
    return result


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypt a SecureVault-encrypted file back to plaintext."""

    with open(input_path, "rb") as f_in:
        payload = f_in.read()
    plaintext, _metadata = decrypt_bytes(password, payload)
    with open(output_path, "wb") as f_out:
        f_out.write(plaintext)
    plaintext = b""  # type: ignore[unreachable]
