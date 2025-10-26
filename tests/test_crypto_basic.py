import os

import pytest

from securevault.crypto import crypto_utils


def test_derive_key_returns_32_bytes():
    salt = os.urandom(crypto_utils.PBKDF2_SALT_LEN)
    key = crypto_utils.derive_key("password123", salt)
    assert len(key) == 32


def test_encrypt_decrypt_roundtrip(tmp_path):
    original = b"Hello SecureVault"
    password = "strong-password"
    encrypted, meta = crypto_utils.encrypt_bytes(password, original)
    assert meta.salt and meta.nonce and meta.tag  # Sanity check header parts
    assert meta.flags == 0

    decrypted, parsed = crypto_utils.decrypt_bytes(password, encrypted)
    assert decrypted == original
    assert parsed.flags == 0


def test_decrypt_with_wrong_password_fails(tmp_path):
    original = b"data"
    encrypted, _ = crypto_utils.encrypt_bytes("correct-horse-battery-staple", original)
    with pytest.raises(ValueError):
        crypto_utils.decrypt_bytes("wrong-password", encrypted)


def test_encrypt_json_format_roundtrip():
    original = b"JSON path"
    password = "secure"
    encrypted, meta = crypto_utils.encrypt_bytes(password, original, output_format="json")
    assert meta.format == "json"
    decrypted, parsed = crypto_utils.decrypt_bytes(password, encrypted)
    assert parsed.format == "json"
    assert decrypted == original


def test_parse_header_rejects_bad_magic():
    original = b"bad magic test"
    password = "secure"
    encrypted, _ = crypto_utils.encrypt_bytes(password, original)
    tampered = b"BAD!" + encrypted[4:]
    with pytest.raises(crypto_utils.HeaderParseError):
        crypto_utils.parse_header(tampered)


def test_header_flags_preserved():
    original = b"archive"
    password = "secure"
    encrypted, meta = crypto_utils.encrypt_bytes(password, original, flags=crypto_utils.HEADER_FLAG_ARCHIVE)
    assert meta.flags & crypto_utils.HEADER_FLAG_ARCHIVE
    _, parsed = crypto_utils.decrypt_bytes(password, encrypted)
    assert parsed.flags & crypto_utils.HEADER_FLAG_ARCHIVE
