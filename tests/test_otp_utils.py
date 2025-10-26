import pyotp

from securevault.otp import otp_utils


def test_create_and_load_totp_metadata(tmp_path):
    output = tmp_path / "metadata.json"
    metadata = otp_utils.create_totp_metadata(
        output_path=output,
        account_name="user@example.com",
        issuer="SecureVaultTests",
        show_qr=False,
    )
    assert metadata.secret
    loaded = otp_utils.load_totp_metadata(output)
    assert loaded.secret == metadata.secret
    assert loaded.account_name == "user@example.com"
    assert loaded.issuer == "SecureVaultTests"


def test_verify_totp_accepts_valid_code(tmp_path):
    output = tmp_path / "metadata.json"
    metadata = otp_utils.create_totp_metadata(
        output_path=output,
        account_name="user@example.com",
        issuer="SecureVaultTests",
        show_qr=False,
    )
    totp = pyotp.TOTP(metadata.secret, digits=metadata.digits, interval=metadata.interval)
    code = totp.now()
    assert otp_utils.verify_totp(metadata, code)


def test_verify_totp_rejects_invalid_code(tmp_path):
    metadata = otp_utils.TOTPMetadata(
        secret=pyotp.random_base32(),
        issuer="SecureVaultTests",
        account_name="user@example.com",
        digits=6,
        interval=30,
        provisioning_uri="",
    )
    assert not otp_utils.verify_totp(metadata, "123456")
