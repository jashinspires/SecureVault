"""Time-based One-Time Password utilities for SecureVault.

These helpers manage provisioning, metadata persistence, and verification of
TOTP codes using the pyotp library.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

import pyotp


@dataclass
class TOTPMetadata:
    """Serializable description of a TOTP secret and display metadata."""

    secret: str
    issuer: str
    account_name: str
    digits: int = 6
    interval: int = 30
    provisioning_uri: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "TOTPMetadata":
        return cls(**data)


def generate_totp_secret(length: int = 32) -> str:
    """Return a random Base32 secret compatible with authenticator apps."""

    return pyotp.random_base32(length=length)


def _display_qr_in_terminal(provisioning_uri: str) -> None:
    try:
        import qrcode
    except ImportError:  # pragma: no cover - optional dependency
        print("Install the 'qrcode' package to display QR codes, or copy the URI below.")
        print(provisioning_uri)
        return

    qr = qrcode.QRCode(border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    qr.print_ascii(out=sys.stdout)


def create_totp_metadata(
    output_path: Path | str,
    account_name: str,
    issuer: str = "SecureVault",
    digits: int = 6,
    interval: int = 30,
    show_qr: bool = True,
) -> TOTPMetadata:
    """Provision a new TOTP secret and persist metadata to JSON."""

    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret, digits=digits, interval=interval)
    provisioning_uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)

    metadata = TOTPMetadata(
        secret=secret,
        issuer=issuer,
        account_name=account_name,
        digits=digits,
        interval=interval,
        provisioning_uri=provisioning_uri,
    )

    path = Path(output_path)
    path.write_text(json.dumps(metadata.to_dict(), indent=2), encoding="utf-8")

    if show_qr:
        _display_qr_in_terminal(provisioning_uri)
    else:  # helpful for automated tests to still show the URI
        print(provisioning_uri)
    return metadata


def load_totp_metadata(path: Path | str) -> TOTPMetadata:
    """Load TOTP metadata from disk."""

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return TOTPMetadata.from_dict(data)


def verify_totp(metadata: TOTPMetadata, otp_code: str, valid_window: int = 1) -> bool:
    """Validate a user-supplied OTP code.

    A small ``valid_window`` allows the previous/next time step to account for
    clock skew. We intentionally avoid logging the OTP code.
    """

    code = otp_code.strip()
    if not code.isdigit():
        return False
    totp = pyotp.TOTP(metadata.secret, digits=metadata.digits, interval=metadata.interval)
    return bool(totp.verify(code, valid_window=valid_window))
