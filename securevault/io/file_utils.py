"""File and folder handling utilities for SecureVault."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Tuple
import zipfile


def read_source(path: str) -> Tuple[bytes, bool]:
    """Return file bytes and whether the input was archived.

    If ``path`` is a directory, its contents are zipped in-memory to ensure a
    single ciphertext blob. The caller is expected to note the archive flag so
    decryption can extract into a directory later.
    """

    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"Input path {path} does not exist.")
    if source.is_dir():
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for fs_item in sorted(source.rglob("*")):
                if fs_item.is_dir():
                    # Zip format stores directories implicitly when files within them are added.
                    continue
                arcname = fs_item.relative_to(source)
                zf.write(fs_item, arcname.as_posix())
        return buffer.getvalue(), True
    if source.is_file():
        return source.read_bytes(), False
    raise FileNotFoundError(f"Unsupported input path {path}.")


def materialize_output(path: str, data: bytes, is_archive: bool) -> None:
    """Write decrypted data to disk.

    Archives are extracted into the provided directory path. Plain files are
    written directly, creating parent directories when needed.
    """

    target = Path(path)
    if is_archive:
        target.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            zf.extractall(target)
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
