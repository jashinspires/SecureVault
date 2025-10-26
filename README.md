<<<<<<< HEAD
# SecureVault
=======
# SecureVault

SecureVault is a beginner-friendly tool that encrypts files or entire folders with AES-256 in Galois/Counter Mode (GCM) and requires two factors to decrypt: the original password (PBKDF2-HMAC-SHA256 with 200k iterations) and a rolling TOTP code (Google Authenticator compatible). The project provides both a CLI and a compact Tkinter GUI so you can secure data on local disks or removable drives.

## Quickstart

1. **Prerequisites**: Python 3.8+ and `pip`.
2. **Install dependencies**:
   ```bash
   pip install cryptography pyotp qrcode
   ```
   `qrcode` is optional; without it the CLI prints a provisioning URI instead of an ASCII QR code.
3. **Run the CLI**:
   ```bash
   python -m securevault encrypt --input secret.txt --out secret.txt.svlt --password-prompt
   python -m securevault provision-totp --output secret.totp.json --account you@example.com
   python -m securevault decrypt --input secret.txt.svlt --out secret.txt --password-prompt --otp --otp-meta secret.totp.json
   # optional: beginner friendly output
   python -m securevault encrypt --input secret.txt --out secret.txt.json --password-prompt --format json
   ```
   Decryption now fails unless both the password and a current 6-digit OTP are correct.
4. **Run tests**:
   ```bash
   pytest
   ```

## Security model

- **Key derivation**: 200,000-iteration PBKDF2-HMAC-SHA256 with a random 16-byte salt to slow brute-force attempts. Increase iterations for stronger protection at the cost of CPU time.
- **Encryption**: AES-256-GCM with 12-byte random nonce and 16-byte authentication tag to guarantee confidentiality and integrity.
- **Two-factor requirement**: TOTP secret stored in `*.totp.json` metadata file (per encrypted dataset). Decryption only succeeds when both the password and the current 6-digit code verify successfully.
- **Header design**: Binary header records magic bytes, version, flags, salt, nonce, and tag. Optional human-readable JSON wrapper base64-encodes the same data for education and debugging.

## What works now

- Password-derived AES-256 encryption/decryption with PBKDF2-HMAC-SHA256 (200k iterations, 16-byte random salt, 12-byte nonce).
- Binary header storing magic bytes, version, salt, nonce length, tag length, and ciphertext.
- Flags byte tracks whether the original input was a directory archive; decryption will automatically extract to the provided directory path.
- Human-readable JSON wrapper (`--format json`) that base64-encodes the header fields and ciphertext for ease of inspection and tutorials.
- CLI command `provision-totp` writes a JSON metadata file and prints a provisioning URI/QR for Google Authenticator.
- CLI commands `encrypt` and `decrypt` require both password and valid TOTP for successful decryption.
- Unit tests covering key derivation, encryption/decryption round-trips, incorrect password handling, and OTP verification edge cases.
- Optional Tkinter GUI (`python -m securevault.gui`) for point-and-click workflows, including provisioning, encryption, and decryption with password + TOTP prompts.

## Example CLI usage

```
# provision and get QR URI
python -m securevault provision-totp --output totp-meta.json --account you@example.com

# encrypt a file
python -m securevault encrypt --input secret.txt --out secret.txt.svlt --password-prompt

# decrypt
python -m securevault decrypt --input secret.txt.svlt --out secret.txt --password-prompt --otp --otp-meta totp-meta.json
# prompts: password (hidden), then "Enter 6-digit TOTP"
```

An `examples/` directory contains `sample.txt.svlt`, a matching `sample.totp.json`, and `decryption-log.txt` documenting the commands used to produce them. Use these artifacts to test the workflow quickly (replace the sample password and TOTP secret before securing real data).

## Next steps

- Extend the header parser to handle alternate formats and folder packaging.
- Add a minimal Tkinter GUI (optional milestone).
- Expand folder packaging to support streaming (tar) and document trade-offs between zip/tar.

## Folder encryption workflow

- When `--input` points at a directory, SecureVault streams the contents into a ZIP archive before encryption.
- During decryption the archive flag stored in the header ensures the decrypted data is automatically extracted into the directory supplied via `--out`.
- Keep the output directory empty before decrypting to avoid overwriting unrelated files.

## Header layout (binary format)

```
[offset] field
0..4    b"SVLT"          # magic
4       version byte     # 0x01
5       flags byte       # bit0 => archive payload
6..21   salt (16 bytes)
22      nonce length (byte)
23..    nonce bytes (default 12)
...     tag length (byte) + tag (16 bytes)
...     ciphertext bytes
```

JSON output stores the same values base64-encoded inside a structured object for beginners who prefer inspecting values without binary tooling.

## GUI quickstart

Launch the Tkinter interface:

```bash
python -m securevault.gui
```

Features:
- Browse to any file, folder, or removable drive (USB pendrive, external HDD) using the "Browse" buttons.
- Provision TOTP metadata directly from the GUI; the QR code appears in a pop-up (requires `qrcode` and `Pillow`, otherwise the provisioning URI is shown as text).
- Encrypts folders by zipping transparently; decrypted archives expand into the chosen directory.
- Enforces password + TOTP verification whenever you decrypt—even on a different computer, provided you copy the encrypted file and matching TOTP metadata JSON together.

> **Tip:** Keep the encrypted file (`*.svlt` or `*.json`) and the TOTP metadata JSON on the same removable media. Anyone without both the password and the rolling TOTP code cannot decrypt the payload, even if the drive is accessed on another machine.

![SecureVault GUI](docs/gui-screenshot.png)

## Packaging & deployment notes

- Create standalone binaries with PyInstaller: `pyinstaller --onefile -w securevault\gui.py` (ensures Tkinter GUI launches without a console window). Ship `qrcode`/`Pillow` alongside if you want QR rendering.
- For cross-platform CLI usage, distribute the source package or use PyInstaller in console mode.
- Dependencies are limited to `cryptography`, `pyotp`, `qrcode`, and optionally `Pillow` for QR previews.

## Manual test plan

1. Provision a TOTP secret (`python -m securevault provision-totp --output demo.totp.json --account demo@example.com`).
2. Encrypt a small file (`python -m securevault encrypt --input demo.txt --out demo.svlt --password-prompt`).
3. Attempt decryption with correct password + current OTP — expect success.
4. Retry with an incorrect password — expect `Decryption failed` error.
5. Retry with an incorrect/expired OTP — expect `Invalid or expired TOTP code`.
6. Encrypt a folder and decrypt into an empty directory — verify files are restored intact.

## Limitations & future ideas

- TOTP metadata JSON is stored alongside encrypted data for convenience; move it to a secure vault or ensure removable media is protected from tampering.
- Current archiving uses ZIP in memory—large directories could consume additional RAM. Streaming tar/zip support and progress feedback are planned upgrades.
- GUI is intentionally minimal; future improvements include dark-mode polish, password strength meters, and key rotation UI.
>>>>>>> 5cf94d5 (Initial SecureVault Release)
