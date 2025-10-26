# SecureVault

SecureVault is a beginner-friendly utility that helps you encrypt files and folders with strong, modern cryptography and an extra layer of protection: a time-based one‑time password (TOTP) like Google Authenticator. You can use it from the command line (CLI) or a small Tkinter-based GUI.

> Friendly summary: enter a password and a 6-digit code from an authenticator app to decrypt. That way, even if someone steals your encrypted file and guesses your password, they still need the rolling TOTP code to open it.

---

## Quick start 

1. Make sure you have **Python 3.8+** and `pip` installed.
2. Install the required packages:

```bash
pip install cryptography pyotp qrcode
```

* `qrcode` is optional. Without it, SecureVault will print a TOTP provisioning URI instead of an ASCII QR code.

3. Try the main commands (examples use the CLI):

```bash
# create TOTP metadata (for Google Authenticator)
python -m securevault provision-totp --output totp-meta.json --account you@example.com

# encrypt a file (you will be prompted for a password)
python -m securevault encrypt --input secret.txt --out secret.txt.svlt --password-prompt

# decrypt (you will be prompted for password then a 6-digit OTP)
python -m securevault decrypt --input secret.txt.svlt --out secret.txt --password-prompt --otp --otp-meta totp-meta.json

# run unit tests
pytest
```

---

## What SecureVault does 

* **Encryption**: It encrypts your data using AES-256 in Galois/Counter Mode (GCM). This keeps your data confidential and detects tampering.
* **Password hardening**: Your password is stretched using PBKDF2-HMAC-SHA256 with 200,000 iterations and a random 16-byte salt. That makes brute-force attacks much slower.
* **Two-factor decryption**: Besides the password, SecureVault requires a valid 6-digit TOTP (Google Authenticator-style) to decrypt.
* **File & folder support**: You can encrypt single files or entire folders. When encrypting a folder, SecureVault archives it before encrypting, and will extract it automatically when decrypting.
* **Human-readable option**: For learning and debugging, you can create a JSON-formatted output that base64-encodes the internal fields instead of a binary file.

---

## Security model 

* **Key derivation**: PBKDF2-HMAC-SHA256 with 200,000 iterations and a 16-byte random salt. This slows down guessing attacks.
* **Encryption**: AES-256-GCM with a 12-byte random nonce and a 16-byte authentication tag.
* **TOTP**: The per-dataset TOTP secret is stored in a `*.totp.json` file. Decryption checks both the password-derived key and the current TOTP code.

If you want stronger protection, you can increase PBKDF2 iterations—but it will make encrypt/decrypt slower.

---

## Files and header layout (useful to know)

SecureVault stores a small header before the ciphertext. In binary mode the layout is roughly:

```
[offset] field
0..3    b"SVLT"         # magic bytes
4       version byte     # 0x01
5       flags byte       # bit0 => archive payload
6..21   salt (16 bytes)
22      nonce length (1 byte)
23..    nonce bytes (default 12)
...     tag length (1 byte) + auth tag (16 bytes)
...     ciphertext bytes
```

The JSON output contains the same values but base64-encoded in a readable object.

---

## Example CLI workflow

1. Provision TOTP metadata:

```bash
python -m securevault provision-totp --output demo.totp.json --account demo@example.com
```

2. Encrypt a file:

```bash
python -m securevault encrypt --input demo.txt --out demo.svlt --password-prompt
```

3. Decrypt it back:

```bash
python -m securevault decrypt --input demo.svlt --out demo.txt --password-prompt --otp --otp-meta demo.totp.json
```

During decryption you will be prompted for the password (hidden) and then for the current 6-digit TOTP code.

There is an `examples/` folder with `sample.txt.svlt`, a `sample.totp.json`, and a short `decryption-log.txt` to help you follow the steps.

---

## GUI 

Start the small Tkinter GUI:

```bash
python -m securevault.gui
```

GUI features:

* Point-and-click provisioning of a TOTP secret (QR popup if `qrcode` and `Pillow` are installed).
* Browse to select files, folders, or removable drives.
* Encrypt and decrypt with password + TOTP prompts.
* Zips folders automatically before encrypting; extracts them automatically when decrypting.

**Tip:** Keep the encrypted file and its matching `*.totp.json` together on the same removable drive if you plan to move them between machines.

---

## Tests & manual checks

Manual test plan:

1. Create TOTP metadata.
2. Encrypt a small file.
3. Decrypt with the correct password + OTP — should succeed.
4. Try decrypting with a wrong password — should fail.
5. Try with an expired/incorrect OTP — should fail.
6. Encrypt a folder and decrypt into an empty directory to confirm files are restored correctly.

Unit tests (run `pytest`) cover the core functions: key derivation, encrypt/decrypt round-trips, incorrect password handling, and OTP checks.

---

## Current limitations & planned improvements

**Limitations**

* TOTP metadata is stored in a JSON file for convenience. For maximum security, store it separately or in a secure vault.
* Archiving currently uses in-memory ZIP which can use a lot of RAM for very large folders.
* The GUI is intentionally minimal.

**Planned improvements**

* Add streaming archive support (tar/zip) to avoid high memory usage.
* Improve the GUI (progress bars, password-strength meter, optional dark mode).
* Add a header parser that accepts multiple formats and optional folder packaging options.
* Consider key rotation workflows and better safe storage patterns for TOTP secrets.

---

## Packaging & distribution

* Create a standalone GUI binary with PyInstaller, e.g.:

```bash
pyinstaller --onefile -w securevault/gui.py
```

* For CLI usage, distributing the source package or a console-mode PyInstaller build works well.

Dependencies: `cryptography`, `pyotp`, `qrcode` (optional), and `Pillow` (optional, for QR images in the GUI).

---

