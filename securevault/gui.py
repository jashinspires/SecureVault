"""Tkinter graphical interface for SecureVault."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from pathlib import Path
from typing import Optional

from .crypto import crypto_utils
from .io import file_utils
from .otp import otp_utils


class SecureVaultApp(tk.Tk):
    """Minimal GUI for encrypting/decrypting with SecureVault."""

    def __init__(self) -> None:
        super().__init__()
        self.title("SecureVault")
        self.resizable(False, False)

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.metadata_var = tk.StringVar()
        self.account_var = tk.StringVar()
        self.issuer_var = tk.StringVar(value="SecureVault")
        self.format_var = tk.StringVar(value="binary")

        self._build_layout()

    def _build_layout(self) -> None:
        padding = {"padx": 8, "pady": 4}

        tk.Label(self, text="Input file or folder:").grid(row=0, column=0, sticky="w", **padding)
        tk.Entry(self, textvariable=self.input_var, width=45).grid(row=0, column=1, columnspan=2, sticky="we", **padding)
        tk.Button(self, text="Browse File", command=self._browse_input_file).grid(row=0, column=3, **padding)
        tk.Button(self, text="Browse Folder", command=self._browse_input_folder).grid(row=0, column=4, **padding)

        tk.Label(self, text="Output path:").grid(row=1, column=0, sticky="w", **padding)
        tk.Entry(self, textvariable=self.output_var, width=45).grid(row=1, column=1, columnspan=2, sticky="we", **padding)
        tk.Button(self, text="Save As", command=self._choose_output_file).grid(row=1, column=3, **padding)
        tk.Button(self, text="Choose Dir", command=self._choose_output_dir).grid(row=1, column=4, **padding)

        tk.Label(self, text="TOTP metadata:").grid(row=2, column=0, sticky="w", **padding)
        tk.Entry(self, textvariable=self.metadata_var, width=45).grid(row=2, column=1, columnspan=2, sticky="we", **padding)
        tk.Button(self, text="Browse", command=self._browse_metadata).grid(row=2, column=3, **padding)

        tk.Label(self, text="Encrypt format:").grid(row=3, column=0, sticky="w", **padding)
        tk.OptionMenu(self, self.format_var, "binary", "json").grid(row=3, column=1, sticky="w", **padding)

        tk.Label(self, text="Provision account:").grid(row=4, column=0, sticky="w", **padding)
        tk.Entry(self, textvariable=self.account_var, width=30).grid(row=4, column=1, **padding)
        tk.Label(self, text="Issuer:").grid(row=4, column=2, sticky="e", **padding)
        tk.Entry(self, textvariable=self.issuer_var, width=15).grid(row=4, column=3, **padding)
        tk.Button(self, text="Provision TOTP", command=self._provision_totp).grid(row=4, column=4, **padding)

        tk.Button(self, text="Encrypt", command=self._encrypt).grid(row=5, column=1, sticky="we", **padding)
        tk.Button(self, text="Decrypt", command=self._decrypt).grid(row=5, column=2, sticky="we", **padding)
        tk.Button(self, text="Quit", command=self.destroy).grid(row=5, column=4, sticky="e", **padding)

    def _browse_input_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file")
        if path:
            self.input_var.set(path)

    def _browse_input_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder")
        if path:
            self.input_var.set(path)

    def _choose_output_file(self) -> None:
        path = filedialog.asksaveasfilename(title="Save encrypted file", defaultextension=".svlt")
        if path:
            self.output_var.set(path)

    def _choose_output_dir(self) -> None:
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self.output_var.set(path)

    def _browse_metadata(self) -> None:
        path = filedialog.askopenfilename(title="Select TOTP metadata", filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if path:
            self.metadata_var.set(path)

    def _ask_password(self, prompt: str) -> Optional[str]:
        password = simpledialog.askstring("Password", prompt, show="*")
        if password is None or not password:
            messagebox.showerror("SecureVault", "Password is required.")
            return None
        return password

    def _ask_otp(self) -> Optional[str]:
        code = simpledialog.askstring("TOTP", "Enter 6-digit TOTP:")
        if code is None:
            return None
        code = code.strip()
        if len(code) != 6 or not code.isdigit():
            messagebox.showerror("SecureVault", "TOTP must be 6 digits.")
            return None
        return code

    def _prepare_encrypt(self) -> Optional[tuple[bytes, bool, str, str]]:
        input_path = self.input_var.get().strip()
        output_format = self.format_var.get() or "binary"
        if not input_path:
            messagebox.showerror("SecureVault", "Select an input file or folder to encrypt.")
            return None

        try:
            plaintext, is_archive = file_utils.read_source(input_path)
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Failed to read input: {exc}")
            return None

        output_path = self.output_var.get().strip()
        if not output_path:
            default_name = Path(input_path).name + (".json" if output_format == "json" else ".svlt")
            output_path = str(Path.home() / default_name)
            self.output_var.set(output_path)

        return plaintext, is_archive, output_path, output_format

    def _write_encrypted_file(self, output_path: str, data: bytes, output_format: str) -> None:
        mode = "wb" if output_format == "binary" else "w"
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, mode) as fh:
            fh.write(data if mode == "wb" else data.decode("utf-8"))

    def _encrypt(self) -> None:
        prepared = self._prepare_encrypt()
        if not prepared:
            return
        plaintext, is_archive, output_path, output_format = prepared

        password = self._ask_password("Enter password for encryption")
        if not password:
            return

        try:
            encrypted_blob, _ = crypto_utils.encrypt_bytes(
                password,
                plaintext,
                flags=crypto_utils.HEADER_FLAG_ARCHIVE if is_archive else 0,
                output_format=output_format,
            )
            self._write_encrypted_file(output_path, encrypted_blob, output_format)
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Encryption failed: {exc}")
            return

        message = "Folder encrypted. Decrypt into a directory destination." if is_archive else "File encrypted successfully."
        messagebox.showinfo("SecureVault", message)

    def _prepare_decrypt(self) -> Optional[tuple[bytes, str, otp_utils.TOTPMetadata]]:
        input_path = self.input_var.get().strip()
        if not input_path:
            messagebox.showerror("SecureVault", "Select an encrypted file to decrypt.")
            return None

        metadata_path = self.metadata_var.get().strip()
        if not metadata_path:
            metadata_path = f"{input_path}.totp.json"
            self.metadata_var.set(metadata_path)
        if not Path(metadata_path).exists():
            messagebox.showerror("SecureVault", f"TOTP metadata not found at {metadata_path}.")
            return None

        try:
            payload = Path(input_path).read_bytes()
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Failed to read encrypted file: {exc}")
            return None

        try:
            metadata = otp_utils.load_totp_metadata(metadata_path)
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Failed to load TOTP metadata: {exc}")
            return None

        return payload, input_path, metadata

    def _resolve_output_path(self, current: str, input_path: str, is_archive: bool) -> str:
        if current:
            return current
        base = Path(input_path)
        if is_archive:
            candidate = base.with_suffix("")
            return str(candidate.with_name(candidate.name + "_decrypted"))
        return str(base.with_suffix(""))

    def _decrypt(self) -> None:
        prepared = self._prepare_decrypt()
        if not prepared:
            return
        payload, input_path, metadata = prepared

        password = self._ask_password("Enter password for decryption")
        if not password:
            return

        code = self._ask_otp()
        if not code:
            return

        if not otp_utils.verify_totp(metadata, code):
            messagebox.showerror("SecureVault", "Invalid or expired TOTP code.")
            return

        try:
            plaintext, payload_meta = crypto_utils.decrypt_bytes(password, payload)
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Decryption failed: {exc}")
            return

        is_archive = bool(payload_meta.flags & crypto_utils.HEADER_FLAG_ARCHIVE)
        output_path = self._resolve_output_path(self.output_var.get().strip(), input_path, is_archive)
        self.output_var.set(output_path)

        try:
            file_utils.materialize_output(output_path, plaintext, is_archive=is_archive)
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Failed to write output: {exc}")
            return

        message = f"Archive decrypted to {output_path}." if is_archive else "File decrypted successfully."
        messagebox.showinfo("SecureVault", message)

    def _provision_totp(self) -> None:
        output_path = self.metadata_var.get().strip()
        account = self.account_var.get().strip()
        issuer = self.issuer_var.get().strip() or "SecureVault"

        if not output_path:
            path = filedialog.asksaveasfilename(title="Save metadata", defaultextension=".json")
            if not path:
                return
            output_path = path
            self.metadata_var.set(output_path)
        if not account:
            messagebox.showerror("SecureVault", "Provide an account label (e.g., email).")
            return

        try:
            metadata = otp_utils.create_totp_metadata(
                output_path=output_path,
                account_name=account,
                issuer=issuer,
                show_qr=False,
            )
        except Exception as exc:
            messagebox.showerror("SecureVault", f"Failed to provision TOTP: {exc}")
            return

        self._show_qr(metadata.provisioning_uri)
        messagebox.showinfo("SecureVault", f"TOTP metadata saved to {output_path}.")

    def _show_qr(self, provisioning_uri: str) -> None:
        try:
            import qrcode
            from PIL import ImageTk
        except Exception:
            messagebox.showinfo(
                "Provisioning URI",
                f"Scan this URI with Google Authenticator:\n{provisioning_uri}",
            )
            return

        qr_img = qrcode.make(provisioning_uri)
        window = tk.Toplevel(self)
        window.title("Scan QR")
        photo = ImageTk.PhotoImage(qr_img)
        label = tk.Label(window, image=photo)
        label.image = photo
        label.pack(padx=12, pady=12)
        tk.Label(window, text="Scan with Google Authenticator").pack(padx=12, pady=(0, 12))


def launch() -> None:
    app = SecureVaultApp()
    app.mainloop()


if __name__ == "__main__":
    launch()
