# Secure Password Storage

A simple terminal-based secure password manager written in Python. It uses AES-GCM encryption and PBKDF2 for strong key derivation to safely store your passwords in an encrypted JSON file.

## Features

* AES-GCM encryption with 200,000 iterations of PBKDF2
* Secure storage of passwords in encrypted JSON format
* Colorful, user-friendly command-line interface
* Add, edit, view, and delete saved passwords
* Change master password

## Requirements

* Python 3.8+
* Packages:

  * `pycryptodome`
  * `colorama`

Install dependencies with:

```bash
pip install pycryptodome colorama
```

## How It Works

1. **Generate Storage**

   * Creates a new encrypted storage file.
   * User sets a master password.
   * Stores the password (and other entries) encrypted using AES-GCM.

2. **Open Storage**

   * Decrypts an existing storage file using the master password.
   * Allows access to stored credentials.

3. **Password Management**

   * Add: Save a new name-password pair.
   * Edit: Change name or value of existing password.
   * Delete: Remove a saved password.
   * View: Display stored passwords in plaintext (only after unlocking).

4. **Change Master Password**

   * Allows the user to change the main encryption password.

5. **Exit & Save**

   * Saves the encrypted data and exits the program safely.

## File Structure

The encrypted JSON file contains two main sections:

```json
{
  "info": {
    "storage_name": "example.json",
    "version": "1.0",
    "salt": "..."
  },
  "encrypted_data": {
    "nonce": "...",
    "tag": "...",
    "ciphertext": "..."
  }
}
```

## Running the Program

Simply execute the script:

```bash
python3 secure_password_storage.py
```

Follow the on-screen prompts to create or access a storage file.

## Notes

* The master password is also stored in the encrypted data under `main_password` for verification.
* Do not forget your master password — without it, decryption is impossible.

## Disclaimer

This tool is for educational and personal use. Use at your own risk. For enterprise-grade password management, consider using a professional solution like Bitwarden, KeePassXC, or 1Password.

---

Happy encrypting! ✨
