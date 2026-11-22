# Personal Password Vault

## About

A command-line password manager that stores account
credentials in encrypted form using Python.

## Features

- Create a master password
- Secure credential storage
- Encrypt and decrypt passwords
- Search saved credentials
- Update and delete credentials
- Generate strong passwords
- Change master password

## Technologies

- Python
- JSON
- Cryptography
- PBKDF2
- Fernet Encryption

## Installation

Install dependencies:

pip install -r requirements.txt

## Run

python main.py

## Security

- Passwords are encrypted before storage.
- A master password is required to unlock the vault.
- The vault data file is excluded from Git.

## Important

Keep a secure backup of your vault file.
If you lose your master password, the saved credentials
cannot be recovered through this application.

This is an educational project, not a professionally
audited password manager.

## Author

Python Projects Challenge
