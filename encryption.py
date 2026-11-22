import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from config import PBKDF2_ITERATIONS


def derive_key(master_password, salt):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32
    )

    return base64.urlsafe_b64encode(key)


def create_vault_key(master_password):
    salt = os.urandom(16)

    key = derive_key(master_password, salt)

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "key": key.decode("utf-8")
    }


def get_fernet(master_password, salt):
    key = derive_key(master_password, salt)
    return Fernet(key)


def encrypt_text(fernet, text):
    encrypted = fernet.encrypt(text.encode("utf-8"))

    return encrypted.decode("utf-8")


def decrypt_text(fernet, encrypted_text):
    try:
        decrypted = fernet.decrypt(
            encrypted_text.encode("utf-8")
        )

        return decrypted.decode("utf-8")

    except InvalidToken:
        raise ValueError("Incorrect master password or corrupted data.")
