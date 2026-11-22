from datetime import datetime, timezone
import base64
import hashlib
import os
import secrets
import string

from config import PBKDF2_ITERATIONS
from encryption import (
    create_vault_key,
    get_fernet,
    encrypt_text,
    decrypt_text
)

from storage import load_vault, save_vault


def create_password_hash(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )


def setup_vault():
    existing = load_vault()

    if existing is not None:
        print("Vault already exists.")
        return

    print("\nCREATE YOUR MASTER PASSWORD")

    password = input("Enter master password: ")
    confirm = input("Confirm master password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    if len(password) < 12:
        print("Master password must contain at least 12 characters.")
        return

    salt = os.urandom(16)
    password_hash = create_password_hash(password, salt)

    vault_key = create_vault_key(password)

    data = {
        "version": 1,
        "auth_salt": base64.b64encode(salt).decode("utf-8"),
        "password_hash": base64.b64encode(
            password_hash
        ).decode("utf-8"),
        "encryption_salt": vault_key["salt"],
        "credentials": []
    }

    save_vault(data)

    print("Password vault created successfully!")


def authenticate():
    data = load_vault()

    if data is None:
        print("Create a vault first.")
        return None, None

    password = input("Enter master password: ")

    salt = base64.b64decode(data["auth_salt"])

    stored_hash = base64.b64decode(data["password_hash"])

    entered_hash = create_password_hash(password, salt)

    if not secrets.compare_digest(stored_hash, entered_hash):
        print("Incorrect master password.")
        return None, None

    encryption_salt = base64.b64decode(
        data["encryption_salt"]
    )

    fernet = get_fernet(password, encryption_salt)

    print("Authentication successful!")

    return data, fernet


def add_credential(data, fernet):
    website = input("Enter website name: ").strip()
    username = input("Enter username/email: ").strip()
    password = input("Enter account password: ")

    if not website or not username or not password:
        print("All fields are required.")
        return

    credential = {
        "id": max(
            (item["id"] for item in data["credentials"]),
            default=0
        ) + 1,
        "website": website,
        "username": encrypt_text(fernet, username),
        "password": encrypt_text(fernet, password),
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    data["credentials"].append(credential)
    save_vault(data)

    print("Credential saved successfully!")


def view_credentials(data, fernet):
    if not data["credentials"]:
        print("No credentials saved.")
        return

    print("\nSAVED CREDENTIALS")

    for item in data["credentials"]:
        username = decrypt_text(
            fernet,
            item["username"]
        )

        password = decrypt_text(
            fernet,
            item["password"]
        )

        print("\nID:", item["id"])
        print("Website:", item["website"])
        print("Username:", username)
        print("Password:", password)
        print("Created:", item["created_at"])


def search_credential(data, fernet):
    keyword = input("Enter website to search: ").strip().lower()

    if not keyword:
        print("Search value cannot be empty.")
        return

    results = [
        item for item in data["credentials"]
        if keyword in item["website"].lower()
    ]

    if not results:
        print("No matching credentials found.")
        return

    for item in results:
        print("\nID:", item["id"])
        print("Website:", item["website"])
        print(
            "Username:",
            decrypt_text(fernet, item["username"])
        )
        print(
            "Password:",
            decrypt_text(fernet, item["password"])
        )


def update_credential(data, fernet):
    try:
        credential_id = int(
            input("Enter credential ID to update: ")
        )
    except ValueError:
        print("Invalid ID.")
        return

    item = next(
        (
            record for record in data["credentials"]
            if record["id"] == credential_id
        ),
        None
    )

    if not item:
        print("Credential not found.")
        return

    print("Leave a field empty to keep its existing value.")

    website = input("New website: ").strip()
    username = input("New username: ").strip()
    password = input("New account password: ")

    if website:
        item["website"] = website

    if username:
        item["username"] = encrypt_text(fernet, username)

    if password:
        item["password"] = encrypt_text(fernet, password)

    save_vault(data)

    print("Credential updated successfully!")


def delete_credential(data):
    try:
        credential_id = int(
            input("Enter credential ID to delete: ")
        )
    except ValueError:
        print("Invalid ID.")
        return

    updated = [
        item for item in data["credentials"]
        if item["id"] != credential_id
    ]

    if len(updated) == len(data["credentials"]):
        print("Credential not found.")
        return

    confirm = input("Confirm deletion? (y/n): ").lower()

    if confirm != "y":
        print("Deletion cancelled.")
        return

    data["credentials"] = updated
    save_vault(data)

    print("Credential deleted successfully!")


def generate_password():
    try:
        length = int(input("Enter password length (12-64): "))
    except ValueError:
        print("Enter a valid number.")
        return

    if not 12 <= length <= 64:
        print("Password length must be between 12 and 64.")
        return

    characters = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    password = "".join(
        secrets.choice(characters)
        for _ in range(length)
    )

    print("\nGenerated password:", password)


def change_master_password(data, old_password):
    print("\nCHANGE MASTER PASSWORD")

    new_password = input("Enter new master password: ")
    confirm = input("Confirm new master password: ")

    if new_password != confirm:
        print("Passwords do not match.")
        return data, old_password

    if len(new_password) < 12:
        print("New password must contain at least 12 characters.")
        return data, old_password

    old_salt = base64.b64decode(data["encryption_salt"])
    old_fernet = get_fernet(old_password, old_salt)

    new_vault_key = create_vault_key(new_password)

    new_salt = base64.b64decode(new_vault_key["salt"])
    new_fernet = get_fernet(new_password, new_salt)

    for item in data["credentials"]:
        username = decrypt_text(
            old_fernet,
            item["username"]
        )

        password = decrypt_text(
            old_fernet,
            item["password"]
        )

        item["username"] = encrypt_text(
            new_fernet,
            username
        )

        item["password"] = encrypt_text(
            new_fernet,
            password
        )

    auth_salt = os.urandom(16)

    data["auth_salt"] = base64.b64encode(
        auth_salt
    ).decode("utf-8")

    data["password_hash"] = base64.b64encode(
        create_password_hash(new_password, auth_salt)
    ).decode("utf-8")

    data["encryption_salt"] = new_vault_key["salt"]

    save_vault(data)

    print("Master password changed successfully!")

    return data, new_password
