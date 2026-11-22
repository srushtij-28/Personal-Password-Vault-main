import json
import os

from config import DATA_DIR, VAULT_FILE


def load_vault():
    os.makedirs(DATA_DIR, exist_ok=True)

    if not os.path.exists(VAULT_FILE):
        return None

    try:
        with open(VAULT_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        raise RuntimeError("Vault file could not be read.")


def save_vault(data):
    os.makedirs(DATA_DIR, exist_ok=True)

    temporary_file = VAULT_FILE + ".tmp"

    with open(temporary_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    os.replace(temporary_file, VAULT_FILE)
