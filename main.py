from vault_manager import (
    setup_vault,
    authenticate,
    add_credential,
    view_credentials,
    search_credential,
    update_credential,
    delete_credential,
    generate_password,
    change_master_password
)


def main():
    while True:
        print("\n================================")
        print("       PERSONAL PASSWORD VAULT")
        print("================================")

        print("1. Create Vault")
        print("2. Login to Vault")
        print("3. Generate Strong Password")
        print("4. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            setup_vault()

        elif choice == "2":
            data, fernet = authenticate()

            if data is None:
                continue

            master_password = input(
                "Re-enter master password to unlock vault: "
            )

            # Authenticate again before entering the vault.
            # This avoids retaining the password from the
            # initial authentication function.
            import base64
            import secrets
            from vault_manager import create_password_hash

            salt = base64.b64decode(data["auth_salt"])
            stored = base64.b64decode(data["password_hash"])

            entered = create_password_hash(master_password, salt)

            if not secrets.compare_digest(stored, entered):
                print("Incorrect master password.")
                continue

            from encryption import get_fernet

            fernet = get_fernet(
                master_password,
                base64.b64decode(data["encryption_salt"])
            )

            while True:
                print("\n---------- VAULT MENU ----------")
                print("1. Add Credential")
                print("2. View All Credentials")
                print("3. Search Credential")
                print("4. Update Credential")
                print("5. Delete Credential")
                print("6. Change Master Password")
                print("7. Logout")

                option = input("\nEnter choice: ").strip()

                if option == "1":
                    add_credential(data, fernet)

                elif option == "2":
                    view_credentials(data, fernet)

                elif option == "3":
                    search_credential(data, fernet)

                elif option == "4":
                    update_credential(data, fernet)

                elif option == "5":
                    delete_credential(data)

                elif option == "6":
                    data, master_password = change_master_password(
                        data,
                        master_password
                    )

                    from encryption import get_fernet

                    fernet = get_fernet(
                        master_password,
                        base64.b64decode(data["encryption_salt"])
                    )

                elif option == "7":
                    print("Logged out successfully.")
                    break

                else:
                    print("Invalid choice.")

        elif choice == "3":
            generate_password()

        elif choice == "4":
            print("Thank you for using Password Vault!")
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
