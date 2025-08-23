import json
import os
from cryptography.fernet import Fernet
import getpass

# === Step 1: Generate or Load Fernet Key ===
def load_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

fernet = load_key()

# === Step 2: Setup or Load Encrypted Master Password ===
def load_master_password():
    if not os.path.exists("master.key"):
        master_pwd = input("Set a Master Password (only first time): ")
        encrypted_master = fernet.encrypt(master_pwd.encode())
        with open("master.key", "wb") as file:
            file.write(encrypted_master)
        print("✅ Master password set and encrypted.")
        return master_pwd
    else:
        with open("master.key", "rb") as file:
            encrypted_master = file.read()
        return fernet.decrypt(encrypted_master).decode()

# === Step 3: Load Existing Credentials ===
def load_credentials():
    if os.path.exists("vault.json"):
        with open("vault.json", "rb") as file:
            encrypted_data = file.read()
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
    return {}

# === Step 4: Save Credentials Securely ===
def save_credentials(credentials):
    encrypted_data = fernet.encrypt(json.dumps(credentials).encode())
    with open("vault.json", "wb") as file:
        file.write(encrypted_data)

# === Step 5: Change Master Password ===
def change_master_password():
    stored_master = load_master_password()
    current = getpass.getpass("Enter current master password: ")

    if current != stored_master:
        print("❌ Incorrect current master password.")
        return

    new_master = getpass.getpass("Enter new master password: ")
    confirm_master = getpass.getpass("Confirm new master password: ")

    if new_master != confirm_master:
        print("❌ Passwords do not match.")
        return

    encrypted_master = fernet.encrypt(new_master.encode())
    with open("master.key", "wb") as file:
        file.write(encrypted_master)

    print("✅ Master password changed successfully!")

# === Step 6: Main Menu ===
def main():
    credentials = load_credentials()
    stored_master = load_master_password()

    print("== Centralised Secure Login Info Repository ==")
    entered_master = getpass.getpass("Enter Master Password: ")

    if entered_master != stored_master:
        print("❌ Incorrect master password.")
        return

    while True:
        print("\n1. Add New Credential")
        print("2. View All Credentials")
        print("3. Change Master Password")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            site = input("Website/App: ")
            username = input("Username: ")
            password = input("Password: ")
            credentials[site] = {"username": username, "password": password}
            save_credentials(credentials)
            print("✅ Saved Successfully.")

        elif choice == "2":
            print("\nStored Credentials:")
            for site, info in credentials.items():
                print(f"{site} -> Username: {info['username']} | Password: {info['password']}")

        elif choice == "3":
            change_master_password()

        elif choice == "4":
            print("👋 Exiting.")
            break

        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()
