import json
import os
from cryptography.fernet import Fernet
import getpass

# === Step 1: Generate or Load AES Key ===
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

# === Step 2: Load Existing Credentials ===
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

# === Step 4: Main Menu ===
def main():
    credentials = load_credentials()


    print("== Centralised Secure Login Info Repository ==")
    master_pwd = input("Enter Master Password: ")

    # In real-world, you would hash and verify the master password
    if master_pwd != "admin123":
        print("❌ Incorrect master password.")
        return

    while True:
        print("\n1. Add New Credential")
        print("2. View All Credentials")
        print("3. Exit")
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
            print("👋 Exiting.")
            break

        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()
