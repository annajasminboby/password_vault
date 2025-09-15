import json
import os
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, simpledialog

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

# === Step 2: Master Password Setup / Verify ===
def setup_master():
    if not os.path.exists("master.hash"):
        pwd = simpledialog.askstring("Set Master Password", "Create a Master Password:", show="*")
        if not pwd:
            messagebox.showerror("Error", "Master password cannot be empty!")
            root.destroy()
            return False
        hash_pwd = hashlib.sha256(pwd.encode()).hexdigest()
        with open("master.hash", "w") as f:
            f.write(hash_pwd)
        messagebox.showinfo("Success", "✅ Master password set.")
        return True
    else:
        pwd = simpledialog.askstring("Master Password", "Enter Master Password:", show="*")
        with open("master.hash", "r") as f:
            stored_hash = f.read()
        if hashlib.sha256(pwd.encode()).hexdigest() != stored_hash:
            messagebox.showerror("Error", "❌ Incorrect master password.")
            root.destroy()
            return False
        return True

# === Step 3: Load Existing Credentials ===
def load_credentials():
    if os.path.exists("vault.json"):
        with open("vault.json", "rb") as file:
            encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data).decode()
                return json.loads(decrypted_data)
            except:
                messagebox.showerror("Error", "Vault corrupted or wrong key.")
                root.destroy()
    return {}

# === Step 4: Save Credentials Securely ===
def save_credentials(credentials):
    encrypted_data = fernet.encrypt(json.dumps(credentials).encode())
    with open("vault.json", "wb") as file:
        file.write(encrypted_data)

# === Step 5: GUI Functions ===
def add_credential():
    site = simpledialog.askstring("New Credential", "Website/App:")
    if not site: return
    username = simpledialog.askstring("New Credential", "Username:")
    password = simpledialog.askstring("New Credential", "Password:", show="*")
    if site and username and password:
        credentials[site] = {"username": username, "password": password}
        save_credentials(credentials)
        messagebox.showinfo("Saved", f"✅ Credentials saved for {site}.")

def view_credentials():
    if not credentials:
        messagebox.showinfo("Vault Empty", "No credentials stored yet.")
        return
    result = ""
    for site, info in credentials.items():
        result += f"{site} -> Username: {info['username']} | Password: {info['password']}\n"
    messagebox.showinfo("Stored Credentials", result)

def exit_app():
    root.destroy()

# === Step 6: Main GUI Window ===
root = tk.Tk()
root.title("🔐 Secure Password Vault")
root.geometry("400x300")
root.resizable(False, False)

# Check master password before loading vault
if setup_master():
    credentials = load_credentials()

    lbl = tk.Label(root, text="Centralised Secure Login Repository", font=("Arial", 12, "bold"))
    lbl.pack(pady=20)

    btn1 = tk.Button(root, text="➕ Add Credential", width=20, command=add_credential)
    btn1.pack(pady=10)

    btn2 = tk.Button(root, text="📂 View Credentials", width=20, command=view_credentials)
    btn2.pack(pady=10)

    btn3 = tk.Button(root, text="🚪 Exit", width=20, command=exit_app)
    btn3.pack(pady=10)

    root.mainloop()
