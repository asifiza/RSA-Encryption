import zlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import json
from ttkthemes import ThemedTk

def generate_new_key_pair():
    new_key = RSA.generate(4096, e=65537)
    private_key = new_key.export_key("PEM")
    public_key = new_key.publickey().export_key("PEM")

    with open('private.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)

    with open('public.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)

def encrypt_blob(blob, public_key):
    rsa_key = RSA.import_key(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)
    blob = zlib.compress(blob)
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted = bytearray()

    while not end_loop:
        chunk = blob[offset:offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))
        encrypted += rsa_key.encrypt(chunk)
        offset += chunk_size

    return base64.b64encode(encrypted)

def decrypt_blob(encrypted_blob, private_key):
    rsakey = RSA.import_key(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted_blob = base64.b64decode(encrypted_blob)
    chunk_size = 512
    offset = 0
    decrypted = bytearray()

    while offset < len(encrypted_blob):
        chunk = encrypted_blob[offset: offset + chunk_size]
        decrypted += rsakey.decrypt(chunk)
        offset += chunk_size

    return zlib.decompress(decrypted)

def login():
    username = username_entry.get()
    password = password_entry.get()

    credentials_file_path = 'user_credentials.json'
    if Path(credentials_file_path).is_file():
        with open(credentials_file_path, 'r') as credentials_file:
            stored_credentials = json.load(credentials_file)

        if username in stored_credentials and stored_credentials[username] == password:
            login_window.destroy()
            main_window.deiconify()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    else:
        messagebox.showerror("Login Failed", "User credentials not found")

def register():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()

    credentials_file_path = 'user_credentials.json'
    if Path(credentials_file_path).is_file():
        with open(credentials_file_path, 'r') as credentials_file:
            stored_credentials = json.load(credentials_file)
    else:
        stored_credentials = {}

    if new_username in stored_credentials:
        messagebox.showerror("Registration Failed", "Username already exists")
    else:
        stored_credentials[new_username] = new_password

        with open(credentials_file_path, 'w') as credentials_file:
            json.dump(stored_credentials, credentials_file)

        register_window.destroy()
        messagebox.showinfo("Registration Successful", "You can now log in with your new credentials")

def show_login_window():
    global login_window
    login_window = tk.Toplevel(main_window)
    login_window.title("Login")
    login_window.geometry("400x200")

    ttk.Label(login_window, text="Username:").pack(pady=10)
    global username_entry
    username_entry = ttk.Entry(login_window)
    username_entry.pack(pady=5)

    ttk.Label(login_window, text="Password:").pack(pady=10)
    global password_entry
    password_entry = ttk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    login_button = ttk.Button(login_window, text="Login", command=login)
    login_button.pack(pady=10)

    register_button = ttk.Button(login_window, text="Register", command=show_register_window)
    register_button.pack(pady=5)

def show_register_window():
    global register_window
    register_window = tk.Toplevel(main_window)
    register_window.title("Register")
    register_window.geometry("400x200")

    ttk.Label(register_window, text="New Username:").pack(pady=10)
    global new_username_entry
    new_username_entry = ttk.Entry(register_window)
    new_username_entry.pack(pady=5)

    ttk.Label(register_window, text="New Password:").pack(pady=10)
    global new_password_entry
    new_password_entry = ttk.Entry(register_window, show="*")
    new_password_entry.pack(pady=5)

    register_button = ttk.Button(register_window, text="Register", command=register)
    register_button.pack(pady=10)

    login_window.wait_window(register_window)  # Wait for register window to be closed before continuing

def update_file_label(file_path):
    file_label.config(text=f"Selected File: {file_path}")

def encrypt_file(file_path):
    public_key = Path('public.pem').read_bytes()
    unencrypted_data = Path(file_path).read_bytes()
    encrypted_data = encrypt_blob(unencrypted_data, public_key)

    encrypted_file_path = file_path + ".enc"
    Path(encrypted_file_path).write_bytes(encrypted_data)

    result_label.config(text=f"File encrypted and saved to: {encrypted_file_path}")

def encrypt_folder(folder_path):
    for file_path in Path(folder_path).rglob("*.*"):
        if file_path.is_file():
            encrypt_file(file_path)

def decrypt_file(encrypted_file_path):
    private_key = Path('private.pem').read_bytes()
    encrypted_data = Path(encrypted_file_path).read_bytes()
    try:
        decrypted_data = decrypt_blob(encrypted_data, private_key)

        decrypted_file_path = encrypted_file_path[:-4]
        Path(decrypted_file_path).write_bytes(decrypted_data)

        os.remove(encrypted_file_path)
        result_label.config(text=f"Decrypted data saved to: {decrypted_file_path}")

    except Exception as e:
        result_label.config(text=f"Error: {str(e)}")

def file_dialog():
    path = filedialog.askopenfilename(title="Select file to encrypt/decrypt", filetypes=[("All Files", "*.*")])
    if path:
        update_file_label(path)

def encrypt_dialog():
    path = file_label.cget("text").split(": ")[1]
    if path:
        if os.path.isdir(path):
            encrypt_folder(path)
        else:
            encrypt_file(path)

def decrypt_dialog():
    path = file_label.cget("text").split(": ")[1]
    if path:
        decrypt_file(path)

main_window = ThemedTk(theme="arc")
main_window.title("RSA File/Folder Encryption/Decryption")
main_window.geometry("800x500")

style = ttk.Style()
style.configure("TFrame", background="#4B8BBE")

# Create a frame to hold the widgets
frame = ttk.Frame(main_window, style="TFrame")
frame.pack(fill=tk.BOTH, expand=True)

# Set the window background color
main_window.configure(bg="#4B8BBE")
frame.configure(style="TFrame")

# Create the buttons with a cool interface, side by side
encrypt_button = ttk.Button(frame, text="Encrypt", command=encrypt_dialog)
encrypt_button.grid(row=0, column=0, padx=10, pady=10)

decrypt_button = ttk.Button(frame, text="Decrypt", command=decrypt_dialog)
decrypt_button.grid(row=0, column=1, padx=10, pady=10)

# Create the label to display the result
result_label = ttk.Label(frame, text="", style='TLabel')
result_label.grid(row=1, column=0, columnspan=2, pady=10)

# Create the label to display the selected file
file_label = ttk.Label(frame, text="Selected File: None", style='TLabel')
file_label.grid(row=2, column=0, columnspan=2, pady=10)

# Create the button to open the file dialog
file_dialog_button = ttk.Button(frame, text="Browse File", command=file_dialog)
file_dialog_button.grid(row=3, column=0, columnspan=2, pady=10)

# Show login window
main_window.withdraw()
show_login_window()

# Footer
footer_label = ttk.Label(main_window, text="This Application is created by Mohammad Asif", foreground="white", background="#4B8BBE")
footer_label.pack(side=tk.BOTTOM, fill=tk.X)

main_window.mainloop()
