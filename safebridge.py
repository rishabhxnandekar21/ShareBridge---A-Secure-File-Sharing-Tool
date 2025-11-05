
# Secure File Transfer Tool

## Importing necessary libraries for GUI creation (Tkinter), file selection, 
# socket-based communication, AES encryption/decryption, 
# key derivation (PBKDF2), data padding, and binary data handling.

import tkinter as tk
from tkinter import filedialog
import socket
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import struct

#Changing password using AES-256 encryption key using PBKDF2 with SHA-256.
#Using a fixed salt for simplicity; in production, use a random salt and store it securely.
#Deriving a 32-byte key for AES-256.
def derive_key(password):
    salt = b'salt_'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

## Function to pad data before encryption (AES requires block-sized data)
## and unpad after decryption.
## Using PKCS7 padding scheme.

def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Function to securely send an encrypted file over a socket connection
##Encrypts a file using AES-256 with a password-derived key and sends it securely over a socket connection.
def send_file(sock, filename, password):
    key = derive_key(password)
    with open(filename, 'rb') as file:
        file_data = file.read()
        file_data = pad_data(file_data)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        filename_bytes = os.path.basename(filename).encode()
        sock.sendall(struct.pack('I', len(filename_bytes)) + filename_bytes)
        sock.sendall(iv + encrypted_data)

##Decrypts AES-256 encrypted data using the provided key and IV, 
# removes padding, and returns the original plaintext.
def decrypt_data(key, data):
    backend = default_backend()
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data

## Listens for an incoming connection, receives an AES-encrypted file along with its metadata,
#  decrypts it using the provided key, and saves the original file to disk.
def receive_file(key, port):
    host = '0.0.0.0'

    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver_socket.bind((host, port))
    receiver_socket.listen(1)
    print("Receiver is listening for incoming connections...")

    client_socket, client_address = receiver_socket.accept()
    print("Connection established with:", client_address)

    filename_len = struct.unpack('I', client_socket.recv(4))[0]
    filename = client_socket.recv(filename_len).decode()

    encrypted_data = b""
    while True:
        chunk = client_socket.recv(4096)
        if not chunk:
            break
        encrypted_data += chunk

    try:
        decrypted_data = decrypt_data(key, encrypted_data)
        with open(filename, 'wb') as file:
            file.write(decrypted_data)
            print(f"File received successfully: {filename}")
    except ValueError as e:
        print(f"Decryption failed: {e}")

    client_socket.close()
    receiver_socket.close()

##Retrieves user inputs from the GUI, connects to the receiver via socket,
#  encrypts and sends the selected file using the provided password,
#  and updates the GUI status message.
def send_file_gui():
    password = password_entry.get()
    filename = file_path_label.cget("text")
    host = host_entry.get()
    port = int(port_entry.get())
    if password and filename and host and port:
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_socket.connect((host, port))
        send_file(sender_socket, filename, password)
        sender_socket.close()
        status_label.config(text="File sent successfully!")
    else:
        status_label.config(text="Please fill in all fields!")

#Gets the decryption key and port from the GUI, starts the file receiving and decryption process, 
# and updates the status message upon completion.
def receive_file_gui():
    key = password_entry.get()
    port = int(port_entry.get())
    if key and port:
        receive_file(derive_key(key), port)
        status_label.config(text="File received successfully!")
    else:
        status_label.config(text="Please enter a valid key and port!")

# Function to open file dialog and choose a file
def choose_file():
    filename = filedialog.askopenfilename()
    file_path_label.config(text=filename)


#Tkinter GUI Setup

root = tk.Tk()
root.title("SafeBridge")
root.geometry('400x500')

root.configure(bg='black')

def configure_widget(widget, font=('Helvetica', 10, 'bold'), bg='black', fg='white'):
    widget.configure(bg=bg, fg=fg, font=font)
    if isinstance(widget, tk.Entry):
        widget.configure(insertbackground='white')

mode_label = tk.Label(root, text="SafeBridge", font=('Helvetica', 16, 'bold'))
configure_widget(mode_label)
mode_label.pack(pady=10)

website_label = tk.Label(root, text="Secure File Transfer Tool", font=('Helvetica', 10, 'italic'))
configure_widget(website_label, font=('Helvetica', 10, 'italic'))
website_label.pack(pady=5)

# -- ensure socket is imported at top of file: import socket --

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip

# call it here (important: call BEFORE using local_ip)
local_ip = get_local_ip()

# now create the label using the variable that exists
ip_label = tk.Label(root, text=f"Your IP: {local_ip} (click to copy)",
                    font=('Helvetica', 9, 'italic'), fg='cyan', cursor='hand2')
configure_widget(ip_label, font=('Helvetica', 9, 'italic'))
ip_label.pack(pady=3)


mode_var = tk.StringVar(value="send")
send_radio = tk.Radiobutton(root, text="Send", variable=mode_var, value="send", selectcolor='black')
configure_widget(send_radio)
send_radio.pack(pady=5)
receive_radio = tk.Radiobutton(root, text="Receive", variable=mode_var, value="receive", selectcolor='black')
configure_widget(receive_radio)
receive_radio.pack(pady=5)

host_label = tk.Label(root, text="Enter Host:")
configure_widget(host_label)
host_label.pack(pady=5)
host_entry = tk.Entry(root)
configure_widget(host_entry)
host_entry.pack(pady=5)

port_label = tk.Label(root, text="Enter Port:")
configure_widget(port_label)
port_label.pack(pady=5)
port_entry = tk.Entry(root)
configure_widget(port_entry)
port_entry.pack(pady=5)

password_label = tk.Label(root, text="Enter Password/Key:")
configure_widget(password_label)
password_label.pack(pady=5)
password_entry = tk.Entry(root, show="*")
configure_widget(password_entry)
password_entry.pack(pady=5)

file_path_label = tk.Label(root, text="No file chosen")
configure_widget(file_path_label)
file_path_label.pack(pady=5)

choose_file_button = tk.Button(root, text="Choose File", command=choose_file)
configure_widget(choose_file_button)
choose_file_button.pack(pady=5)

execute_button = tk.Button(root, text="RUN", command=lambda: send_file_gui() if mode_var.get() == "send" else receive_file_gui())
configure_widget(execute_button)
execute_button.pack(pady=5)

status_label = tk.Label(root, text="")
configure_widget(status_label)
status_label.pack(pady=10)

root.mainloop()

