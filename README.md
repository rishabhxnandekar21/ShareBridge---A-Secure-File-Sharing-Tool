🛡️ SafeBridge
Secure, Encrypted File Transfer Utility
SafeBridge is a lightweight, cross-platform file transfer tool built by 0x4m4. It ensures your files are transferred safely and privately over a network using end-to-end AES-256 encryption.
________________________________________
✨ Features
•	AES-256 Encryption: Protects your files with military-grade encryption.
•	PBKDF2 Key Derivation: Uses salted and iterated hashing to secure passwords.
•	Cross-Platform Support: Works seamlessly on Windows, Linux, macOS, and even Android (via terminal).
•	Simple GUI: Minimal interface built with Tkinter for easy use.
•	File Integrity: Maintains file name and data consistency during transfer.
________________________________________
💡 Why SafeBridge?
Unlike typical file-sharing platforms that store or expose your data on external servers, SafeBridge encrypts every file locally before sending it.
Only the intended recipient with the correct password can decrypt it.
It’s private, fast, and completely offline-capable — no third-party dependency, no data leaks.
________________________________________
⚙️ Requirements
Make sure the following are installed:
•	Python 3.x
•	Required libraries:
•	pip install cryptography
•	pip install tkinter
(No need to install socket; it’s part of Python’s standard library.)
________________________________________


🧭 Usage
Sending a File
1.	Launch SafeBridge.
2.	Select Send mode.
3.	Enter the recipient’s IP address and port.
4.	Choose the file to send.
5.	Enter a secure password.
6.	Click Execute to start the transfer.
Receiving a File
1.	Launch SafeBridge.
2.	Select Receive mode.
3.	Enter the port to listen on.
4.	Enter the same password as the sender.
5.	Click Execute to start listening and decrypt incoming files.
________________________________________
🧱 Security Architecture
SafeBridge ensures strong protection with multiple cryptographic layers:
•	AES-256 symmetric encryption for data security.
•	PBKDF2 with HMAC-SHA256 for password-based key generation.
•	Unique IV (Initialization Vector) per session for randomness and replay protection.
________________________________________
⚠️ Disclaimer
While SafeBridge uses strong encryption, overall security depends on your password strength and secure sharing of that password with the recipient.
Always use a long, unique password to maximize protection.
________________________________________
SafeBridge — Build a secure bridge for your files 🧠💾
