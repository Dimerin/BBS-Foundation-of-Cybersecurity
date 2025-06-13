# Bulletin Board System (BBS)

A secure, client-server Bulletin Board System implemented in C++ as part of the "Foundation of Cybersecurity" course at the University of Pisa.

## 📘 Overview

This project implements a secure, centralized Bulletin Board System (BBS) that allows users to register, log in, and perform operations such as adding, reading, and listing posts. Special focus is placed on secure communication, authentication, and perfect forward secrecy.

## 🛠 Tools & Technologies

- **Language:** C++
- **Crypto Library:** OpenSSL (lcrypto)
- **Environment:** Ubuntu 20.04 LTS via WSL
- **Communication Protocol:** TCP sockets (port `4242`)
- **Encryption:** RSA, AES-128-GCM, Ephemeral Diffie-Hellman (PFS)

## 🧑‍💻 Features

### ✅ Client Commands

- `register [Email] [Username] [Password]`  
  Register a new user with email, username, and password (OTP verification included).

- `login [Username] [Password]`  
  Log in securely using RSA encryption and Ephemeral Diffie-Hellman key exchange.

- `logout`  
  Logout from the BBS and terminate the session.

- `list [N]`  
  List the latest N posts from the server.

- `get [Id]`  
  Retrieve a post by its ID.

- `add [Title] [Author] [Body]`  
  Add a new post to the board.

- `exit`  
  Exit the client application.

## 🧩 Server Design

- Centralized server with a known IP/port
- Uses RSA for initial encryption and AES-128-GCM for session communication
- Maintains a private/public RSA key pair and session encryption key (KAESBBS)
- Supports replay attack prevention with nonce verification and session expiration

## 🔐 Security Highlights

- **Registration:** User data is encrypted with server’s RSA public key; OTP verification is required.
- **Login:** Ephemeral Diffie-Hellman key exchange with hashed-password authentication.
- **Session Encryption:** AES-128-GCM ensures confidentiality and message integrity.
- **Post Storage:** Posts are encrypted and stored on disk using AES; keys are refreshed on every server restart.

## 🧪 How to Run

```bash
make
./run.sh
```
## 🔐 Note
The RSA key included in the `.pem` file must be generated using `openssl` and placed in the `FoC-Project/keys` folder. BBS project specification from 2024-2025 academic year.



