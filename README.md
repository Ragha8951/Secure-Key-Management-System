# Secure Key Management System

## Live Demo
[Run on Google Colab](https://colab.research.google.com/drive/1s4BW-S-pWZtZcLzhiS7YzfZTNThACpwH?usp=sharing)

## Features
- Implements a secure key management system with encryption and key exchange.
- Supports user registration, certificate issuance, and revocation.
- Uses Diffie-Hellman key exchange for secure communication.
- Encrypts and decrypts messages with AES encryption.
- Tracks revoked keys to prevent unauthorized access.

## Prerequisites
- Install Python 3.x on your system.
- Install the required cryptographic library:
  ```bash
  pip install cryptography
  ```
- Upgrade the cryptography library if needed:
  ```bash
  pip install --upgrade cryptography
  ```
- Google Colab access (for running the script online).

## How It Works
1. **User Registration:** Each user registers and gets a unique private key and AES key.
2. **Certificate Issuance:** A digital certificate is generated for the user, signed by the system’s Certificate Authority (CA).
3. **Diffie-Hellman Key Exchange:** Users can establish a shared secret key for secure communication.
4. **Message Encryption & Decryption:** Messages are encrypted using AES with shared keys.
5. **Key & Certificate Revocation:** Users can revoke keys and certificates to maintain security.
6. **Checking Certificate Status:** The system verifies whether a certificate is valid, revoked, or expired.

## Example Usage
```bash
Enter user ID: Alice
User 'Alice' registered with key version 1.

Enter user ID: Bob
User 'Bob' registered with key version 1.

Shared key established: 3f8d2e5c4...

Enter message: Hello, Bob!
Encrypted Message (hex): 4a7b89d1...

Decrypted Message: Hello, Bob!
```

## Understanding Code in Simple Words
Imagine a **secret club** where only authorized members can communicate securely.
- **User Registration:** A new member joins and receives a special secret handshake (private key).
- **Certificate Issuance:** The club leader gives them an ID card (certificate) to prove they belong.
- **Key Exchange:** Two members meet and agree on a secret word (shared key) without anyone else knowing.
- **Message Encryption:** They use this secret word to write coded messages that only they can understand.
- **Message Decryption:** The recipient uses the same secret word to read the original message.
- **Revocation:** If a member loses trust, their ID card and secret handshake are taken away, preventing further access.
- **Checking Status:** Before trusting a message, members check if the sender's ID card is still valid.

## Real-Life Applications
- **Cybersecurity:** Used for managing cryptographic keys in secure systems.
- **End-to-End Encryption:** Ensures secure messaging in apps like WhatsApp and Signal.
- **Online Banking:** Protects transactions by securely exchanging keys.
- **Enterprise Security:** Helps organizations maintain secure access control.
- **Cloud Security:** Encrypts data to prevent unauthorized access in cloud storage.

## Notes
- The system uses RSA for certificates and AES for message encryption.
- Revoked keys cannot be used again for security reasons.
- Ensure the cryptography library is updated for optimal security.

## Future Enhancements
- Implement a more efficient key rotation mechanism.
- Add support for multi-user group encryption.
- Improve user authentication with biometric verification.

## Contribution
Contributions are welcome! If you find any issues or have suggestions, feel free to create a pull request or open an issue on GitHub.

## Author
**GitHub:** [@Ragha8951](https://github.com/Ragha8951)  
**Email:** [ragha8951@gmail.com](mailto:ragha8951@gmail.com)

Thank you for visiting ❤️

