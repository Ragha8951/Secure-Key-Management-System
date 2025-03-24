import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta

class SecureKeyManagement:
    def __init__(self):
        self.users = {}
        self.ca = self._init_ca()
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
        self.shared_keys = {}  # {(user1, user2): key}
        self.revoked_keys = set()  # Track revoked symmetric keys
        self.key_versions = {}  # Track key versions for rollover

    def _init_ca(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureKMS Root CA")
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        return {
            'key': ca_key,
            'cert': ca_cert,
            'revoked': set()
        }

    def register_user(self, user_id):
        if user_id in self.users:
            raise ValueError(f"User {user_id} already exists")
        
        aes_key = os.urandom(32)
        priv_key = rsa.generate_private_key(65537, 2048)
        
        self.users[user_id] = {
            'aes_key': aes_key,
            'priv_key': priv_key,
            'cert': None,
            'dh_priv': None
        }
        self.key_versions[user_id] = 1
        return aes_key

    def issue_certificate(self, user_id):
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not registered")
        if self.users[user_id]['cert']:
            raise ValueError(f"Certificate already exists for {user_id}")
            
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_id)
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca['cert'].subject)
            .public_key(self.users[user_id]['priv_key'].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(self.ca['key'], hashes.SHA256())
        )
        
        self.users[user_id]['cert'] = cert
        return cert

    def revoke_certificate(self, user_id):
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not registered")
        if not self.users[user_id]['cert']:
            raise ValueError(f"No certificate exists for {user_id}")
            
        self.ca['revoked'].add(self.users[user_id]['cert'].serial_number)
        self.revoke_symmetric_key(user_id)

    def revoke_symmetric_key(self, user_id):
        """Revoke and regenerate a user's symmetric key"""
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not registered")
        
        # Revoke current key
        current_key = self.users[user_id]['aes_key']
        self.revoked_keys.add(current_key)
        
        # Generate new key
        new_key = os.urandom(32)
        self.users[user_id]['aes_key'] = new_key
        self.key_versions[user_id] += 1
        
        # Revoke all shared keys involving this user
        to_delete = [pair for pair in self.shared_keys if user_id in pair]
        for pair in to_delete:
            self.revoked_keys.add(self.shared_keys[pair])
            del self.shared_keys[pair]
        
        return new_key

    def revoke_shared_key(self, user1, user2):
        """Revoke a specific shared key between two users"""
        key = self.shared_keys.get((user1, user2))
        if key:
            self.revoked_keys.add(key)
            del self.shared_keys[(user1, user2)]
            del self.shared_keys[(user2, user1)]  # Remove both directions
            return True
        return False

    def is_key_revoked(self, key):
        """Check if a key has been revoked"""
        return key in self.revoked_keys

    def check_certificate_status(self, user_id):
        if user_id not in self.users:
            return "User not registered"
        if not self.users[user_id]['cert']:
            return "No certificate issued"
            
        cert = self.users[user_id]['cert']
        if cert.serial_number in self.ca['revoked']:
            return "REVOKED"
        if cert.not_valid_after_utc < datetime.now(timezone.utc):
            return "EXPIRED"
        return "VALID"

    def dh_key_exchange(self, user_id):
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not registered")
            
        priv_key = self.dh_parameters.generate_private_key()
        self.users[user_id]['dh_priv'] = priv_key
        return priv_key.public_key()

    def establish_shared_key(self, user1, user2):
        """Establish a shared secret between two users using DH"""
        if user1 not in self.users or user2 not in self.users:
            raise ValueError("One or both users not registered")
            
        pub1 = self.dh_key_exchange(user1)
        pub2 = self.dh_key_exchange(user2)
        
        shared1 = self.derive_shared_secret(user1, pub2)
        shared2 = self.derive_shared_secret(user2, pub1)
        
        if shared1 == shared2:
            self.shared_keys[(user1, user2)] = shared1
            self.shared_keys[(user2, user1)] = shared1  # Symmetric
            return shared1
        raise ValueError("Key exchange failed")

    def derive_shared_secret(self, user_id, peer_public_key):
        if user_id not in self.users or not self.users[user_id]['dh_priv']:
            raise ValueError("Invalid user or no DH private key")
            
        shared_key = self.users[user_id]['dh_priv'].exchange(peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'DH Key Derivation'
        ).derive(shared_key)

    def encrypt_message(self, sender, receiver, message):
        """Encrypt with key revocation check"""
        if (sender, receiver) not in self.shared_keys:
            self.establish_shared_key(sender, receiver)
            
        shared_key = self.shared_keys[(sender, receiver)]
        
        if self.is_key_revoked(shared_key):
            raise ValueError("Shared key has been revoked - establish new key first")
            
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt_message(self, receiver, sender, ciphertext):
        """Decrypt with key revocation check"""
        if (sender, receiver) not in self.shared_keys:
            raise ValueError("No shared key established")
            
        shared_key = self.shared_keys[(sender, receiver)]
        
        if self.is_key_revoked(shared_key):
            raise ValueError("Shared key has been revoked - establish new key first")
            
        iv = ciphertext[:16]
        tag = ciphertext[16:32]
        encrypted = ciphertext[32:]
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return (decryptor.update(encrypted) + decryptor.finalize()).decode()

class KeyManagementUI:
    def __init__(self):
        self.system = SecureKeyManagement()
    
    def _print_menu(self):
        print("\n=== Secure Key Management System ===")
        print("1. Register User")
        print("2. Issue Certificate")
        print("3. Revoke Certificate")
        print("4. Check Certificate Status")
        print("5. Establish Shared Key")
        print("6. Send Encrypted Message")
        print("7. Receive Decrypted Message")
        print("8. Revoke Symmetric Key")
        print("9. Revoke Shared Key")
        print("10. Exit")

    def run(self):
        while True:
            self._print_menu()
            choice = input("Enter choice: ").strip()
            
            try:
                if choice == '1':
                    user_id = input("Enter user ID: ").strip()
                    self.system.register_user(user_id)
                    print(f"User '{user_id}' registered with key version {self.system.key_versions[user_id]}.")
                
                elif choice == '2':
                    user_id = input("Enter user ID: ").strip()
                    cert = self.system.issue_certificate(user_id)
                    print(f"Certificate issued for '{user_id}' (SN: {cert.serial_number}).")
                
                elif choice == '3':
                    user_id = input("Enter user ID to revoke certificate: ").strip()
                    self.system.revoke_certificate(user_id)
                    print(f"Certificate and symmetric key revoked for '{user_id}'")
                    print(f"New key version: {self.system.key_versions[user_id]}")
                
                elif choice == '4':
                    user_id = input("Enter user ID to check status: ").strip()
                    status = self.system.check_certificate_status(user_id)
                    print(f"Certificate status: {status}")
                
                elif choice == '5':
                    user1 = input("First user ID: ").strip()
                    user2 = input("Second user ID: ").strip()
                    key = self.system.establish_shared_key(user1, user2)
                    print(f"Shared key established: {key.hex()[:16]}...")
                
                elif choice == '6':
                    sender = input("Your user ID: ").strip()
                    receiver = input("Recipient user ID: ").strip()
                    message = input("Message to send: ").strip()
                    ciphertext = self.system.encrypt_message(sender, receiver, message)
                    print(f"Encrypted Message (hex): {ciphertext.hex()}")
                
                elif choice == '7':
                    receiver = input("Your user ID: ").strip()
                    sender = input("Sender user ID: ").strip()
                    ciphertext_hex = input("Encrypted message (hex): ").strip()
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    message = self.system.decrypt_message(receiver, sender, ciphertext)
                    print(f"Decrypted Message: {message}")
                
                elif choice == '8':
                    user_id = input("Enter user ID to revoke symmetric key: ").strip()
                    new_key = self.system.revoke_symmetric_key(user_id)
                    print(f"New key version {self.system.key_versions[user_id]}: {new_key.hex()[:16]}...")
                
                elif choice == '9':
                    user1 = input("First user ID: ").strip()
                    user2 = input("Second user ID: ").strip()
                    if self.system.revoke_shared_key(user1, user2):
                        print("Shared key revoked")
                    else:
                        print("No shared key found")
                
                elif choice == '10':
                    print("Exiting system...")
                    break
                
                else:
                    print("Invalid choice")
            
            except ValueError as e:
                print(f"Error: {str(e)}")
            except Exception as e:
                print(f"Critical error: {str(e)}")

if __name__ == "__main__":
    ui = KeyManagementUI()
    ui.run()