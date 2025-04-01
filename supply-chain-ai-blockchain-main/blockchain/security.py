from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import Tuple, Dict, Optional
import json
import hashlib
from datetime import datetime

class CryptographicSecurity:
    def __init__(self):
        self.backend = default_backend()
        self._generate_key_pair()
        
    def _generate_key_pair(self) -> None:
        """Generate RSA key pair for digital signatures"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        
    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure salt"""
        return os.urandom(16)
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())
        
    def encrypt_data(self, data: str, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return ciphertext, iv
        
    def decrypt_data(self, ciphertext: bytes, iv: bytes, key: bytes) -> str:
        """Decrypt data using AES-256-GCM"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
        
    def sign_data(self, data: Dict) -> bytes:
        """Sign data using RSA-PSS"""
        data_string = json.dumps(data, sort_keys=True)
        signature = self.private_key.sign(
            data_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
        
    def verify_signature(self, data: Dict, signature: bytes) -> bool:
        """Verify RSA-PSS signature"""
        try:
            data_string = json.dumps(data, sort_keys=True)
            self.public_key.verify(
                signature,
                data_string.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
            
    def generate_merkle_root(self, transactions: list) -> str:
        """Generate Merkle root from list of transactions"""
        if not transactions:
            return ""
            
        # Convert transactions to hashes
        hashes = [hashlib.sha3_256(json.dumps(tx, sort_keys=True).encode()).hexdigest() 
                 for tx in transactions]
        
        # Build Merkle tree
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i + 1]
                new_hash = hashlib.sha3_256(combined.encode()).hexdigest()
                new_hashes.append(new_hash)
            hashes = new_hashes
            
        return hashes[0]
        
    def hash_transaction(self, transaction: Dict) -> str:
        """Generate SHA-3 hash of transaction"""
        return hashlib.sha3_256(
            json.dumps(transaction, sort_keys=True).encode()
        ).hexdigest()
        
    def export_public_key(self) -> str:
        """Export public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
    def import_public_key(self, key_pem: str) -> None:
        """Import public key from PEM format"""
        self.public_key = serialization.load_pem_public_key(
            key_pem.encode(),
            backend=self.backend
        ) 