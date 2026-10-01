import os
import hashlib
from typing import Optional, Tuple
from cryptography.fernet import Fernet

KEY_FILE = "master.key"

def get_or_create_key() -> bytes:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read().strip()
            if len(key) == 44:
                return key

    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def encrypt_file(data: bytes, key: Optional[bytes] = None) -> bytes:
    if key is None:
        key = get_or_create_key()
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_file(cipher_data: bytes, key: Optional[bytes] = None) -> bytes:
    if key is None:
        key = get_or_create_key()
    fernet = Fernet(key)
    return fernet.decrypt(cipher_data)

def encrypt_data(data: bytes, key: Optional[bytes] = None) -> Tuple[bytes, str]:
    encrypted = encrypt_file(data, key)
    digest = calculate_sha256(data)
    return encrypted, digest

# Function aliases for test suite compatibility
get_master_key = get_or_create_key
decrypt_data = decrypt_file