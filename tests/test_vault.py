import pytest
from app.crypto import get_master_key, encrypt_data, decrypt_data, calculate_sha256

def test_encryption_and_decryption():
    key = get_master_key()
    original_bytes = b"Ransomware Resilient Backup Test Payload"
    
    # Test encryption & hash computation
    encrypted_blob, sha256_hash = encrypt_data(original_bytes, key)
    assert encrypted_blob != original_bytes
    assert sha256_hash == calculate_sha256(original_bytes)
    
    # Test decryption
    decrypted_bytes = decrypt_data(encrypted_blob, key)
    assert decrypted_bytes == original_bytes

def test_tampering_detection():
    key = get_master_key()
    original_bytes = b"Important Business File Data"
    
    encrypted_blob, sha256_hash = encrypt_data(original_bytes, key)
    
    # Simulate byte corruption on disk
    corrupted_blob = bytearray(encrypted_blob)
    corrupted_blob[-1] ^= 0xFF  # Flip the last byte
    
    # Decryption should fail or produce hash mismatch
    with pytest.raises(Exception):
        decrypted_bytes = decrypt_data(bytes(corrupted_blob), key)
        restored_hash = calculate_sha256(decrypted_bytes)
        assert restored_hash != sha256_hash