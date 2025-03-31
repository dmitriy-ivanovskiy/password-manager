import pytest
import base64
import sys
import os

# Add app directory to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.utils.crypto import (
    generate_salt,
    hash_master_password,
    derive_key,
    encrypt_data,
    decrypt_data
)

def test_salt_generation():
    """Test that salt generation creates random bytes of correct length"""
    salt1 = generate_salt()
    salt2 = generate_salt()
    
    assert len(salt1) == 16
    assert salt1 != salt2  # Should be random

def test_key_derivation():
    """Test key derivation from password and salt"""
    password = "test_password"
    salt = b'testsalt12345678'
    
    key = derive_key(password, salt)
    
    # Test key format is correct (base64 encoded)
    assert isinstance(key, bytes)
    # Should be 32 bytes before encoding
    assert len(base64.urlsafe_b64decode(key + b'=' * (-len(key) % 4))) == 32
    
    # Same password and salt should yield same key
    key2 = derive_key(password, salt)
    assert key == key2
    
    # Different password should yield different key
    key3 = derive_key("different_password", salt)
    assert key != key3

def test_password_hashing():
    """Test master password hashing"""
    password = "master_password"
    salt = generate_salt()
    
    # Hash should be deterministic for same inputs
    hash1 = hash_master_password(password, salt)
    hash2 = hash_master_password(password, salt)
    assert hash1 == hash2
    
    # Different passwords should yield different hashes
    hash3 = hash_master_password("different_password", salt)
    assert hash1 != hash3
    
    # Different salts should yield different hashes
    salt2 = generate_salt()
    hash4 = hash_master_password(password, salt2)
    assert hash1 != hash4 

def test_generate_salt():
    """Test salt generation."""
    salt1 = generate_salt()
    salt2 = generate_salt()
    
    assert len(salt1) == 16  # Check length (16 bytes = 128 bits)
    assert salt1 != salt2    # Check randomness
    assert isinstance(salt1, bytes)

def test_hash_master_password():
    """Test master password hashing."""
    password = "TestPassword123!"
    salt = generate_salt()
    
    hash1 = hash_master_password(password, salt)
    hash2 = hash_master_password(password, salt)
    
    assert hash1 == hash2  # Same password + salt should produce same hash
    assert isinstance(hash1, str)
    assert len(hash1) > 0

def test_derive_key():
    """Test key derivation."""
    password = "TestPassword123!"
    salt = generate_salt()
    
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    
    # Key should be base64 encoded and suitable for Fernet
    assert len(key1) == 44  # Base64 encoded 32-byte key
    assert key1 == key2     # Same input should produce same key
    assert isinstance(key1, bytes)

def test_password_encryption_decryption():
    """Test password encryption and decryption."""
    master_password = "TestPassword123!"
    password_to_encrypt = "SecurePass456!"
    
    # Generate salt and derive key
    salt = generate_salt()
    key = derive_key(master_password, salt)
    
    # Encrypt password
    encrypted = encrypt_data(password_to_encrypt, key)
    assert isinstance(encrypted, str)
    assert encrypted != password_to_encrypt
    
    # Decrypt password
    decrypted = decrypt_data(encrypted, key)
    assert decrypted == password_to_encrypt

def test_encryption_with_wrong_key():
    """Test encryption/decryption with wrong key."""
    correct_master_pass = "CorrectPassword123!"
    wrong_master_pass = "WrongPassword123!"
    password_to_encrypt = "SecurePass456!"
    
    # Generate salt and derive keys
    salt = generate_salt()
    correct_key = derive_key(correct_master_pass, salt)
    wrong_key = derive_key(wrong_master_pass, salt)
    
    # Encrypt with correct key
    encrypted = encrypt_data(password_to_encrypt, correct_key)
    
    # Try to decrypt with wrong key
    with pytest.raises(Exception):
        decrypt_data(encrypted, wrong_key) 