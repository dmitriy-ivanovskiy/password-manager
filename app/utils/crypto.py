from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets
import json
import os
from app.config import Config

def get_fernet_from_session(session):
    """
    Get a Fernet instance from the session encryption key
    
    Args:
        session: Flask session object
        
    Returns:
        Fernet object or None if no encryption key in session
    """
    if 'encryption_key' not in session:
        return None
    return Fernet(session['encryption_key'].encode())

def generate_salt():
    """
    Generate a cryptographically secure random salt
    
    Returns:
        bytes: Random 16-byte salt
    """
    return secrets.token_bytes(16)

def derive_key(password, salt):
    """
    Derive an encryption key from a password and salt using PBKDF2
    
    Args:
        password (str): Master password
        salt (bytes): Random salt
        
    Returns:
        bytes: Base64 encoded 32-byte key suitable for Fernet
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=Config.PBKDF2_ITERATIONS,
    )
    # Generate a raw key from the password
    raw_key = kdf.derive(password.encode())
    
    # Ensure proper padding with the right length for Fernet
    # Fernet requires 32 url-safe base64-encoded bytes
    key = base64.urlsafe_b64encode(raw_key)
    
    # Verify that the resulting key is valid for Fernet
    try:
        # Test if we can create a Fernet instance with this key
        Fernet(key)
    except Exception as e:
        # If there's an error, log it and regenerate the key with proper length and padding
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Invalid Fernet key generated: {e}")
        
        # Make sure the key is exactly 32 bytes
        raw_key = raw_key[:32]
        key = base64.urlsafe_b64encode(raw_key)
    
    return key

def hash_master_password(password, salt):
    """
    Hash the master password for storage/verification
    
    Args:
        password (str): Master password
        salt (bytes): Random salt
        
    Returns:
        str: Base64 encoded key derived from password
    """
    # Generate a raw key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=Config.PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(password.encode())
    
    # Base64 encode the raw key for storage
    return base64.urlsafe_b64encode(raw_key).decode()

def encrypt_data(data, key):
    """
    Encrypt data using Fernet symmetric encryption
    
    Args:
        data (str): Data to encrypt
        key (bytes): Encryption key
        
    Returns:
        str: Encrypted data as base64 string
    """
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    """
    Decrypt data using Fernet symmetric encryption
    
    Args:
        encrypted_data (str): Encrypted data as base64 string
        key (bytes): Encryption key
        
    Returns:
        str: Decrypted data
        
    Raises:
        Exception: If decryption fails
    """
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data.encode()).decode()

def encrypt_config(config_data, key):
    """
    Encrypt config.json data with a key
    
    Args:
        config_data (dict): Configuration data
        key (str): Encryption key (must be a valid Fernet key)
        
    Returns:
        str: Encrypted data as base64 string
    """
    try:
        # Ensure key is valid Fernet format
        if not key:
            raise ValueError("Empty encryption key")
        
        # If key is shorter than 32 bytes, pad it
        if len(key) < 32:
            key = key.ljust(32, '0')
            
        # If key is not base64 encoded, encode it
        try:
            key_bytes = key.encode()
            # Test if key can be used for Fernet
            Fernet(key_bytes)
        except Exception:
            # Key is not in correct format, generate a valid one using it as seed
            import hashlib
            raw_key = hashlib.sha256(key.encode()).digest()
            key_bytes = base64.urlsafe_b64encode(raw_key)
        
        # Use the key to encrypt data
        fernet = Fernet(key_bytes)
        return fernet.encrypt(json.dumps(config_data).encode()).decode()
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error encrypting config: {e}")
        
        # Fallback - use a generated key if all else fails
        fallback_key = Fernet.generate_key()
        fernet = Fernet(fallback_key)
        return fernet.encrypt(json.dumps(config_data).encode()).decode()

def decrypt_config(encrypted_data, key):
    """
    Decrypt config.json data
    
    Args:
        encrypted_data (str): Encrypted data as base64 string
        key (str): Encryption key (must be a valid Fernet key)
        
    Returns:
        dict: Decrypted configuration data
        
    Raises:
        Exception: If decryption fails
    """
    try:
        # Apply the same transformations as in encrypt_config
        if len(key) < 32:
            key = key.ljust(32, '0')
            
        try:
            key_bytes = key.encode()
            # Test if key can be used for Fernet
            Fernet(key_bytes)
        except Exception:
            import hashlib
            raw_key = hashlib.sha256(key.encode()).digest()
            key_bytes = base64.urlsafe_b64encode(raw_key)
        
        fernet = Fernet(key_bytes)
        return json.loads(fernet.decrypt(encrypted_data.encode()).decode())
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error decrypting config: {e}")
        raise

def decrypt_password(encrypted_password, vault_key):
    """
    Decrypt a password from the vault
    
    Args:
        encrypted_password (str): Encrypted password from the database
        vault_key (bytes): Vault key for decryption
        
    Returns:
        str: Decrypted password
    """
    try:
        import logging
        from flask import current_app
        logger = logging.getLogger(__name__)
        
        # Handle different formats of vault_key
        if isinstance(vault_key, str):
            # If it's a string, encode it
            key = vault_key.encode()
        else:
            # If it's already bytes, use it directly
            key = vault_key
        
        # Create Fernet instance with the vault key
        fernet = Fernet(key)
        
        # Decrypt the password
        return fernet.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        logger.error(f"Error decrypting password: {e}")
        raise

def encrypt_password(password, vault_key):
    """
    Encrypt a password for storage in the vault
    
    Args:
        password (str): Plain text password to encrypt
        vault_key (bytes or str): Vault key for encryption
        
    Returns:
        str: Encrypted password
    """
    try:
        import logging
        logger = logging.getLogger(__name__)
        
        # Handle different formats of vault_key
        if isinstance(vault_key, str):
            # If it's a string, encode it
            key = vault_key.encode()
        else:
            # If it's already bytes, use it directly
            key = vault_key
        
        # Create Fernet instance with the vault key
        fernet = Fernet(key)
        
        # Encrypt the password
        return fernet.encrypt(password.encode()).decode()
    except Exception as e:
        logger.error(f"Error encrypting password: {e}")
        raise 