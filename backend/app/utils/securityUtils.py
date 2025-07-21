import os
import re
import html
import bleach
import secrets
import hashlib
import base64
from typing import Any, Union
from cryptography.fernet import Fernet

# ----------------------------------------------------------
# ✅ **File Handling Security**
# ----------------------------------------------------------

def sanitize_file_path(file_path: str, max_length: int = 255) -> str:
    """
    Sanitize file paths to prevent directory traversal attacks.
    
    Args:
        file_path (str): Input file path
        max_length (int): Maximum allowed length of the path
    
    Returns:
        str: Sanitized file path
    """
    file_path = file_path.replace('\x00', '')  # Null byte injection prevention
    file_path = ''.join(c for c in file_path if c.isprintable())  # Remove non-printable chars
    file_path = file_path[:max_length]  # Limit length
    file_path = re.sub(r'(\.\./|\.\.\\)', '', file_path)  # Remove directory traversal sequences
    return file_path.strip()

def validate_file(file_path: str) -> bool:
    """
    Validate a file's existence and permissions.
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        bool: True if the file is valid, False otherwise
    """
    return os.path.exists(file_path) and os.access(file_path, os.R_OK)

# ----------------------------------------------------------
# ✅ **Input Sanitization**
# ----------------------------------------------------------

def sanitize_input(input_value: Union[str, Any], max_length: int = 1000) -> str:
    """
    Sanitize input to prevent injection attacks.
    
    Args:
        input_value (str): Input value to sanitize
        max_length (int): Maximum length of the input
    
    Returns:
        str: Sanitized input
    """
    if not isinstance(input_value, str):
        input_value = str(input_value)
    
    input_value = input_value[:max_length]  # Truncate input length
    input_value = html.escape(input_value)  # Escape HTML characters
    input_value = bleach.clean(input_value, strip=True)  # Remove unsafe HTML tags
    input_value = ''.join(char for char in input_value if char.isprintable())  # Remove non-printable chars
    return input_value.strip()

# ----------------------------------------------------------
# ✅ **Token & Credential Security**
# ----------------------------------------------------------

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure cryptographic token.
    
    Args:
        length (int): Length of the token
    
    Returns:
        str: Hexadecimal secure token
    """
    return secrets.token_hex(length)

def hash_value(value: str, salt: str = '') -> str:
    """
    Generate a secure hash using SHA-256 with optional salting.
    
    Args:
        value (str): Value to hash
        salt (str): Optional salt for added security
    
    Returns:
        str: SHA-256 hashed value
    """
    salted_value = f"{salt}{value}"
    return hashlib.sha256(salted_value.encode()).hexdigest()

def validate_email(email: str) -> bool:
    """
    Validate email format using regex.
    
    Args:
        email (str): Email address to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def validate_password(password: str) -> bool:
    """
    Validate password strength based on security policies.
    
    - At least 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character (@$!%*?&)
    
    Args:
        password (str): Password to validate
    
    Returns:
        bool: True if valid, False otherwise
    """
    password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$'
    return bool(re.match(password_regex, password))

def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data, showing only the last few characters.
    
    Args:
        data (str): Sensitive data
        visible_chars (int): Number of characters to remain visible
    
    Returns:
        str: Masked sensitive data
    """
    return f"{'*' * (len(data) - visible_chars)}{data[-visible_chars:]}" if len(data) > visible_chars else data

# ----------------------------------------------------------
# ✅ **Encryption & Secure Storage**
# ----------------------------------------------------------

def generate_encryption_key() -> bytes:
    """
    Generate a Fernet encryption key.
    
    Returns:
        bytes: Secure encryption key
    """
    return Fernet.generate_key()

def encrypt_data(data: str, key: bytes) -> str:
    """
    Encrypt data using Fernet symmetric encryption.
    
    Args:
        data (str): Data to encrypt
        key (bytes): Encryption key
    
    Returns:
        str: Encrypted data in base64 format
    """
    cipher = Fernet(key)
    return base64.urlsafe_b64encode(cipher.encrypt(data.encode())).decode()

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    """
    Decrypt data using Fernet symmetric encryption.
    
    Args:
        encrypted_data (str): Base64 encoded encrypted data
        key (bytes): Encryption key
    
    Returns:
        str: Decrypted data
    """
    cipher = Fernet(key)
    return cipher.decrypt(base64.urlsafe_b64decode(encrypted_data)).decode()

# ----------------------------------------------------------
# ✅ **CLI & API Authentication Security**
# ----------------------------------------------------------

def generate_jwt_secret() -> str:
    """
    Generate a secure JWT secret key.
    
    Returns:
        str: Secure JWT secret
    """
    return secrets.token_hex(64)

def validate_cli_auth_token(token: str, stored_hash: str, salt: str) -> bool:
    """
    Validate a CLI authentication token using a stored hash.
    
    Args:
        token (str): CLI token to validate
        stored_hash (str): Stored hashed token
        salt (str): Salt used in hashing
    
    Returns:
        bool: True if token is valid, False otherwise
    """
    return hash_value(token, salt) == stored_hash

# ----------------------------------------------------------
# ✅ **Secure Configuration**
# ----------------------------------------------------------

class SecurityConfig:
    """
    Centralized security configurations for the application.
    """

    JWT_SECRET_KEY = generate_jwt_secret()
    ENCRYPTION_KEY = generate_encryption_key()

    PASSWORD_POLICY = {
        "min_length": 12,
        "uppercase_required": True,
        "lowercase_required": True,
        "number_required": True,
        "special_character_required": True
    }

    MAX_FILE_UPLOAD_SIZE = 16 * 1024 * 1024  # 16MB
    ALLOWED_FILE_EXTENSIONS = {".exe", ".dll", ".bin", ".apk", ".msi"}

    @staticmethod
    def is_valid_file_extension(filename: str) -> bool:
        """
        Check if a file has a valid extension.
        
        Args:
            filename (str): Filename to check
        
        Returns:
            bool: True if valid, False otherwise
        """
        return os.path.splitext(filename)[1].lower() in SecurityConfig.ALLOWED_FILE_EXTENSIONS

    @staticmethod
    def enforce_password_policy(password: str) -> bool:
        """
        Check if a password meets security policies.
        
        Args:
            password (str): Password to validate
        
        Returns:
            bool: True if policy is met, False otherwise
        """
        return validate_password(password)

