"""
Form validation utilities for the Password Manager application.

This module provides reusable validation functions for form inputs, such as
passwords, usernames, email addresses, and URLs. It also includes functions
for sanitizing inputs and creating custom validators for WTForms.
"""

import re
from wtforms.validators import ValidationError
import validators
from flask import current_app


def validate_password_strength(password, min_length=12, require_special=True, 
                              require_upper=True, require_lower=True, 
                              require_digit=True):
    """
    Validates password strength according to security requirements.
    
    Args:
        password (str): Password to validate
        min_length (int): Minimum required length
        require_special (bool): Require special characters
        require_upper (bool): Require uppercase letters
        require_lower (bool): Require lowercase letters
        require_digit (bool): Require digits
        
    Returns:
        tuple: (is_valid, error_message)
    """
    error_messages = []
    
    # Check password length
    if len(password) < min_length:
        error_messages.append(f"Password must be at least {min_length} characters long")
    
    # Check for uppercase letters
    if require_upper and not any(c.isupper() for c in password):
        error_messages.append("Password must contain at least one uppercase letter")
    
    # Check for lowercase letters
    if require_lower and not any(c.islower() for c in password):
        error_messages.append("Password must contain at least one lowercase letter")
    
    # Check for digits
    if require_digit and not any(c.isdigit() for c in password):
        error_messages.append("Password must contain at least one digit")
    
    # Check for special characters
    if require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        error_messages.append("Password must contain at least one special character")
    
    # Return validation result
    if error_messages:
        return False, ", ".join(error_messages)
    return True, ""


def validate_email(email):
    """
    Validates an email address format.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not validators.email(email):
        return False, "Invalid email address format"
    return True, ""


def validate_url(url):
    """
    Validates a URL format.
    
    Args:
        url (str): URL to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not validators.url(url):
        return False, "Invalid URL format"
    return True, ""


def sanitize_input(text):
    """
    Sanitizes user input to prevent XSS and other injection attacks.
    
    Args:
        text (str): Text to sanitize
        
    Returns:
        str: Sanitized text
    """
    # Basic sanitization - remove HTML tags
    sanitized = re.sub(r'<[^>]*>', '', text)
    return sanitized


class PasswordStrengthValidator:
    """
    Custom WTForms validator for password strength.
    """
    def __init__(self, min_length=12, require_special=True, 
                require_upper=True, require_lower=True, require_digit=True,
                message=None):
        self.min_length = min_length
        self.require_special = require_special
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digit = require_digit
        self.message = message
    
    def __call__(self, form, field):
        password = field.data
        is_valid, message = validate_password_strength(
            password, 
            self.min_length, 
            self.require_special,
            self.require_upper,
            self.require_lower,
            self.require_digit
        )
        
        if not is_valid:
            if self.message:
                raise ValidationError(self.message)
            raise ValidationError(message)


class UrlValidator:
    """
    Custom WTForms validator for URLs.
    """
    def __init__(self, message=None):
        self.message = message or "Invalid URL format"
    
    def __call__(self, form, field):
        is_valid, _ = validate_url(field.data)
        if not is_valid:
            raise ValidationError(self.message)


def register_form_validators():
    """
    Returns a dictionary of validators that can be imported and used in forms.
    
    Returns:
        dict: Dictionary of validator functions
    """
    return {
        'validate_password_strength': validate_password_strength,
        'validate_email': validate_email,
        'validate_url': validate_url,
        'sanitize_input': sanitize_input,
        'PasswordStrengthValidator': PasswordStrengthValidator,
        'UrlValidator': UrlValidator
    } 