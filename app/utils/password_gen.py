import secrets
import string
import zxcvbn
from app.config import Config

def generate_password(length=None, include_uppercase=True, include_lowercase=True, 
                      include_digits=True, include_symbols=True):
    """
    Generate a cryptographically secure random password with options
    
    Args:
        length (int, optional): Password length
        include_uppercase (bool): Include uppercase letters
        include_lowercase (bool): Include lowercase letters
        include_digits (bool): Include digits
        include_symbols (bool): Include special characters
        
    Returns:
        str: Generated password
    """
    # Use default length from config if not specified
    if length is None:
        length = Config.PASSWORD_LENGTH
    
    # Define character sets based on parameters
    chars = ''
    required_chars = []
    
    if include_lowercase:
        chars += string.ascii_lowercase
        required_chars.append(secrets.choice(string.ascii_lowercase))
        
    if include_uppercase:
        chars += string.ascii_uppercase
        required_chars.append(secrets.choice(string.ascii_uppercase))
        
    if include_digits:
        chars += string.digits
        required_chars.append(secrets.choice(string.digits))
        
    if include_symbols:
        symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?'
        chars += symbols
        required_chars.append(secrets.choice(symbols))
    
    # If no character sets were selected, default to all
    if not chars:
        chars = string.ascii_letters + string.digits + '!@#$%^&*()-_=+[]{}|;:,.<>?'
        required_chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice('!@#$%^&*()-_=+[]{}|;:,.<>?')
        ]
    
    # Generate the password
    # Start with required character from each selected set
    password = required_chars.copy()
    
    # Fill the rest with random characters from all selected sets
    password.extend(secrets.choice(chars) for _ in range(length - len(required_chars)))
    
    # Shuffle the password to ensure the required characters aren't all at the beginning
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def check_password_strength(password):
    """
    Check password strength using zxcvbn
    
    Args:
        password (str): Password to evaluate
        
    Returns:
        dict: Contains score (0-4), feedback and suggestions
    """
    result = zxcvbn.zxcvbn(password)
    
    return {
        'score': result['score'],  # 0-4 (0=weak, 4=strong)
        'warning': result['feedback']['warning'],
        'suggestions': result['feedback']['suggestions'],
        # Adding detailed feedback descriptions for each score
        'feedback': [
            "Very weak: This password could be guessed very easily.",
            "Weak: This password is still too easy to guess.",
            "Fair: This password provides some security, but could be stronger.",
            "Strong: This password is strong and would be difficult to guess.",
            "Very strong: Excellent password choice!"
        ][result['score']]
    } 