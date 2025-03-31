import os
import secrets
from dotenv import load_dotenv

# Load .env file in development
if os.path.exists('.env'):
    load_dotenv()

class Config:
    """Application configuration"""
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'
    
    # Paths
    CONFIG_PATH = os.environ.get('CONFIG_PATH', 'instance/config.json')
    DB_PATH = os.environ.get('DB_PATH', 'instance/vault.db')
    
    # Security settings
    PBKDF2_ITERATIONS = int(os.environ.get('PBKDF2_ITERATIONS', 100000))
    DEFAULT_PASSWORD_LENGTH = int(os.environ.get('DEFAULT_PASSWORD_LENGTH', 16))
    
    # Session settings
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = "./flask_session"
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('SESSION_TIMEOUT_MINUTES', 30)) * 60
    
    # Logging settings
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/password_manager.log')
    
    # CSP and security headers
    TALISMAN_CONTENT_SECURITY_POLICY = {
        'default-src': "'self'",
        'img-src': ['data:', "'self'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'script-src': ["'self'", "'unsafe-inline'"],
    }
    
    # Rate limiting
    RATELIMIT_DEFAULT = ["200 per day", "50 per hour"]
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_STRATEGY = "fixed-window"
    
    # For Flask 2.x compatibility
    @property
    def SESSION_COOKIE_SECURE(self):
        """Set secure cookie in production only"""
        return os.environ.get('FLASK_ENV') == 'production'
        
    @property
    def SESSION_COOKIE_HTTPONLY(self):
        """Always set HttpOnly flag"""
        return True
        
    @property
    def SESSION_COOKIE_SAMESITE(self):
        """Use strict SameSite policy"""
        return 'Strict' 