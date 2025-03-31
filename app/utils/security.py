"""
Security utilities for the Password Manager application.

This module provides helper functions for various security features,
including CSRF protection, rate limiting, content security policy,
and security headers.
"""

from flask import current_app, request
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets
import functools

# Initialize security extensions
csrf = CSRFProtect()
talisman = Talisman()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


def generate_secure_token(length=32):
    """
    Generate a cryptographically secure random token.
    
    Args:
        length (int): Length of the token in bytes
        
    Returns:
        str: Secure random token as a hex string
    """
    return secrets.token_hex(length)


def configure_csp(app):
    """
    Configure Content Security Policy for the application.
    
    Args:
        app: Flask application
    """
    # Default CSP policy for a secure web application
    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],  # Unsafe-inline needed for some libraries
        'style-src': ["'self'", "'unsafe-inline'"],   # Unsafe-inline needed for some CSS
        'img-src': ["'self'", 'data:'],              # Allow data: for embedded images
        'font-src': ["'self'"],
        'connect-src': ["'self'"],
        'frame-src': ["'none'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'form-action': ["'self'"],
    }
    
    app.config['TALISMAN_CONTENT_SECURITY_POLICY'] = csp


def rate_limit(limit_value):
    """
    Decorator to apply rate limiting to a route.
    
    Args:
        limit_value (str): Rate limit value (e.g., "5 per minute")
        
    Returns:
        function: Rate limiting decorator
    """
    def decorator(f):
        return limiter.limit(limit_value)(f)
    return decorator


def apply_rate_limits(app):
    """
    Apply rate limits to sensitive routes.
    
    Args:
        app: Flask application
    """
    # Import blueprints here to avoid circular imports
    from app.routes import auth_bp
    
    # Apply rate limits to authentication routes
    limiter.limit("5 per minute")(auth_bp.route('/login', methods=['POST']))
    limiter.limit("5 per minute")(auth_bp.route('/register', methods=['POST']))
    limiter.limit("3 per minute")(auth_bp.route('/reset-password', methods=['POST']))


def secure_headers():
    """
    Get a dictionary of secure headers to apply to responses.
    
    Returns:
        dict: Security headers
    """
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
    }


def apply_security_headers(response):
    """
    Apply security headers to an HTTP response.
    
    Args:
        response: Flask response object
        
    Returns:
        response: Modified Flask response
    """
    for header, value in secure_headers().items():
        response.headers[header] = value
    return response


def init_app(app):
    """
    Initialize security features for the Flask app.
    
    Args:
        app: Flask application
    """
    # Initialize CSRF protection
    csrf.init_app(app)
    
    # Configure CSP
    configure_csp(app)
    
    # Initialize Talisman for HTTPS and CSP
    talisman.init_app(
        app,
        content_security_policy=app.config.get('TALISMAN_CONTENT_SECURITY_POLICY'),
        force_https=app.config.get('FORCE_HTTPS', False),
    )
    
    # Initialize rate limiting
    limiter.init_app(app)
    
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response

    # Apply rate limits after all blueprints are registered
    @app.before_first_request
    def setup_rate_limits():
        apply_rate_limits(app) 
