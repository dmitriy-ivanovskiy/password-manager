"""
Session management utilities for the Password Manager application.

This module provides helper functions for managing user sessions,
including session creation, validation, and timeout management.
"""

from datetime import datetime, timedelta
from flask import session, current_app, request, redirect, url_for, flash
import functools


def set_session_data(user_id, username, is_authenticated=True, remember=False):
    """
    Set session data for an authenticated user.
    
    Args:
        user_id (int): User ID
        username (str): Username
        is_authenticated (bool): Whether the user is authenticated
        remember (bool): Whether to extend session lifetime
    """
    session.clear()
    session['user_id'] = user_id
    session['username'] = username
    session['is_authenticated'] = is_authenticated
    session['last_active'] = datetime.utcnow()
    
    # Set session to permanent if remember is enabled
    if remember:
        session.permanent = True


def logout_user():
    """
    Log out the current user by clearing the session.
    """
    session.clear()


def is_authenticated():
    """
    Check if the current user is authenticated.
    
    Returns:
        bool: True if user is authenticated, False otherwise
    """
    return session.get('is_authenticated', False)


def get_current_user_id():
    """
    Get the current user's ID from the session.
    
    Returns:
        int: User ID or None if not authenticated
    """
    return session.get('user_id')


def get_current_username():
    """
    Get the current user's username from the session.
    
    Returns:
        str: Username or None if not authenticated
    """
    return session.get('username')


def update_session_activity():
    """
    Update the last activity timestamp in the session.
    """
    session['last_active'] = datetime.utcnow()


def check_session_timeout():
    """
    Check if the current session has timed out.
    
    Returns:
        bool: True if session is valid, False if timed out
    """
    if 'last_active' not in session:
        return False
        
    last_active = session.get('last_active')
    now = datetime.utcnow()
    timeout_minutes = current_app.config.get('PERMANENT_SESSION_LIFETIME').total_seconds() / 60
    
    # Check if session has expired
    if (now - last_active).total_seconds() > timeout_minutes * 60:
        return False
        
    return True


def login_required(view):
    """
    Decorator for views that require authentication.
    
    Args:
        view: The view function to decorate
    
    Returns:
        function: The decorated view function
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not is_authenticated():
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login', next=request.path))
            
        if not check_session_timeout():
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('auth.login', next=request.path))
            
        # Update last active time
        update_session_activity()
        
        return view(**kwargs)
        
    return wrapped_view


def vault_required(view):
    """
    Decorator for views that require an initialized vault.
    
    Args:
        view: The view function to decorate
        
    Returns:
        function: The decorated view function
    """
    @functools.wraps(view)
    @login_required
    def wrapped_view(**kwargs):
        from app.utils.db import load_config
        
        # Check if vault is initialized
        config = load_config()
        if not config.get('master_password_hash'):
            flash('You need to set up your password vault first.', 'warning')
            return redirect(url_for('auth.setup'))
            
        return view(**kwargs)
        
    return wrapped_view


def init_app(app):
    """
    Register session functions with the Flask app.
    
    Args:
        app: Flask application
    """
    # Register before_request handler for session timeout
    @app.before_request
    def check_session_before_request():
        # Skip for static files and login/register routes
        if request.endpoint and (
            request.endpoint.startswith('static') or 
            request.path.startswith('/login') or 
            request.path.startswith('/register') or
            request.path.startswith('/setup')
        ):
            return
            
        # Check if session exists and is still valid
        if is_authenticated() and not check_session_timeout():
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('auth.login')) 