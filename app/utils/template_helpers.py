"""
Template helper utilities for Jinja2 templates.

This module provides filters, functions, and other utilities to be used
in the application's templates.
"""
from datetime import datetime
from flask import current_app
import babel.dates
import re


def register_template_helpers(app):
    """
    Register all template helpers with the Flask app.
    
    Args:
        app: Flask application instance
    """
    # Register filters
    app.jinja_env.filters['datetime'] = format_datetime
    app.jinja_env.filters['date'] = format_date
    app.jinja_env.filters['time'] = format_time
    app.jinja_env.filters['timesince'] = timesince
    app.jinja_env.filters['truncate'] = truncate_text
    app.jinja_env.filters['slugify'] = slugify
    
    # Register global functions
    app.jinja_env.globals.update(
        current_year=lambda: datetime.utcnow().year,
        app_name=lambda: app.config.get('APP_NAME', 'Password Manager'),
        app_version=lambda: app.config.get('APP_VERSION', '1.0.0'),
        is_production=lambda: not app.debug,
    )


def format_datetime(value, format='medium'):
    """
    Format a datetime object for display in templates.
    
    Args:
        value: The datetime to format
        format: Format to use (full, long, medium, short) or a custom format string
        
    Returns:
        str: Formatted datetime string
    """
    if value is None:
        return ''
        
    if format == 'full':
        format_string = "EEEE, d. MMMM y 'at' HH:mm"
    elif format == 'long':
        format_string = "d. MMMM y 'at' HH:mm"
    elif format == 'medium':
        format_string = "dd.MM.y HH:mm"
    elif format == 'short':
        format_string = "dd.MM.y"
    else:
        format_string = format
    
    return babel.dates.format_datetime(value, format_string)


def format_date(value, format='medium'):
    """
    Format a date object for display in templates.
    
    Args:
        value: The date to format
        format: Format to use (full, long, medium, short) or a custom format string
        
    Returns:
        str: Formatted date string
    """
    if value is None:
        return ''
        
    if format == 'full':
        format_string = "EEEE, d. MMMM y"
    elif format == 'long':
        format_string = "d. MMMM y"
    elif format == 'medium':
        format_string = "dd.MM.y"
    elif format == 'short':
        format_string = "dd.MM"
    else:
        format_string = format
    
    return babel.dates.format_date(value, format_string)


def format_time(value, format='medium'):
    """
    Format a time object for display in templates.
    
    Args:
        value: The time to format
        format: Format to use (full, long, medium, short) or a custom format string
        
    Returns:
        str: Formatted time string
    """
    if value is None:
        return ''
        
    if format == 'full':
        format_string = "HH:mm:ss Z"
    elif format == 'long':
        format_string = "HH:mm:ss"
    elif format == 'medium':
        format_string = "HH:mm"
    elif format == 'short':
        format_string = "HH"
    else:
        format_string = format
    
    return babel.dates.format_time(value, format_string)


def timesince(value, now=None):
    """
    Return a string representing time since the given datetime.
    
    Args:
        value: The datetime to process
        now: The datetime to use as reference point (defaults to now)
        
    Returns:
        str: Human-readable time difference
    """
    if now is None:
        now = datetime.utcnow()
        
    if value is None:
        return ''
        
    diff = now - value
    
    # Convert to total seconds for easier comparison
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return 'just now'
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f'{minutes} minute{"s" if minutes != 1 else ""} ago'
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f'{hours} hour{"s" if hours != 1 else ""} ago'
    elif seconds < 2592000:  # ~30 days
        days = int(seconds / 86400)
        return f'{days} day{"s" if days != 1 else ""} ago'
    elif seconds < 31536000:  # ~365 days
        months = int(seconds / 2592000)
        return f'{months} month{"s" if months != 1 else ""} ago'
    else:
        years = int(seconds / 31536000)
        return f'{years} year{"s" if years != 1 else ""} ago'


def truncate_text(text, length=50, suffix='...'):
    """
    Truncate text to a specified length.
    
    Args:
        text: The text to truncate
        length: Maximum length of the truncated text
        suffix: String to append to truncated text
        
    Returns:
        str: Truncated text
    """
    if text is None:
        return ''
        
    if len(text) <= length:
        return text
    else:
        return text[:length].rsplit(' ', 1)[0] + suffix


def slugify(text):
    """
    Convert text to a URL-friendly slug.
    
    Args:
        text: The text to slugify
        
    Returns:
        str: Slugified text
    """
    if text is None:
        return ''
        
    # Convert to lowercase and replace spaces with hyphens
    text = text.lower().replace(' ', '-')
    
    # Remove special characters
    text = re.sub(r'[^a-z0-9-]', '', text)
    
    # Replace multiple hyphens with a single hyphen
    text = re.sub(r'-+', '-', text)
    
    # Remove leading/trailing hyphens
    return text.strip('-') 