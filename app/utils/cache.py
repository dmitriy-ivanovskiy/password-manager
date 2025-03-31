"""
Caching utilities for the Password Manager application.

This module provides functions for caching data to improve performance,
including simple in-memory caching and function result caching.
"""

from functools import wraps
from datetime import datetime, timedelta
from flask import current_app
import threading
import time

# Simple in-memory cache
_cache = {}
_cache_lock = threading.RLock()


def cache_get(key, default=None):
    """
    Get a value from the cache.
    
    Args:
        key (str): Cache key
        default: Default value if key not found
        
    Returns:
        Any: Cached value or default
    """
    with _cache_lock:
        cache_item = _cache.get(key)
        
        if cache_item is None:
            return default
        
        # Check if the item has expired
        if cache_item['expiry'] and cache_item['expiry'] < datetime.utcnow():
            del _cache[key]
            return default
            
        return cache_item['value']


def cache_set(key, value, timeout=300):
    """
    Set a value in the cache.
    
    Args:
        key (str): Cache key
        value: Value to cache
        timeout (int): Cache timeout in seconds (0 for no expiry)
    """
    with _cache_lock:
        expiry = None
        if timeout > 0:
            expiry = datetime.utcnow() + timedelta(seconds=timeout)
            
        _cache[key] = {
            'value': value,
            'expiry': expiry,
            'created': datetime.utcnow()
        }


def cache_delete(key):
    """
    Delete a value from the cache.
    
    Args:
        key (str): Cache key
    """
    with _cache_lock:
        if key in _cache:
            del _cache[key]


def cache_clear():
    """
    Clear all values from the cache.
    """
    with _cache_lock:
        _cache.clear()


def memoize(timeout=300):
    """
    Decorator to cache function results.
    
    Args:
        timeout (int): Cache timeout in seconds
        
    Returns:
        function: Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create a cache key from the function name and arguments
            key = f"memoize:{func.__module__}.{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get cached result
            result = cache_get(key)
            if result is not None:
                return result
                
            # Call the function and cache the result
            result = func(*args, **kwargs)
            cache_set(key, result, timeout)
            return result
            
        return wrapper
    return decorator


def clear_memoized(func, *args, **kwargs):
    """
    Clear the cache for a memoized function.
    
    Args:
        func: The memoized function
        *args, **kwargs: Optional arguments to clear specific cache entries
    """
    if args or kwargs:
        key = f"memoize:{func.__module__}.{func.__name__}:{str(args)}:{str(kwargs)}"
        cache_delete(key)
    else:
        # Clear all cache entries for this function
        prefix = f"memoize:{func.__module__}.{func.__name__}:"
        with _cache_lock:
            for key in list(_cache.keys()):
                if key.startswith(prefix):
                    del _cache[key]


def timed_cache(timeout=60):
    """
    Decorator for caching a value for a specified period of time.
    
    Args:
        timeout (int): Cache timeout in seconds
        
    Returns:
        function: Decorator function
    """
    def decorator(func):
        cached_value = None
        last_update = None
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal cached_value, last_update
            
            # Check if we need to update the cache
            current_time = time.time()
            if cached_value is None or last_update is None or current_time - last_update > timeout:
                cached_value = func(*args, **kwargs)
                last_update = current_time
                
            return cached_value
        
        return wrapper
    return decorator


def init_app(app):
    """
    Initialize the cache module with the Flask app.
    
    Args:
        app: Flask application
    """
    # Periodically clean expired cache entries
    def cache_cleanup():
        """Remove expired cache entries."""
        with _cache_lock:
            now = datetime.utcnow()
            expired_keys = [
                key for key, item in _cache.items() 
                if item['expiry'] and item['expiry'] < now
            ]
            
            for key in expired_keys:
                del _cache[key]
                
    # Register a function to clean up the cache periodically if in production
    if not app.debug:
        @app.before_request
        def cleanup_cache():
            # Only run cleanup occasionally (1% of requests)
            import random
            if random.random() < 0.01:
                cache_cleanup() 