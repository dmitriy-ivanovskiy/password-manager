"""
Database utilities for the Password Manager application.

This module provides helper functions for database operations,
including initialization, session management, and common queries.
"""

import os
import json
import sqlite3
from flask import current_app, g
from contextlib import contextmanager
import uuid


def get_db():
    """
    Get a database connection from the Flask application context.
    
    Returns:
        sqlite3.Connection: Database connection
    """
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DB_PATH'],  # Using DB_PATH consistently
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        
        # Enable foreign keys
        g.db.execute('PRAGMA foreign_keys = ON')
    
    return g.db


def close_db(e=None):
    """
    Close the database connection if it exists.
    
    Args:
        e: Error that triggered the close (if any)
    """
    db = g.pop('db', None)
    
    if db is not None:
        db.close()


def init_db():
    """
    Initialize the database with the schema.
    """
    db = get_db()
    
    # Check if tables already exist
    result = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    
    # Only initialize if tables don't exist
    if result is None:
        with current_app.open_resource('schema.sql') as f:
            db.executescript(f.read().decode('utf8'))
            db.commit()


def init_app(app):
    """
    Register database functions with the Flask app.
    
    Args:
        app: Flask application
    """
    app.teardown_appcontext(close_db)
    
    # Create tables when app is initialized if they don't exist
    with app.app_context():
        init_db()


@contextmanager
def get_db_cursor():
    """
    Context manager for database cursor.
    
    Yields:
        sqlite3.Cursor: Database cursor
    """
    db = get_db()
    cursor = db.cursor()
    try:
        yield cursor
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        cursor.close()


def execute_query(query, parameters=(), one=False):
    """
    Execute a database query.
    
    Args:
        query (str): SQL query to execute
        parameters (tuple): Parameters for the query
        one (bool): Whether to fetch one or all results
        
    Returns:
        list or dict: Query results
    """
    with get_db_cursor() as cursor:
        cursor.execute(query, parameters)
        
        if one:
            return cursor.fetchone()
        return cursor.fetchall()


def execute_insert(query, parameters=()):
    """
    Execute an INSERT query and return the last inserted row id.
    
    Args:
        query (str): SQL INSERT query
        parameters (tuple): Parameters for the query
        
    Returns:
        int: Last inserted row id
    """
    with get_db_cursor() as cursor:
        cursor.execute(query, parameters)
        return cursor.lastrowid


def generate_uuid():
    """
    Generate a UUID string.
    
    Returns:
        str: UUID string
    """
    return str(uuid.uuid4())


def load_config():
    """
    Load configuration from the config file.
    
    Returns:
        dict: Configuration data
    """
    config_path = current_app.config['CONFIG_PATH']
    
    if not os.path.exists(config_path):
        # Create empty config file if it doesn't exist
        with open(config_path, 'w') as f:
            json.dump({'salt': None, 'master_password_hash': None, 'key': None}, f)
        
    with open(config_path, 'r') as f:
        return json.load(f)


def save_config(config_data):
    """
    Save configuration to the config file.
    
    Args:
        config_data (dict): Configuration data to save
    """
    config_path = current_app.config['CONFIG_PATH']
    
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=2)


def transaction():
    """
    Context manager for database transactions.
    
    Yields:
        sqlite3.Connection: Database connection
    """
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        raise e 
