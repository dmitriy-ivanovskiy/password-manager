import sqlite3
import logging
import os
from contextlib import contextmanager
from app.config import Config

logger = logging.getLogger(__name__)

@contextmanager
def get_db_connection():
    """
    Context manager for database connections with error handling
    
    Yields:
        sqlite3.Connection: Database connection object
        
    Raises:
        Exception: If connection fails
    """
    conn = None
    try:
        conn = sqlite3.connect(Config.DB_PATH)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Unexpected error with database: {e}")
        raise
    finally:
        if conn:
            conn.close()

def init_database():
    """
    Initialize the SQLite database with the passwords table
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # First check if database exists and has data
        if os.path.exists(Config.DB_PATH):
            logger.warning(f"Database already exists at {Config.DB_PATH}")
            # Optionally, you could delete it here to ensure a clean slate
            os.remove(Config.DB_PATH)
            logger.info("Removed existing database for clean initialization")
            
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            logger.info("Database initialized successfully")
            return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return False

def get_all_passwords(search_query=None, filters=None):
    """
    Get all passwords from the database, optionally filtered by search query and filters
    
    Args:
        search_query (str, optional): Text to search for in site or username
        filters (dict, optional): Additional filters like sort_by, sort_order, category
        
    Returns:
        list: List of database row objects
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            query_parts = ["SELECT * FROM passwords"]
            params = []
            where_clauses = []
            
            # Apply search filter if provided
            if search_query:
                where_clauses.append("(site LIKE ? OR username LIKE ?)")
                search_param = f"%{search_query}%"
                params.extend([search_param, search_param])
            
            # Apply category filter if provided
            if filters and 'category' in filters and filters['category']:
                where_clauses.append("category = ?")
                params.append(filters['category'])
            
            # Combine WHERE clauses if any
            if where_clauses:
                query_parts.append("WHERE " + " AND ".join(where_clauses))
            
            # Apply sorting
            if filters and 'sort_by' in filters:
                # Validate sort column to prevent SQL injection
                valid_columns = ['id', 'site', 'username', 'category', 'created_at', 'updated_at']
                sort_by = filters['sort_by'] if filters['sort_by'] in valid_columns else 'site'
                
                # Validate sort order
                sort_order = filters.get('sort_order', 'ASC').upper()
                if sort_order not in ['ASC', 'DESC']:
                    sort_order = 'ASC'
                
                query_parts.append(f"ORDER BY {sort_by} {sort_order}")
            else:
                query_parts.append("ORDER BY site ASC")
            
            # Construct the final query
            query = " ".join(query_parts)
            cursor.execute(query, params)
                
            return cursor.fetchall()
    except Exception as e:
        logger.error(f"Error retrieving passwords: {e}")
        return []

def get_password_by_id(password_id):
    """
    Get a single password from the database by ID
    
    Args:
        password_id (int): Record ID
        
    Returns:
        sqlite3.Row or None: Password record or None if not found
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM passwords WHERE id = ?", (password_id,))
            return cursor.fetchone()
    except Exception as e:
        logger.error(f"Error retrieving password by ID: {e}")
        return None

def get_categories():
    """
    Get all unique categories from the passwords table
    
    Returns:
        list: List of category names
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT category FROM passwords ORDER BY category")
            categories = [row[0] for row in cursor.fetchall()]
            return categories
    except Exception as e:
        logger.error(f"Error retrieving categories: {e}")
        return ['General']

def add_password(site, username, encrypted_password, category='General'):
    """
    Add a new password entry to the database
    
    Args:
        site (str): Website or service name
        username (str): Username for the site
        encrypted_password (str): Encrypted password
        category (str, optional): Category for organization
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO passwords (site, username, encrypted_password, category) VALUES (?, ?, ?, ?)",
                (site, username, encrypted_password, category)
            )
        logger.info(f"Added new password entry for site: {site}")
        return True
    except Exception as e:
        logger.error(f"Error adding password: {e}")
        return False

def update_password(password_id, site, username, encrypted_password, category=None):
    """
    Update an existing password entry in the database
    
    Args:
        password_id (int): Record ID
        site (str): Website or service name
        username (str): Username for the site
        encrypted_password (str): Encrypted password
        category (str, optional): Category for organization
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Only update category if provided
            if category is not None:
                cursor.execute(
                    "UPDATE passwords SET site = ?, username = ?, encrypted_password = ?, category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (site, username, encrypted_password, category, password_id)
                )
            else:
                cursor.execute(
                    "UPDATE passwords SET site = ?, username = ?, encrypted_password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (site, username, encrypted_password, password_id)
                )
                
            if cursor.rowcount == 0:
                logger.warning(f"No record found to update for ID: {password_id}")
                return False
        logger.info(f"Updated password entry for site: {site}")
        return True
    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return False

def delete_password(password_id):
    """
    Delete a password entry from the database
    
    Args:
        password_id (int): Record ID
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
            if cursor.rowcount == 0:
                logger.warning(f"No record found to delete for ID: {password_id}")
                return False
        logger.info(f"Deleted password entry with ID: {password_id}")
        return True
    except Exception as e:
        logger.error(f"Error deleting password: {e}")
        return False 
