import pytest
from flask import g, session
from app.db import get_db_connection

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    from app import create_app
    from app.db import init_database
    
    app = create_app({
        'TESTING': True,
        'DATABASE': ':memory:',
        'SECRET_KEY': 'test',
        'WTF_CSRF_ENABLED': False,
        'CONFIG_PATH': ':memory:',
        'DB_PATH': ':memory:',
        'SESSION_TYPE': 'filesystem'
    })

    # Create tables
    with app.app_context():
        init_database()
    
    yield app

def test_add_password(client, auth):
    """Test adding a new password."""
    # First register and login
    auth.register('TestPassword123!')
    auth.login('TestPassword123!')

    # Add a new password
    response = client.post('/passwords/add', data={
        'site': 'example.com',
        'username': 'testuser',
        'password': 'SecurePass123!'
    }, follow_redirects=True)
    assert b"Password added successfully" in response.data

def test_edit_password(client, auth):
    """Test editing an existing password."""
    # First add a password
    auth.register('TestPassword123!')
    auth.login('TestPassword123!')
    
    # Add a password
    client.post('/passwords/add', data={
        'site': 'example.com',
        'username': 'testuser',
        'password': 'SecurePass123!'
    })

    # Get the password ID from the database
    with client.application.app_context():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM passwords LIMIT 1')
            password = cursor.fetchone()
            password_id = password['id']

    # Edit the password
    response = client.post(f'/passwords/edit/{password_id}', data={
        'site': 'example.com',
        'username': 'newuser',
        'password': 'NewSecurePass123!'
    }, follow_redirects=True)
    assert b"Password updated successfully" in response.data

def test_delete_password(client, auth):
    """Test deleting a password."""
    # First add a password
    auth.register('TestPassword123!')
    auth.login('TestPassword123!')
    
    # Add a password
    client.post('/passwords/add', data={
        'site': 'example.com',
        'username': 'testuser',
        'password': 'SecurePass123!'
    })

    # Get the password ID from the database
    with client.application.app_context():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM passwords LIMIT 1')
            password = cursor.fetchone()
            password_id = password['id']

    # Delete the password
    response = client.post(f'/passwords/delete/{password_id}', follow_redirects=True)
    assert b"Password deleted successfully" in response.data

def test_generate_password(client, auth):
    """Test password generation."""
    # First login
    auth.register('TestPassword123!')
    auth.login('TestPassword123!')

    response = client.get('/passwords/generate_password_page')
    assert response.status_code == 200
    assert b"Generate Password" in response.data

def test_search_passwords(client, auth):
    """Test password search functionality."""
    # First add some passwords
    auth.register('TestPassword123!')
    auth.login('TestPassword123!')
    
    # Add two passwords
    client.post('/passwords/add', data={
        'site': 'example.com',
        'username': 'testuser',
        'password': 'SecurePass123!'
    })
    client.post('/passwords/add', data={
        'site': 'test.com',
        'username': 'testuser2',
        'password': 'AnotherPass123!'
    })

    # Search for passwords
    response = client.get('/passwords/dashboard?search=example')
    assert b"example.com" in response.data
    assert b"test.com" not in response.data 