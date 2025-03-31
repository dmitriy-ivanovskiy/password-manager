import pytest
from flask import g, session
from app.db import get_db_connection

def test_register(client):
    """Test registration."""
    response = client.post('/auth/create_vault', data={
        'master_password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    }, follow_redirects=True)
    assert b"Your vault has been created successfully! You can now add passwords." in response.data

def test_register_validate_input(client):
    """Test registration input validation."""
    # Test empty password
    response = client.post('/auth/create_vault', data={
        'master_password': '',
        'confirm_password': ''
    }, follow_redirects=True)
    assert b"Master password is required" in response.data

    # Test password mismatch
    response = client.post('/auth/create_vault', data={
        'master_password': 'TestPassword123!',
        'confirm_password': 'DifferentPassword123!'
    }, follow_redirects=True)
    assert b"Passwords must match" in response.data

def test_login(client):
    """Test login."""
    # First register
    client.post('/auth/create_vault', data={
        'master_password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    })
    
    # Then login
    response = client.post('/auth/login', data={
        'master_password': 'TestPassword123!'
    }, follow_redirects=True)
    assert b"Login successful" in response.data

def test_login_validate_input(client):
    """Test login input validation."""
    # First create a vault
    client.post('/auth/create_vault', data={
        'master_password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    })
    
    # Test empty password
    response = client.post('/auth/login', data={
        'master_password': ''
    }, follow_redirects=True)
    assert b"Master password is required" in response.data
    
    # Test incorrect password
    response = client.post('/auth/login', data={
        'master_password': 'WrongPassword123!'
    }, follow_redirects=True)
    assert b"Incorrect master password" in response.data

def test_logout(client):
    """Test logout."""
    # First register and login
    client.post('/auth/create_vault', data={
        'master_password': 'TestPassword123!',
        'confirm_password': 'TestPassword123!'
    })
    client.post('/auth/login', data={
        'master_password': 'TestPassword123!'
    })
    
    # Then logout
    response = client.get('/auth/logout', follow_redirects=True)
    assert b"You have been logged out" in response.data