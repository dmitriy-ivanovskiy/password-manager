import os
import tempfile
import pytest
from app import create_app
from app.db import get_db_connection, init_database
import json

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create temporary directory for instance folder
    instance_path = tempfile.mkdtemp()
    
    # Create temporary database file
    db_path = os.path.join(instance_path, 'vault.db')
    
    # Create and initialize config file
    config_path = os.path.join(instance_path, 'config.json')
    empty_config = {
        "salt": None,
        "master_password_hash": None,
        "key": None
    }
    with open(config_path, 'w') as f:
        json.dump(empty_config, f)
    
    app = create_app({
        'TESTING': True,
        'DATABASE': db_path,
        'CONFIG_PATH': config_path,
        'SECRET_KEY': 'test',
        'WTF_CSRF_ENABLED': False,  # Disable CSRF for testing
        'SESSION_TYPE': 'filesystem',
        'PERMANENT_SESSION_LIFETIME': 1800,  # 30 minutes,
        'INSTANCE_PATH': instance_path
    })

    # Create the database and load test data
    with app.app_context():
        init_database()

    yield app

    # Clean up the temporary files
    for file in os.listdir(instance_path):
        os.unlink(os.path.join(instance_path, file))
    os.rmdir(instance_path)

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test CLI runner for the app."""
    return app.test_cli_runner()

@pytest.fixture
def auth(client):
    """Authentication helper class for tests."""
    class AuthActions:
        def __init__(self, client):
            self._client = client

        def register(self, master_password='test'):
            return self._client.post(
                '/auth/create_vault',
                data={'master_password': master_password, 'confirm_password': master_password}
            )

        def login(self, master_password='test'):
            return self._client.post(
                '/auth/login',
                data={'master_password': master_password}
            )

        def logout(self):
            return self._client.get('/auth/logout')

    return AuthActions(client) 