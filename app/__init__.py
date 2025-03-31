import os
from flask import Flask, redirect, url_for
import flask_session
from datetime import timedelta
from .config import Config
from .utils.logging import configure_logging
from .utils.template_helpers import register_template_helpers
from .utils.session import init_app as init_session
from .utils.db import init_app as init_db
from .utils.security import init_app as init_security, limiter
from .utils.cache import init_app as init_cache
from .errors import register_error_handlers
from . import cli

def create_app(test_config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__, 
                instance_relative_config=True,
                template_folder='../templates',
                static_folder='../static')
    
    # Load configuration
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    
    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
        os.makedirs(os.path.dirname(app.config['DB_PATH']), exist_ok=True)
    except OSError:
        pass
    
    # Initialize session interface
    flask_session.Session(app)
    
    # Setup logging
    configure_logging(app)
    
    # Register template helpers
    register_template_helpers(app)
    
    # Initialize core components
    init_db(app)
    init_session(app)
    init_cache(app)
    
    # Initialize security features (before blueprints)
    init_security(app)
    
    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.passwords import passwords_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(passwords_bp)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register CLI commands
    cli.init_app(app)
    
    # Default route
    @app.route('/')
    def index():
        return redirect(url_for('passwords.dashboard'))
    
    return app
