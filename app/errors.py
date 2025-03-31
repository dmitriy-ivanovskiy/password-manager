"""
Error handlers for the application.
"""
from flask import render_template, Blueprint

# Create a blueprint for error handlers
bp = Blueprint('errors', __name__)

@bp.app_errorhandler(404)
def page_not_found(e):
    """Handle 404 Page Not Found errors."""
    return render_template('404.html'), 404

@bp.app_errorhandler(500)
def internal_server_error(e):
    """Handle 500 Internal Server errors."""
    return render_template('500.html'), 500

@bp.app_errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors."""
    return render_template('403.html'), 403

@bp.app_errorhandler(401)
def unauthorized(e):
    """Handle 401 Unauthorized errors."""
    return render_template('401.html'), 401

def register_error_handlers(app):
    """Register the error handlers with the app."""
    app.register_blueprint(bp) 