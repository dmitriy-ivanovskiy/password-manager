import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask


def configure_logging(app: Flask) -> None:
    """
    Configure logging for the application.
    
    Args:
        app: Flask application instance
    """
    if not os.path.exists('logs'):
        os.makedirs('logs', exist_ok=True)
    
    # Get log level and file from config
    log_level = app.config.get('LOG_LEVEL', 'INFO')
    log_file = app.config.get('LOG_FILE', 'logs/password_manager.log')
    
    # Set up format for logs
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    
    # Configure root logger for basic setup
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Only add file handler if not in debug mode
    if not app.debug:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10240,
            backupCount=10
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(getattr(logging, log_level))
        
        # Add handlers to app logger
        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, log_level))
        
        # Log startup
        app.logger.info('Password Manager startup')
    
    # Add filters and other log configuration
    add_sensitive_data_filter(app.logger)


def add_sensitive_data_filter(logger):
    """
    Add a filter to redact sensitive data in logs.
    
    Args:
        logger: Logger to add filter to
    """
    class SensitiveDataFilter(logging.Filter):
        def filter(self, record):
            # Check if record contains passwords or other sensitive data
            # and redact them if necessary
            if hasattr(record, 'msg') and isinstance(record.msg, str):
                # Redact potential passwords
                if 'password' in record.msg.lower():
                    record.msg = record.msg.replace(
                        record.msg.split('password')[1], 
                        ' [REDACTED]'
                    )
                    
                # Redact potential API keys or tokens
                for keyword in ['api_key', 'token', 'secret']:
                    if keyword in record.msg.lower():
                        record.msg = record.msg.replace(
                            record.msg.split(keyword)[1], 
                            ' [REDACTED]'
                        )
            return True
            
    logger.addFilter(SensitiveDataFilter())


def get_logger(name):
    """
    Get a logger with the specified name.
    
    Args:
        name: Name of the logger
        
    Returns:
        A configured logger instance
    """
    logger = logging.getLogger(name)
    add_sensitive_data_filter(logger)
    return logger 