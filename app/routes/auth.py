import os
import json
import logging
import base64
import shutil
import pyotp
import qrcode
import io
from flask import (
    Blueprint, render_template, redirect, url_for,
    request, session, flash, current_app
)
from functools import wraps
from app.utils.security import limiter  # Updated import
from datetime import datetime
import zipfile
import tempfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.forms import LoginForm, CreateVaultForm, TwoFactorForm, SetupTwoFactorForm
from app.utils.crypto import (
    generate_salt, derive_key, hash_master_password,
    encrypt_config, decrypt_config
)
from app.db import init_database

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

# Get logger
logger = logging.getLogger(__name__)

# Authentication check decorator
def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'encryption_key' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def two_factor_required(f):
    """Decorator to check if 2FA is completed"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'encryption_key' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('auth.login'))
        
        # Skip if 2FA is not enabled or already verified
        if not session.get('2fa_enabled', False) or session.get('2fa_verified', False):
            return f(*args, **kwargs)
        
        # Store the original destination
        session['next_url'] = request.path
        
        flash('Please complete two-factor authentication', 'warning')
        return redirect(url_for('auth.two_factor_verify'))
    return decorated_function

def check_config_exists():
    """Check if the configuration file exists and has valid data"""
    if not os.path.exists(current_app.config['CONFIG_PATH']):
        return False
    
    try:
        # Check if config is encrypted
        config_key = os.environ.get('CONFIG_KEY')
        if config_key:
            with open(current_app.config['CONFIG_PATH'], 'r') as f:
                encrypted_data = f.read()
            config = decrypt_config(encrypted_data, config_key)
        else:
            with open(current_app.config['CONFIG_PATH'], 'r') as f:
                config = json.load(f)
        
        # Check if config has valid data
        return (config.get('salt') is not None and 
                config.get('master_password_hash') is not None)
    except Exception:
        return False

def create_config(master_password):
    """
    Create a new configuration file with a new salt and hashed master password
    
    Args:
        master_password (str): Master password to hash and store
    """
    salt = generate_salt()
    hashed_password = hash_master_password(master_password, salt)
    
    config = {
        'salt': base64.urlsafe_b64encode(salt).decode(),
        'master_password_hash': hashed_password,
        '2fa_enabled': False,
        '2fa_secret': None
    }
    
    try:
        # Encrypt the config if a CONFIG_KEY is set
        config_key = os.environ.get('CONFIG_KEY')
        if config_key:
            encrypted_config = encrypt_config(config, config_key)
            with open(current_app.config['CONFIG_PATH'], 'w') as f:
                f.write(encrypted_config)
            logger.info("Created encrypted config file")
        else:
            # Save unencrypted (still contains only hashed password)
            with open(current_app.config['CONFIG_PATH'], 'w') as f:
                json.dump(config, f)
            logger.info("Created config file")
    except Exception as e:
        logger.error(f"Error saving config file: {e}")
        raise

def get_config():
    """
    Get the configuration from the config file
    
    Returns:
        dict: Configuration data or None if error
    """
    if not check_config_exists():
        logger.warning("Config file does not exist")
        return None
    
    try:
        # Check if config is encrypted
        config_key = os.environ.get('CONFIG_KEY')
        if config_key:
            with open(current_app.config['CONFIG_PATH'], 'r') as f:
                encrypted_data = f.read()
            config = decrypt_config(encrypted_data, config_key)
        else:
            with open(current_app.config['CONFIG_PATH'], 'r') as f:
                config = json.load(f)
        
        # Decode the salt from base64
        config['salt'] = base64.urlsafe_b64decode(config['salt'])
        return config
    except Exception as e:
        logger.error(f"Error reading config: {e}")
        return None

def update_config(config):
    """
    Update the configuration file
    
    Args:
        config (dict): Configuration data to save
    """
    # Make a copy to avoid modifying the original
    config_copy = config.copy()
    
    # Convert salt to base64 string for storage
    if isinstance(config_copy['salt'], bytes):
        config_copy['salt'] = base64.urlsafe_b64encode(config_copy['salt']).decode()
    
    # Encrypt the config if a CONFIG_KEY is set
    config_key = os.environ.get('CONFIG_KEY')
    if config_key:
        encrypted_config = encrypt_config(config_copy, config_key)
        with open(current_app.config['CONFIG_PATH'], 'w') as f:
            f.write(encrypted_config)
    else:
        # Save unencrypted
        with open(current_app.config['CONFIG_PATH'], 'w') as f:
            json.dump(config_copy, f)
    
    logger.info("Updated configuration")

# Define custom rate limit exceeded error handler
@auth_bp.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors with a styled page"""
    logger.warning("Rate limit exceeded for user")
    return render_template('errors/rate_limit.html', 
                           retry_after=getattr(e, 'retry_after', 60)), 429

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please try again in a minute.")
def login():
    """Handle user login"""
    form = LoginForm()
    
    # Check if we just reset the vault to avoid showing "session expired" message
    just_reset = session.pop('just_reset', False)
    
    # If GET request or form validation fails, show the login page
    if request.method == 'GET' or not form.validate_on_submit():
        return render_template('login.html', form=form)
    
    # Check if vault exists
    if not check_config_exists():
        logger.warning("Login attempt but no vault exists")
        flash("No vault exists. Please create a new vault first.", "error")
        return redirect(url_for('auth.create_vault'))
    
    # Get master password from form
    master_password = form.master_password.data
    
    # Get configuration
    config = get_config()
    if not config:
        logger.error("Failed to load configuration")
        flash("Configuration error. Please recreate your vault.", "error")
        return render_template('login.html', form=form)
    
    # Verify master password
    try:
        salt = config['salt']
        stored_hash = config['master_password_hash']
        provided_hash = hash_master_password(master_password, salt)
        
        if provided_hash != stored_hash:
            logger.warning("Login attempt with incorrect password")
            flash("Incorrect master password", "error")
            return render_template('login.html', form=form)
        
        # Derive key for Fernet encryption
        key = derive_key(master_password, salt)
        
        # Test if the key is valid for Fernet
        try:
            test_fernet = Fernet(key)
            # Test encryption/decryption
            test_data = test_fernet.encrypt(b"test")
            test_fernet.decrypt(test_data)
            logger.debug("Fernet key validated successfully")
        except Exception as e:
            logger.error(f"Fernet key validation failed: {e}")
            # Generate a secure key for the session instead
            key = Fernet.generate_key()
            logger.warning("Using generated Fernet key for session")
        
        # Set the key in the session (ensure it's decoded properly)
        if isinstance(key, bytes):
            # Store both raw bytes and decoded string version for different scenarios
            session['encryption_key'] = key.decode()
            # Use a safe string format for vault_key to avoid serialization issues
            session['vault_key'] = key.decode()
        else:
            # If somehow key is already a string, ensure we have consistent format
            session['encryption_key'] = key
            session['vault_key'] = key
            
        session['user_id'] = config.get('user_id', 1)
        
        # Check if 2FA is enabled
        if config.get('2fa_enabled', False):
            session['2fa_enabled'] = True
            session['2fa_verified'] = False
            session['2fa_secret'] = config.get('2fa_secret')
            return redirect(url_for('auth.two_factor_verify'))
        
        # Login successful - set flash message
        flash("Login successful", "success")
        
        # Redirect to dashboard
        return redirect(url_for('passwords.dashboard'))
    except Exception as e:
        logger.error(f"Error during login: {e}")
        flash(f"An error occurred during login", "error")
        return render_template('login.html', form=form)

@auth_bp.route('/two-factor-verify', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Too many 2FA attempts. Please try again in a minute.")
def two_factor_verify():
    """Verify 2FA code"""
    # Ensure user is logged in but not 2FA verified
    if 'encryption_key' not in session or not session.get('2fa_enabled'):
        return redirect(url_for('auth.login'))
    
    if session.get('2fa_verified', False):
        return redirect(url_for('passwords.dashboard'))
    
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        # Get entered code and secret
        entered_code = form.code.data
        secret = session.get('2fa_secret')
        
        # Verify the code
        totp = pyotp.TOTP(secret)
        if totp.verify(entered_code):
            session['2fa_verified'] = True
            logger.info("Two-factor authentication successful")
            
            # Redirect to original destination or dashboard
            next_url = session.pop('next_url', url_for('passwords.dashboard'))
            return redirect(next_url)
        else:
            logger.warning("Invalid two-factor code")
            flash("Invalid two-factor code", "error")
    
    return render_template('two_factor_verify.html', form=form)

@auth_bp.route('/setup-two-factor', methods=['GET', 'POST'])
@login_required
def setup_two_factor():
    """Set up two-factor authentication"""
    form = SetupTwoFactorForm()
    
    # Get configuration
    config = get_config()
    if not config:
        flash("Configuration error", "error")
        return redirect(url_for('passwords.dashboard'))
    
    # Check if 2FA is already enabled
    if config.get('2fa_enabled', False) and request.method == 'GET':
        flash("Two-factor authentication is already enabled", "info")
        return redirect(url_for('passwords.dashboard'))
    
    # Generate new secret on GET request
    if request.method == 'GET':
        secret = pyotp.random_base32()
        session['temp_2fa_secret'] = secret
        
        # Generate QR code
        totp = pyotp.TOTP(secret)
        url = totp.provisioning_uri(
            "Password Manager", issuer_name="Password Manager"
        )
        
        # Create QR code image
        img = qrcode.make(url)
        img_io = io.BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        img_data = base64.b64encode(img_io.getvalue()).decode()
        
        return render_template(
            'setup_two_factor.html',
            form=form,
            secret=secret,
            qr_code=img_data
        )
    
    # Handle form submission
    if form.validate_on_submit():
        # Get entered code and temp secret
        entered_code = form.code.data
        secret = session.get('temp_2fa_secret')
        
        # Verify the code
        totp = pyotp.TOTP(secret)
        if totp.verify(entered_code):
            # Update configuration with 2FA settings
            config['2fa_enabled'] = True
            config['2fa_secret'] = secret
            update_config(config)
            
            # Update session
            session['2fa_enabled'] = True
            session['2fa_verified'] = True
            session.pop('temp_2fa_secret', None)
            
            logger.info("Two-factor authentication setup successful")
            flash("Two-factor authentication has been enabled", "success")
            return redirect(url_for('passwords.dashboard'))
        else:
            logger.warning("Invalid two-factor code during setup")
            flash("Invalid code. Please try again", "error")
    
    # Re-generate QR code for the form
    secret = session.get('temp_2fa_secret')
    totp = pyotp.TOTP(secret)
    url = totp.provisioning_uri("Password Manager", issuer_name="Password Manager")
    img = qrcode.make(url)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    img_data = base64.b64encode(img_io.getvalue()).decode()
    
    return render_template(
        'setup_two_factor.html',
        form=form,
        secret=secret,
        qr_code=img_data
    )

@auth_bp.route('/disable-two-factor', methods=['POST'])
@login_required
@two_factor_required
def disable_two_factor():
    """Disable two-factor authentication"""
    # Get configuration
    config = get_config()
    if not config:
        flash("Configuration error", "error")
        return redirect(url_for('passwords.dashboard'))
    
    # Update configuration
    config['2fa_enabled'] = False
    config['2fa_secret'] = None
    update_config(config)
    
    # Update session
    session['2fa_enabled'] = False
    session['2fa_verified'] = False
    session.pop('2fa_secret', None)
    
    logger.info("Two-factor authentication disabled")
    flash("Two-factor authentication has been disabled", "success")
    return redirect(url_for('passwords.dashboard'))

@auth_bp.route('/create_vault', methods=['GET', 'POST'])
@limiter.limit("10 per hour", error_message="Too many vault creation attempts. Please try again later.")
def create_vault():
    """Handle creation of a new vault"""
    # Check if vault already exists
    if check_config_exists():
        flash("A vault already exists. Please login or reset your vault first.", "warning")
        return redirect(url_for('auth.login'))
    
    form = CreateVaultForm()
    
    # Check if we just reset the vault to maintain the success message
    just_reset = session.get('just_reset', False)
    
    # Check if this is just the GET request
    if request.method == 'GET':
        return render_template('create_vault.html', form=form, just_reset=just_reset)
    
    # Validate the form
    if not form.validate_on_submit():
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "error")
        return render_template('create_vault.html', form=form)
    
    # Get form data
    master_password = form.master_password.data
    
    success = True
    try:
        # Step 1: Create configuration with salt and hashed password
        create_config(master_password)
        logger.info("Config created successfully")
        
        # Step 2: Initialize the database
        init_database()
        logger.info("Database initialized successfully")
        
        # Step 3: Derive key for encryption
        config = get_config()
        if not config:
            raise Exception("Failed to load configuration after creation")
        
        key = derive_key(master_password, config['salt'])
        
        # Step 4: Store the key in the session
        session['encryption_key'] = key.decode()
        session['vault_key'] = key
        session['user_id'] = config.get('user_id', 1)
        
        flash("Your vault has been created successfully! You can now add passwords.", "success")
        return redirect(url_for('passwords.dashboard'))
    except Exception as e:
        success = False
        logger.error(f"Error creating vault: {e}")
        # Clean up partial creation if failure
        if os.path.exists(current_app.config['CONFIG_PATH']):
            os.remove(current_app.config['CONFIG_PATH'])
        if os.path.exists(current_app.config['DB_PATH']):
            os.remove(current_app.config['DB_PATH'])
        
        flash(f"Error creating vault: {str(e)}", "error")
        return render_template('create_vault.html', form=form)

@auth_bp.route('/logout')
def logout():
    """Log user out by clearing the session"""
    session.clear()
    logger.info("User logged out")
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/export-vault')
@login_required
def export_vault():
    """Create and download a backup of the vault"""
    try:
        # Create a temporary directory for backup files
        temp_dir = tempfile.mkdtemp()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = os.path.join(temp_dir, f'password_manager_backup_{timestamp}')
        os.makedirs(backup_dir)
        
        # Create metadata file with backup information
        metadata = {
            'backup_date': datetime.now().isoformat(),
            'app_version': '1.0.0',  # Add version tracking
            'backup_format_version': '1.0',
            'timestamp': timestamp,
            'user_info': {
                '2fa_enabled': session.get('2fa_enabled', False)
            }
        }
        
        with open(os.path.join(backup_dir, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Copy vault database and config
        if os.path.exists(current_app.config['DB_PATH']):
            shutil.copy2(current_app.config['DB_PATH'], os.path.join(backup_dir, 'vault.db'))
        
        if os.path.exists(current_app.config['CONFIG_PATH']):
            shutil.copy2(current_app.config['CONFIG_PATH'], os.path.join(backup_dir, 'config.json'))
        
        # Create a README with instructions
        readme_content = """# Password Manager Vault Backup

## Important Information
- This backup contains your encrypted password vault and configuration
- You will need your master password to access this data
- Keep this backup in a secure location

## Restoring Your Backup
1. Install the Password Manager application
2. Stop the application if it's running
3. Locate your application's instance directory
4. Replace the 'vault.db' and 'config.json' files with the ones from this backup
5. Restart the application and log in with your master password

## Need Help?
If you have trouble restoring your backup, please refer to the documentation or contact support.

Date of backup: {backup_date}
"""
        with open(os.path.join(backup_dir, 'README.md'), 'w') as f:
            f.write(readme_content.format(backup_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        
        # Create a ZIP file of the backup directory
        zip_path = os.path.join(temp_dir, f'vault_backup_{timestamp}.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(backup_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, temp_dir)
                    zipf.write(file_path, arcname)
        
        logger.info(f"Vault backup created: {zip_path}")
        
        # Return the ZIP file as a download
        return send_file(
            zip_path,
            as_attachment=True,
            download_name=f'vault_backup_{timestamp}.zip',
            mimetype='application/zip'
        )
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        flash("Error creating backup", "error")
        return redirect(url_for('passwords.dashboard'))

@auth_bp.route('/reset-vault', methods=['POST'])
@limiter.limit("3 per hour", error_message="Too many vault reset attempts. Please try again later.")
def reset_vault():
    """Reset the vault by deleting the configuration and database"""
    try:
        # Check if the vault exists
        if not check_config_exists():
            flash('No vault exists to reset.', 'error')
            return redirect(url_for('auth.create_vault'))
        
        # Delete the config file and vault database
        config_path = current_app.config['CONFIG_PATH']
        db_path = current_app.config['DB_PATH']
        
        logger.info(f"Attempting to reset vault. Config path: {config_path}, DB path: {db_path}")
        
        if os.path.exists(config_path):
            os.remove(config_path)
            logger.info("Config file deleted during vault reset")
        else:
            logger.warning("Config file not found during reset")
        
        if os.path.exists(db_path):
            os.remove(db_path)
            logger.info("Database file deleted during vault reset")
        else:
            logger.warning("Database file not found during reset")
        
        # Also clear the session
        session.clear()
        
        # Redirect to create vault page with success message
        flash('Your vault has been reset successfully.', 'success')
        
        # This prevents the "session expired" message
        session['just_reset'] = True
        
        # Use redirect with a query parameter to help client-side detection of reset
        return redirect(url_for('auth.create_vault', from_reset=1))
    except Exception as e:
        logger.error(f"Error during vault reset: {e}")
        flash(f"Error resetting vault: {str(e)}", "error")
        return redirect(url_for('auth.login')) 
