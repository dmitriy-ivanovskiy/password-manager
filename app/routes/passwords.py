import logging
from flask import (
    Blueprint, render_template, redirect, url_for,
    request, session, flash, jsonify, current_app
)
from cryptography.fernet import Fernet

from app.routes.auth import login_required
from app.forms import PasswordForm, GeneratePasswordForm
from app.utils.crypto import decrypt_password, encrypt_password
from app.utils.password_gen import generate_password, check_password_strength
from app.db import (
    get_all_passwords, get_password_by_id,
    add_password as db_add_password,
    update_password as db_update_password,
    delete_password as db_delete_password,
    get_categories
)

# Create blueprint
passwords_bp = Blueprint('passwords', __name__)

# Get logger
logger = logging.getLogger(__name__)

@passwords_bp.route('/dashboard')
@login_required
def dashboard():
    """Render the dashboard page with decrypted passwords"""
    # First, check if we have the required session data
    if 'vault_key' not in session or 'user_id' not in session:
        logger.warning("Missing session data for dashboard access")
        session.clear()
        flash('Your session has expired. Please login again.', 'warning')
        return redirect(url_for('auth.login'))
    
    # Get request parameters
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    sort_by = request.args.get('sort_by', 'site')
    sort_order = request.args.get('sort_order', 'asc')
    
    # Apply filters if provided
    filters = {
        'sort_by': sort_by,
        'sort_order': sort_order
    }
    
    if search_query:
        filters['search'] = search_query
    
    if category_filter:
        filters['category'] = category_filter
    
    # Get all available categories for the filter dropdown
    categories = get_categories()
    
    # Get and decrypt passwords
    try:
        user_id = session.get('user_id')
        vault_key = session.get('vault_key')
        
        if not vault_key:
            # Clear session and send to login
            session.clear()
            flash('Your session has expired. Please login again.', 'warning')
            return redirect(url_for('auth.login'))
            
        # Retrieve passwords first, then decrypt them
        passwords = get_all_passwords(search_query, filters)
        
        if not passwords:
            # If no passwords, just return the empty dashboard
            logger.info("No passwords found for user")
            return render_template('dashboard.html', 
                               passwords=[], 
                               search_query=search_query, 
                               categories=categories,
                               category_filter=category_filter,
                               sort_by=sort_by,
                               sort_order=sort_order)
        
        # Convert SQLite Row objects to dictionaries for template use
        password_list = []
        for row in passwords:
            # Convert SQLite Row to dictionary
            password_dict = dict(row)
            try:
                password_dict['decrypted_password'] = decrypt_password(password_dict['encrypted_password'], vault_key)
                password_dict['name'] = password_dict['site']  # Make sure template has the expected 'name' field
                
                # Handle created_at date string if it exists
                if 'created_at' in password_dict and password_dict['created_at']:
                    # If it's already a string, leave it as is
                    if isinstance(password_dict['created_at'], str):
                        pass  # Keep as string
                
                password_list.append(password_dict)
            except Exception as e:
                logger.error(f"Failed to decrypt password ID {password_dict.get('id')}: {e}")
                password_dict['decrypted_password'] = "〈Decryption failed〉"
                password_dict['name'] = password_dict['site']
                password_list.append(password_dict)
    
        return render_template('dashboard.html', 
                               passwords=password_list, 
                               search_query=search_query, 
                               categories=categories,
                               category_filter=category_filter,
                               sort_by=sort_by,
                               sort_order=sort_order)
    except Exception as e:
        current_app.logger.error(f"Error in dashboard: {str(e)}")
        
        # If there's a vault issue, redirect to login
        if "vault" in str(e).lower() or "decrypt" in str(e).lower():
            session.clear()
            flash('There was an issue accessing your vault. Please login again.', 'warning')
            return redirect(url_for('auth.login'))
            
        flash('An error occurred while loading your passwords.', 'danger')
        return render_template('dashboard.html', passwords=[])

@passwords_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_password():
    """Add a new password entry"""
    form = PasswordForm()
    
    # Get all categories for the form
    categories = get_categories()
    
    # If form validation fails in a POST request, or if it's a GET request, show the form
    if request.method == 'GET':
        return render_template('add_password.html', form=form, categories=categories)
    
    # For POST requests, process the form data
    if not form.validate_on_submit():
        return render_template('add_password.html', form=form, categories=categories)
    
    try:
        # Get form data
        site = form.site.data
        username = form.username.data
        password = form.password.data
        
        # Get category from select element, not WTForms field
        category = request.form.get('category', 'General')
        
        # Skip "new" option which is used for the "Add new category" feature
        if category == 'new':
            category = 'General'
        
        # Check password strength and provide warning for weak passwords
        strength = check_password_strength(password)
        if strength['score'] < 2:
            flash(f"Warning: {strength.get('warning', 'Weak password')}.", "warning")
            # Continue with save despite weak password
        
        # Get vault key from session
        vault_key = session.get('vault_key')
        if not vault_key:
            logger.error("No vault key in session")
            flash("Session expired. Please login again.", "error")
            return redirect(url_for('auth.login'))
        
        # Encrypt password
        try:
            encrypted_password = encrypt_password(password, vault_key)
            
            # Add to database
            if db_add_password(site, username, encrypted_password, category):
                logger.info(f"Added new password for site: {site}")
                flash('Password added successfully', 'success')
                return redirect(url_for('passwords.dashboard'))
            else:
                logger.error(f"Database error when adding password for site: {site}")
                flash('Error adding password', 'error')
        except Exception as e:
            logger.error(f"Error encrypting password: {e}")
            flash("Error encrypting password", "error")
    except Exception as e:
        logger.error(f"Exception when adding password: {str(e)}")
        flash(f"Error adding password: {str(e)}", "error")
    
    return render_template('add_password.html', form=form, categories=categories)

@passwords_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_password(id):
    """Edit an existing password entry"""
    # Get encrypted password from database
    encrypted_password = get_password_by_id(id)
    if not encrypted_password:
        flash('Password not found', 'error')
        return redirect(url_for('passwords.dashboard'))
    
    # Convert SQLite Row to dictionary to avoid attribute access issues
    encrypted_password_dict = dict(encrypted_password)
    
    # Get all categories for the form
    categories = get_categories()
    
    # Get Fernet for decryption
    vault_key = session.get('vault_key')
    if not vault_key:
        logger.error("No vault key in session")
        flash("Session expired. Please login again.", "error")
        return redirect(url_for('auth.login'))
    
    # Initialize form
    form = PasswordForm()
    
    # For GET request, populate form with decrypted data
    if request.method == 'GET':
        try:
            # Use the decrypt_password function for consistency
            decrypted_password = decrypt_password(encrypted_password_dict['encrypted_password'], vault_key)
            
            form.site.data = encrypted_password_dict['site']
            form.username.data = encrypted_password_dict['username']
            form.password.data = decrypted_password
            
            # Safe access to category with fallback
            if 'category' in encrypted_password_dict and encrypted_password_dict['category']:
                form.category.data = encrypted_password_dict['category']
            else:
                form.category.data = 'General'
                
            return render_template('edit_password.html', form=form, password_id=id, categories=categories)
        except Exception as e:
            logger.error(f"Error decrypting password for edit: {e}")
            flash('Error decrypting password', 'error')
            return redirect(url_for('passwords.dashboard'))
    
    # For POST request, validate form and update password
    if form.validate_on_submit():
        try:
            site = form.site.data
            username = form.username.data
            password = form.password.data
            
            # Get category from select element, not WTForms field
            category = request.form.get('category', 'General')
            
            # Skip "new" option which is used for the "Add new category" feature
            if category == 'new':
                category = 'General'
            
            # Check password strength if changed
            try:
                current_password = decrypt_password(encrypted_password_dict['encrypted_password'], vault_key)
                if password != current_password:
                    strength = check_password_strength(password)
                    if strength['score'] < 2:
                        flash(f"Warning: {strength.get('warning', 'Weak password')}.", "warning")
                        # Continue with save despite weak password
            except Exception as e:
                logger.error(f"Error checking password strength: {e}")
            
            # Encrypt new password
            new_encrypted_password = encrypt_password(password, vault_key)
            
            # Update in database
            if db_update_password(id, site, username, new_encrypted_password, category):
                logger.info(f"Updated password for site: {site}")
                flash('Password updated successfully', 'success')
                return redirect(url_for('passwords.dashboard'))
            else:
                flash('Error updating password', 'error')
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            flash(f"Error updating password: {str(e)}", "error")
    
    # If validation failed or error occurred
    return render_template('edit_password.html', form=form, password_id=id, categories=categories)

@passwords_bp.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_password(id):
    """Delete a password entry"""
    # Check if the password exists
    password = get_password_by_id(id)
    if not password:
        flash('Password not found', 'error')
        return redirect(url_for('passwords.dashboard'))
    
    # For GET requests, show confirmation
    if request.method == 'GET':
        return render_template('confirm_delete.html', password=dict(password))
    
    # For POST requests, delete the password
    if db_delete_password(id):
        logger.info(f"Deleted password with ID: {id}")
        flash('Password deleted successfully', 'success')
    else:
        flash('Error deleting password', 'error')
    
    return redirect(url_for('passwords.dashboard'))

@passwords_bp.route('/generate_password_page')
@login_required
def generate_password_page():
    """Show password generation page"""
    form = GeneratePasswordForm()
    # Generate a default password
    password = generate_password()
    return render_template('generate_password.html', form=form, password=password)

@passwords_bp.route('/generate-password-ajax', methods=['POST'])
@login_required
def generate_password_ajax():
    """Generate a password and return as JSON (for AJAX requests)"""
    form = GeneratePasswordForm()
    
    if form.validate_on_submit():
        # Get options from form
        length = form.length.data if form.length.data else None
        include_uppercase = form.include_uppercase.data
        include_lowercase = form.include_lowercase.data
        include_digits = form.include_digits.data
        include_symbols = form.include_symbols.data
        
        # Generate password with options
        password = generate_password(
            length=length,
            include_uppercase=include_uppercase,
            include_lowercase=include_lowercase,
            include_digits=include_digits,
            include_symbols=include_symbols
        )
    else:
        # Use defaults if form invalid
        password = generate_password()
    
    # Get strength info
    strength = check_password_strength(password)
    
    return jsonify({
        'password': password,
        'strength': strength
    })

@passwords_bp.route('/check-password-strength', methods=['POST'])
@login_required
def check_password_strength_ajax():
    """Check password strength and return as JSON"""
    password = request.json.get('password', '')
    strength = check_password_strength(password)
    return jsonify(strength) 