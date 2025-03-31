"""
File handling utilities for the Password Manager application.

This module provides helper functions for common file operations,
such as securely saving uploaded files, parsing file formats,
and managing temporary files.
"""

import os
import uuid
import tempfile
import shutil
import json
import csv
import io
from werkzeug.utils import secure_filename
from flask import current_app


def get_safe_filename(filename):
    """
    Generate a safe filename by combining a secure version of the original
    filename with a UUID to ensure uniqueness.
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Safe filename
    """
    # Get a secure version of the original filename
    secure_name = secure_filename(filename)
    
    # Extract the file extension
    if '.' in secure_name:
        name, ext = os.path.splitext(secure_name)
    else:
        name, ext = secure_name, ''
    
    # Generate a UUID and combine with the original name
    unique_id = str(uuid.uuid4())[:8]
    safe_name = f"{name}_{unique_id}{ext}"
    
    return safe_name


def get_upload_path(filename, subdir=None):
    """
    Get the full path for an uploaded file.
    
    Args:
        filename (str): Filename
        subdir (str, optional): Subdirectory within uploads
        
    Returns:
        str: Full path to the file
    """
    # Get the base uploads directory
    uploads_dir = current_app.config.get('UPLOAD_FOLDER', 
                                        os.path.join(current_app.instance_path, 'uploads'))
    
    # Create the directory if it doesn't exist
    if subdir:
        target_dir = os.path.join(uploads_dir, subdir)
    else:
        target_dir = uploads_dir
        
    os.makedirs(target_dir, exist_ok=True)
    
    # Return the full path
    return os.path.join(target_dir, filename)


def save_uploaded_file(file_storage, subdir=None, use_safe_name=True):
    """
    Save an uploaded file.
    
    Args:
        file_storage: Flask FileStorage object
        subdir (str, optional): Subdirectory within uploads
        use_safe_name (bool): Whether to generate a safe filename
        
    Returns:
        str: Path to the saved file
    """
    if not file_storage:
        return None
        
    # Get the original filename
    original_filename = file_storage.filename
    
    # Generate a safe filename if requested
    if use_safe_name:
        filename = get_safe_filename(original_filename)
    else:
        filename = secure_filename(original_filename)
    
    # Get the full path
    filepath = get_upload_path(filename, subdir)
    
    # Save the file
    file_storage.save(filepath)
    
    return filepath


def create_temp_file(data=None, suffix=None, prefix=None, delete=True):
    """
    Create a temporary file.
    
    Args:
        data: Optional data to write to the file
        suffix (str, optional): File suffix
        prefix (str, optional): File prefix
        delete (bool): Whether to delete the file when closed
        
    Returns:
        tuple: (file object, filepath)
    """
    # Create a temporary file
    temp_file = tempfile.NamedTemporaryFile(suffix=suffix, prefix=prefix, delete=delete)
    
    # Write data to the file if provided
    if data is not None:
        if isinstance(data, str):
            temp_file.write(data.encode('utf-8'))
        else:
            temp_file.write(data)
        temp_file.flush()
    
    return temp_file, temp_file.name


def parse_csv_file(filepath, has_header=True, delimiter=','):
    """
    Parse a CSV file.
    
    Args:
        filepath (str): Path to the CSV file
        has_header (bool): Whether the file has a header row
        delimiter (str): CSV delimiter
        
    Returns:
        tuple: (headers, rows) if has_header is True, otherwise (None, rows)
    """
    headers = None
    rows = []
    
    with open(filepath, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter=delimiter)
        
        if has_header:
            headers = next(reader)
            
        for row in reader:
            rows.append(row)
    
    return headers, rows


def csv_to_dict_list(filepath, delimiter=','):
    """
    Parse a CSV file into a list of dictionaries.
    
    Args:
        filepath (str): Path to the CSV file
        delimiter (str): CSV delimiter
        
    Returns:
        list: List of dictionaries representing the CSV rows
    """
    result = []
    
    with open(filepath, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile, delimiter=delimiter)
        for row in reader:
            result.append(dict(row))
    
    return result


def dict_list_to_csv(data, fieldnames=None):
    """
    Convert a list of dictionaries to CSV data.
    
    Args:
        data (list): List of dictionaries
        fieldnames (list, optional): List of field names to include
        
    Returns:
        str: CSV data as a string
    """
    output = io.StringIO()
    
    if not fieldnames and data:
        fieldnames = data[0].keys()
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(data)
    
    return output.getvalue()


def load_json_file(filepath):
    """
    Load data from a JSON file.
    
    Args:
        filepath (str): Path to the JSON file
        
    Returns:
        dict: JSON data
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_json_file(data, filepath, indent=2):
    """
    Save data to a JSON file.
    
    Args:
        data: Data to save
        filepath (str): Path to the JSON file
        indent (int): JSON indentation
        
    Returns:
        bool: True if successful
    """
    # Ensure the directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=indent)
        
    return True


def ensure_directory(directory):
    """
    Ensure a directory exists.
    
    Args:
        directory (str): Directory path
        
    Returns:
        str: Directory path
    """
    os.makedirs(directory, exist_ok=True)
    return directory


def list_files(directory, pattern=None):
    """
    List files in a directory.
    
    Args:
        directory (str): Directory path
        pattern (str, optional): Glob pattern to match
        
    Returns:
        list: List of file paths
    """
    if not os.path.exists(directory):
        return []
        
    if pattern:
        import glob
        return glob.glob(os.path.join(directory, pattern))
    else:
        return [
            os.path.join(directory, f) 
            for f in os.listdir(directory) 
            if os.path.isfile(os.path.join(directory, f))
        ] 