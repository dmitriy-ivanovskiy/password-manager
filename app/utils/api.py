"""
API response formatting utilities.

This module provides standardized functions for creating consistent
API responses throughout the application.
"""
from flask import jsonify
from http import HTTPStatus


def api_response(data=None, message=None, status_code=HTTPStatus.OK, errors=None, meta=None):
    """
    Create a standardized API response.
    
    Args:
        data (any, optional): The main response data
        message (str, optional): A message describing the response
        status_code (HTTPStatus, optional): HTTP status code
        errors (list or dict, optional): Error details
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    response = {
        "success": 200 <= status_code < 300,
        "status_code": status_code
    }
    
    if message:
        response["message"] = message
        
    if data is not None:
        response["data"] = data
        
    if errors:
        response["errors"] = errors
        
    if meta:
        response["meta"] = meta
        
    return jsonify(response), status_code


def success_response(data=None, message="Success", status_code=HTTPStatus.OK, meta=None):
    """
    Create a success API response.
    
    Args:
        data (any, optional): The response data
        message (str, optional): Success message
        status_code (HTTPStatus, optional): HTTP status code (must be a success code)
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    if not 200 <= status_code < 300:
        status_code = HTTPStatus.OK
        
    return api_response(data, message, status_code, meta=meta)


def error_response(message="An error occurred", 
                  status_code=HTTPStatus.INTERNAL_SERVER_ERROR, 
                  errors=None, 
                  data=None, 
                  meta=None):
    """
    Create an error API response.
    
    Args:
        message (str, optional): Error message
        status_code (HTTPStatus, optional): HTTP status code (should be an error code)
        errors (list or dict, optional): Detailed error information
        data (any, optional): Additional data to include
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    if 200 <= status_code < 300:
        status_code = HTTPStatus.INTERNAL_SERVER_ERROR
        
    return api_response(data, message, status_code, errors, meta)


def validation_error(errors, message="Validation failed", meta=None):
    """
    Create a validation error response.
    
    Args:
        errors (dict): Field validation errors
        message (str, optional): Validation error message
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    return error_response(
        message=message, 
        status_code=HTTPStatus.BAD_REQUEST, 
        errors=errors, 
        meta=meta
    )


def not_found_error(resource_name="Resource", meta=None):
    """
    Create a not found error response.
    
    Args:
        resource_name (str, optional): Name of the resource that wasn't found
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    return error_response(
        message=f"{resource_name} not found", 
        status_code=HTTPStatus.NOT_FOUND, 
        meta=meta
    )


def unauthorized_error(message="Unauthorized access", meta=None):
    """
    Create an unauthorized error response.
    
    Args:
        message (str, optional): Unauthorized error message
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    return error_response(
        message=message, 
        status_code=HTTPStatus.UNAUTHORIZED, 
        meta=meta
    )


def forbidden_error(message="Access forbidden", meta=None):
    """
    Create a forbidden error response.
    
    Args:
        message (str, optional): Forbidden error message
        meta (dict, optional): Additional metadata
        
    Returns:
        tuple: A tuple containing (response_json, status_code)
    """
    return error_response(
        message=message, 
        status_code=HTTPStatus.FORBIDDEN, 
        meta=meta
    ) 