from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, NumberRange

class LoginForm(FlaskForm):
    """Form for user login"""
    master_password = PasswordField('Master Password', validators=[
        DataRequired(message="Master password is required")
    ])

class CreateVaultForm(FlaskForm):
    """Form for creating a new vault"""
    master_password = PasswordField('Master Password', validators=[
        DataRequired(message="Master password is required"),
        Length(min=8, message="Master password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('master_password', message="Passwords must match")
    ])

class PasswordForm(FlaskForm):
    """Form for adding or editing a password"""
    site = StringField('Site/Service', validators=[
        DataRequired(message="Site name is required")
    ])
    username = StringField('Username/Email', validators=[
        DataRequired(message="Username is required")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])
    category = StringField('Category', validators=[
        Optional()
    ])

class GeneratePasswordForm(FlaskForm):
    """Form for generating a password"""
    length = IntegerField('Password Length', validators=[
        DataRequired(message="Length is required"),
        NumberRange(min=8, max=64, message="Length must be between 8 and 64")
    ], default=16)
    include_uppercase = BooleanField('Include Uppercase Letters', default=True)
    include_lowercase = BooleanField('Include Lowercase Letters', default=True)
    include_digits = BooleanField('Include Numbers', default=True)
    include_symbols = BooleanField('Include Symbols', default=True)

class TwoFactorForm(FlaskForm):
    """Form for verifying 2FA code"""
    code = StringField('Authentication Code', validators=[
        DataRequired(message="Authentication code is required"),
        Length(min=6, max=6, message="Code must be 6 digits")
    ])

class SetupTwoFactorForm(FlaskForm):
    """Form for setting up 2FA"""
    code = StringField('Authentication Code', validators=[
        DataRequired(message="Authentication code is required"),
        Length(min=6, max=6, message="Code must be 6 digits")
    ]) 
