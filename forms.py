from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class MessageForm:
    """Form for message submission"""
    def __init__(self, form_data=None):
        self.name = StringValue(form_data.get('name', '') if form_data else '')
        self.email = EmailValue(form_data.get('email', '') if form_data else '')
        self.message = StringValue(form_data.get('message', '') if form_data else '')
        self.errors = {}
    
    def validate(self):
        """Validate the form data"""
        is_valid = True
        
        # Validate name
        if not self.name.data:
            self.errors['name'] = 'Name is required'
            is_valid = False
        elif len(self.name.data) < 2:
            self.errors['name'] = 'Name must be at least 2 characters'
            is_valid = False
        
        # Validate email
        if not self.email.data:
            self.errors['email'] = 'Email is required'
            is_valid = False
        elif not self.email.validate():
            self.errors['email'] = 'Invalid email address'
            is_valid = False
        
        # Validate message
        if not self.message.data:
            self.errors['message'] = 'Message is required'
            is_valid = False
        elif len(self.message.data) < 10:
            self.errors['message'] = 'Message must be at least 10 characters'
            is_valid = False
        elif len(self.message.data) > 1000:
            self.errors['message'] = 'Message cannot exceed 1000 characters'
            is_valid = False
        
        return is_valid

class RegisterForm:
    """Form for user registration"""
    def __init__(self, form_data=None):
        self.username = StringValue(form_data.get('username', '') if form_data else '')
        self.password = StringValue(form_data.get('password', '') if form_data else '')
        self.confirm_password = StringValue(form_data.get('confirm_password', '') if form_data else '')
        self.email = EmailValue(form_data.get('email', '') if form_data else '')
        self.errors = {}
    
    def validate(self):
        """Validate the form data"""
        is_valid = True
        
        # Validate username
        if not self.username.data:
            self.errors['username'] = 'Username is required'
            is_valid = False
        elif len(self.username.data) < 3:
            self.errors['username'] = 'Username must be at least 3 characters'
            is_valid = False
        
        # Validate password
        if not self.password.data:
            self.errors['password'] = 'Password is required'
            is_valid = False
        elif len(self.password.data) < 8:
            self.errors['password'] = 'Password must be at least 8 characters'
            is_valid = False
        
        # Validate confirm password
        if self.password.data != self.confirm_password.data:
            self.errors['confirm_password'] = 'Passwords do not match'
            is_valid = False
        
        # Validate email if provided
        if self.email.data and not self.email.validate():
            self.errors['email'] = 'Invalid email address'
            is_valid = False
        
        return is_valid

class LoginForm:
    """Form for user login"""
    def __init__(self, form_data=None):
        self.username = StringValue(form_data.get('username', '') if form_data else '')
        self.password = StringValue(form_data.get('password', '') if form_data else '')
        self.errors = {}
    
    def validate(self):
        """Validate the form data"""
        is_valid = True
        
        # Validate username
        if not self.username.data:
            self.errors['username'] = 'Username is required'
            is_valid = False
        
        # Validate password
        if not self.password.data:
            self.errors['password'] = 'Password is required'
            is_valid = False
        
        return is_valid

# Form field classes for validation
class StringValue:
    """String field for forms"""
    def __init__(self, data):
        self.data = data if data else ''
    
    def validate(self):
        """Check if the value is valid"""
        return len(self.data) > 0

class EmailValue:
    """Email field for forms"""
    def __init__(self, data):
        self.data = data if data else ''
    
    def validate(self):
        """Check if the email is valid"""
        import re
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, self.data))
