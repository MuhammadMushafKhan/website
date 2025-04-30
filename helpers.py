import re
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def validate_email(email):
    """
    Validate email format
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not email:
        return False
        
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))

def validate_username(username):
    """
    Validate username format
    
    Args:
        username (str): Username to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not username:
        return False
        
    # Username should be 3-30 characters and contain only alphanumeric characters,
    # underscores, and hyphens
    pattern = r"^[a-zA-Z0-9_-]{3,30}$"
    return bool(re.match(pattern, username))

def validate_password(password):
    """
    Validate password strength
    
    Args:
        password (str): Password to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not password:
        return False
        
    # Password should be at least 8 characters
    return len(password) >= 8

def validate_message(message):
    """
    Validate message content
    
    Args:
        message (str): Message to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not message:
        return False
        
    # Message should be 10-1000 characters
    return 10 <= len(message) <= 1000

def sanitize_input(text):
    """
    Sanitize user input to prevent XSS
    
    Args:
        text (str): Text to sanitize
        
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
        
    # Replace HTML special characters
    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
        "/": "&#x2F;"
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
        
    return text

def log_activity(user_id, action, details=None):
    """
    Log user activity for audit purposes
    
    Args:
        user_id (int): User ID
        action (str): Action being performed
        details (dict, optional): Additional details
    """
    try:
        activity = {
            'user_id': user_id,
            'action': action,
            'details': details
        }
        logger.info(f"User activity: {activity}")
    except Exception as e:
        logger.error(f"Error logging activity: {str(e)}")
