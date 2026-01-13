"""
Validate input data for basic correctness
"""

import re

def is_valid_username(username: str) -> bool:
    """
    Username must be 3-30 chars, letters/numbers/_/.
    """
    pattern = r"^[a-zA-Z0-9_.]{3,30}$"
    return bool(re.match(pattern, username))

def is_valid_email(email: str) -> bool:
    """
    Basic email validation
    """
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return bool(re.match(pattern, email))

def is_valid_phone(phone: str) -> bool:
    """
    Basic phone number validation: starts with + or number, 7-15 digits
    """
    pattern = r"^\+?\d{7,15}$"
    return bool(re.match(pattern, phone))

def is_valid_name(name: str) -> bool:
    """
    Name should have at least 2 characters, letters and spaces only
    """
    pattern = r"^[A-Za-z ]{2,100}$"
    return bool(re.match(pattern, name))
