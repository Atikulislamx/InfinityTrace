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
    Phone number validation using phonenumbers library if available.
    Falls back to basic validation: starts with + or number, 7-15 digits
    """
    try:
        import phonenumbers
        from phonenumbers import NumberParseException
        
        # Try to parse and validate using phonenumbers library
        try:
            parsed = phonenumbers.parse(phone, None)
            return phonenumbers.is_valid_number(parsed) or phonenumbers.is_possible_number(parsed)
        except NumberParseException:
            # Fall back to basic validation if parsing fails
            pass
    except ImportError:
        # phonenumbers not available, use basic validation
        pass
    
    # Fallback: basic pattern matching
    pattern = r"^\+?\d{7,15}$"
    return bool(re.match(pattern, phone))

def is_valid_name(name: str) -> bool:
    """
    Name should have at least 2 characters, letters and spaces only
    """
    pattern = r"^[A-Za-z ]{2,100}$"
    return bool(re.match(pattern, name))
