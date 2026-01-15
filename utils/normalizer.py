"""
Normalize and clean input data: usernames, emails, phone numbers, names
"""

import re

def normalize_username(username: str) -> str:
    """
    Clean and normalize username:
    - strip spaces
    - lowercase
    - remove special chars except _ and .
    """
    username = username.strip().lower()
    username = re.sub(r"[^a-z0-9_.]", "", username)
    return username

def normalize_email(email: str) -> str:
    """
    Clean and lowercase email
    """
    return email.strip().lower()

def normalize_phone(phone: str) -> str:
    """
    Clean phone number:
    - Remove spaces, dashes, brackets
    - Keep only numbers with optional + at start
    - Try to normalize to E.164 format if phonenumbers library is available
    """
    try:
        import phonenumbers
        from phonenumbers import NumberParseException, PhoneNumberFormat
        
        # Try to parse and normalize to E.164
        try:
            parsed = phonenumbers.parse(phone, None)
            if phonenumbers.is_valid_number(parsed) or phonenumbers.is_possible_number(parsed):
                return phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        except NumberParseException:
            pass  # Fall back to basic normalization
    except ImportError:
        pass  # phonenumbers not available, use basic normalization
    
    # Fallback: basic normalization
    phone = phone.strip()
    phone = re.sub(r"[^\d+]", "", phone)
    return phone

def normalize_name(name: str) -> str:
    """
    Standardize full name:
    - Strip extra spaces
    - Capitalize first letters
    """
    name = " ".join(name.strip().split())
    name = name.title()
    return name
