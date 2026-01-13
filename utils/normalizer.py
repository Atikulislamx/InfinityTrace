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
    """
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
