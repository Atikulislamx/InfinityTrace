"""
Analyze public email footprints and reputation
"""

import requests
import re

def check_email(email):
    """
    Check for public email footprints and data breach references
    
    Args:
        email (str)
    Returns:
        List[Dict]: [{"source": "HaveIBeenPwned", "result": "..."}]
    """
    results = []
    
    # Extract domain from email for domain-based checks
    domain = email.split('@')[-1] if '@' in email else None
    
    # Check if email domain is from a disposable email service
    if domain and _is_disposable_email(domain):
        results.append({
            "source": "Disposable Email Check",
            "result": "Temporary/disposable email domain detected",
            "risk": "high"
        })
    
    # Check for common patterns in email that might indicate risk
    if _has_suspicious_pattern(email):
        results.append({
            "source": "Pattern Analysis",
            "result": "Email contains suspicious patterns",
            "risk": "medium"
        })
    
    # Note: Real HaveIBeenPwned API requires API key and has rate limits
    # For ethical OSINT, we provide the URL for manual checking
    results.append({
        "source": "HaveIBeenPwned Reference",
        "result": f"Check manually at: https://haveibeenpwned.com/",
        "link": f"https://haveibeenpwned.com/",
        "risk": "info"
    })
    
    return results


def _is_disposable_email(domain):
    """
    Check if email domain is from a known disposable email service
    
    Args:
        domain (str): email domain
    Returns:
        bool: True if disposable
    """
    # Common disposable email domains
    disposable_domains = [
        'tempmail.com', 'guerrillamail.com', '10minutemail.com',
        'mailinator.com', 'throwaway.email', 'maildrop.cc',
        'trashmail.com', 'yopmail.com', 'temp-mail.org',
        'fakeinbox.com', 'sharklasers.com', 'getnada.com'
    ]
    
    return domain.lower() in disposable_domains


def _has_suspicious_pattern(email):
    """
    Check if email has suspicious patterns
    
    Args:
        email (str): email address
    Returns:
        bool: True if suspicious
    """
    # Check for excessive numbers (e.g., test12345@example.com)
    username = email.split('@')[0] if '@' in email else email
    
    # More than 5 consecutive digits
    if re.search(r'\d{5,}', username):
        return True
    
    # Very short usernames (1-2 chars)
    if len(username) < 3:
        return True
    
    # Excessive special characters
    special_chars = len(re.findall(r'[._-]', username))
    if special_chars > 3:
        return True
    
    return False
