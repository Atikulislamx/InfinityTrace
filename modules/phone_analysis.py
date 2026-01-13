"""
Analyze public references for phone numbers
"""

import re

def check_phone(phone):
    """
    Check for public phone number references and spam reports
    
    Args:
        phone (str)
    Returns:
        List[Dict]: [{"source": "SpamDB", "result": "..."}]
    """
    results = []
    
    # Analyze phone number pattern
    phone_clean = re.sub(r'[^\d+]', '', phone)
    
    # Check if it looks like a VoIP/virtual number pattern
    if _is_voip_pattern(phone_clean):
        results.append({
            "source": "Number Type Analysis",
            "result": "Possible VoIP/virtual number pattern",
            "risk": "medium"
        })
    
    # Check country code (if present)
    country_info = _get_country_info(phone_clean)
    if country_info:
        results.append({
            "source": "Geographic Analysis",
            "result": country_info,
            "risk": "info"
        })
    
    # Provide references to public spam databases
    results.append({
        "source": "Spam Database Reference",
        "result": "Check manually at public spam databases",
        "link": "https://www.whocallsme.com/",
        "risk": "info"
    })
    
    results.append({
        "source": "TrueCaller Reference",
        "result": "Search on TrueCaller for spam reports",
        "link": "https://www.truecaller.com/",
        "risk": "info"
    })
    
    return results


def _is_voip_pattern(phone):
    """
    Check if phone number matches common VoIP patterns
    
    Args:
        phone (str): cleaned phone number
    Returns:
        bool: True if likely VoIP
    """
    # This is a simplified check
    # Common VoIP area codes in US: 800, 888, 877, 866, 855, 844, 833
    voip_patterns = [
        r'^\+?1(800|888|877|866|855|844|833)',  # US toll-free
    ]
    
    for pattern in voip_patterns:
        if re.match(pattern, phone):
            return True
    
    return False


def _get_country_info(phone):
    """
    Get basic country information from phone number
    
    Args:
        phone (str): cleaned phone number
    Returns:
        str: country information or None
    """
    # Basic country code detection
    country_codes = {
        '+1': 'North America (US/Canada)',
        '+44': 'United Kingdom',
        '+91': 'India',
        '+86': 'China',
        '+81': 'Japan',
        '+49': 'Germany',
        '+33': 'France',
        '+61': 'Australia',
        '+7': 'Russia/Kazakhstan',
        '+55': 'Brazil',
        '+880': 'Bangladesh',
    }
    
    for code, country in country_codes.items():
        if phone.startswith(code):
            return f"Country code: {country}"
    
    # If starts with + but not in our list
    if phone.startswith('+'):
        return "International number (country code not recognized)"
    
    return "No country code detected (may be local number)"
