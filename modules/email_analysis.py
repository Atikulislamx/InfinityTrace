"""
Analyze public email footprints and reputation
"""

from utils.normalizer import normalize_email

def check_email(email):
    """
    Args:
        email (str)
    Returns:
        List[Dict]: [{"source": "HaveIBeenPwned", "link": "..."}]
    """
    # Normalize email
    email = normalize_email(email)
    
    results = []
    
    # Public email checking resources (non-API, informational only)
    # These are public search engines and databases where users can manually check
    results.append({
        "source": "HaveIBeenPwned",
        "link": f"https://haveibeenpwned.com/account/{email}",
        "description": "Check if email appears in known data breaches"
    })
    
    results.append({
        "source": "DeHashed",
        "link": f"https://www.dehashed.com/search?query={email}",
        "description": "Public breach database search"
    })
    
    results.append({
        "source": "LeakCheck",
        "link": f"https://leakcheck.io/",
        "description": "Email leak database"
    })
    
    # Note: We're not actually calling APIs here as that would require authentication
    # We're just providing public reference URLs where this email can be checked
    
    return results
