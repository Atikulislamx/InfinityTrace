"""
Analyze public references for phone numbers
"""

from utils.normalizer import normalize_phone

def check_phone(phone):
    """
    Args:
        phone (str)
    Returns:
        List[Dict]: [{"source": "SpamDB", "link": "..."}]
    """
    # Normalize phone number
    phone = normalize_phone(phone)
    
    results = []
    
    # Public phone number databases and spam report sites
    results.append({
        "source": "TrueCaller",
        "link": f"https://www.truecaller.com/search/phone/{phone}",
        "description": "Public phone number lookup and spam reports"
    })
    
    results.append({
        "source": "WhoCalledMe",
        "link": f"https://whocalled.us/lookup/{phone}",
        "description": "Community-reported phone number database"
    })
    
    results.append({
        "source": "800Notes",
        "link": f"https://800notes.com/Phone.aspx/{phone}",
        "description": "Public phone spam database"
    })
    
    results.append({
        "source": "SpamCalls",
        "link": f"https://spamcalls.net/en/number/{phone}",
        "description": "International spam phone database"
    })
    
    # Note: These are public reference URLs where the phone can be manually checked
    # No private APIs are accessed
    
    return results
