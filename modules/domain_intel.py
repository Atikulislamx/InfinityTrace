"""
Analyze associated domains / external links
"""

def check_domain(username):
    """
    Args:
        username (str)
    Returns:
        List[Dict]: [{"domain": "example.com", "age_days": 12, "link": "..."}]
    """
    if not username:
        return []
    
    results = []
    
    # Common domain patterns for usernames
    possible_domains = [
        f"{username}.com",
        f"{username}.net",
        f"{username}.org"
    ]
    
    # Public WHOIS lookup services (for manual checking)
    for domain in possible_domains:
        results.append({
            "domain": domain,
            "whois_link": f"https://who.is/whois/{domain}",
            "description": "Check domain registration and age",
            "age_days": None  # Requires actual WHOIS lookup
        })
    
    # Blacklist checking services
    results.append({
        "service": "VirusTotal",
        "link": "https://www.virustotal.com/",
        "description": "Check domain reputation and security"
    })
    
    results.append({
        "service": "URLVoid",
        "link": "https://www.urlvoid.com/",
        "description": "Check if domain is blacklisted"
    })
    
    # Note: Actual domain age calculation would require WHOIS API access
    # We provide public reference URLs for manual verification
    
    return results
