"""
Analyze associated domains / external links
"""

import re
import requests
from datetime import datetime

def check_domain(username):
    """
    Analyze domains and external links associated with username
    
    Args:
        username (str)
    Returns:
        List[Dict]: [{"domain": "example.com", "age_days": 12, "result": "..."}]
    """
    results = []
    
    # Check if username matches a potential domain pattern
    if _looks_like_domain(username):
        domain = username if '.' in username else f"{username}.com"
        
        # Try to resolve the domain
        domain_info = _check_domain_exists(domain)
        if domain_info:
            results.append(domain_info)
    
    # Common personal website patterns
    common_domains = [
        f"{username}.com",
        f"{username}.net",
        f"{username}.org",
        f"{username}.io",
    ]
    
    for domain in common_domains:
        try:
            # Quick check if domain responds
            response = requests.head(f"http://{domain}", timeout=3, allow_redirects=True)
            if response.status_code < 400:
                results.append({
                    "domain": domain,
                    "status": "active",
                    "result": f"Domain {domain} is active",
                    "risk": "info"
                })
        except requests.exceptions.RequestException:
            # Domain doesn't exist or isn't accessible
            pass
    
    # Provide WHOIS lookup references
    if results:
        results.append({
            "domain": "WHOIS Lookup",
            "result": "Use WHOIS to check domain registration details",
            "link": "https://who.is/",
            "risk": "info"
        })
    
    return results


def _looks_like_domain(username):
    """
    Check if username looks like it could be a domain
    
    Args:
        username (str): username to check
    Returns:
        bool: True if looks like domain
    """
    # Check if it has domain-like characteristics
    # No spaces, may have dots, letters and numbers
    pattern = r'^[a-z0-9.-]+$'
    return bool(re.match(pattern, username.lower()))


def _check_domain_exists(domain):
    """
    Check if a domain exists and is accessible
    
    Args:
        domain (str): domain to check
    Returns:
        dict or None: domain information if exists
    """
    try:
        # Try both http and https
        for protocol in ['https', 'http']:
            try:
                response = requests.head(
                    f"{protocol}://{domain}",
                    timeout=5,
                    allow_redirects=True
                )
                
                if response.status_code < 400:
                    return {
                        "domain": domain,
                        "status": "active",
                        "protocol": protocol,
                        "result": f"Domain is active and accessible",
                        "risk": "info"
                    }
            except requests.exceptions.RequestException:
                continue
    except Exception:
        pass
    
    return None
