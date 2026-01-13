"""
Search public social media platforms for a given username
and return found profiles with URLs
"""

import requests
from utils.normalizer import normalize_username

def search_username(username):
    """
    Args:
        username (str): the username to search
    Returns:
        List[Dict]: [{"platform": "Instagram", "url": "..."}]
    """
    # Normalize username before searching
    username = normalize_username(username)
    
    results = []
    
    # Define platforms with their URL patterns
    platforms = {
        "Instagram": f"https://www.instagram.com/{username}/",
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Telegram": f"https://t.me/{username}"
    }
    
    # Headers to avoid being blocked
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    # Check each platform by attempting to access the profile URL
    for platform, url in platforms.items():
        try:
            # Use HEAD request to check if profile exists without downloading full page
            # Note: This is a simple check and may produce false positives/negatives
            # as platforms may return different status codes or require authentication
            response = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
            
            # Most platforms return 200 for valid profiles and 404 for non-existent ones
            # However, this is not 100% reliable and should be used as a reference only
            if response.status_code == 200:
                results.append({
                    "platform": platform,
                    "url": url
                })
        except requests.RequestException:
            # Skip if request fails (timeout, connection error, etc.)
            pass
    
    return results
