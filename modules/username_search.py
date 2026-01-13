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
    
    # Check each platform by attempting to access the profile URL
    for platform, url in platforms.items():
        try:
            # Use HEAD request to check if profile exists without downloading full page
            response = requests.head(url, timeout=5, allow_redirects=True)
            # Instagram, GitHub, Twitter return 200 for valid profiles
            # 404 for non-existent profiles
            if response.status_code == 200:
                results.append({
                    "platform": platform,
                    "url": url
                })
        except requests.RequestException:
            # Skip if request fails (timeout, connection error, etc.)
            pass
    
    return results
