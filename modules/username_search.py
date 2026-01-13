"""
Search public social media platforms for a given username
and return found profiles with URLs
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def search_username(username):
    """
    Search for username across major public platforms
    
    Args:
        username (str): the username to search
    Returns:
        List[Dict]: [{"platform": "Instagram", "url": "..."}]
    """
    # Define platforms with their URL patterns
    platforms = {
        "Instagram": f"https://instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "Telegram": f"https://t.me/{username}",
        "Medium": f"https://medium.com/@{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
    }
    
    results = []
    session = _create_session()
    
    for platform, url in platforms.items():
        try:
            # Set user agent to avoid blocks
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Make HEAD request to check if profile exists
            response = session.head(url, headers=headers, timeout=5, allow_redirects=True)
            
            # Check if profile likely exists
            # 200 = exists, 404 = doesn't exist, other codes may vary
            if response.status_code == 200:
                results.append({
                    "platform": platform,
                    "url": url,
                    "status": "found"
                })
            elif response.status_code == 404:
                # Profile doesn't exist, don't add to results
                pass
            else:
                # Uncertain status, include but mark as uncertain
                results.append({
                    "platform": platform,
                    "url": url,
                    "status": "uncertain"
                })
        except requests.exceptions.RequestException:
            # Network error or timeout, skip this platform
            pass
    
    return results


def _create_session():
    """
    Create a requests session with retry logic
    
    Returns:
        requests.Session: configured session
    """
    session = requests.Session()
    
    # Configure retry strategy
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    return session
