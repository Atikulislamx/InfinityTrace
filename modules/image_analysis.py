"""
Check if profile images are reused publicly (stock sites etc.)
"""

def check_image(username):
    """
    Analyze potential image reuse for a username's public profiles
    
    Args:
        username (str)
    Returns:
        List[Dict]: [{"site": "StockImage", "result": "..."}]
    """
    results = []
    
    # Note: Actual reverse image search requires:
    # - Fetching profile images from social media platforms
    # - Using reverse image search APIs (Google, TinEye, etc.)
    # - These typically require API keys and have rate limits
    
    # For ethical OSINT, we provide guidance on manual checking
    results.append({
        "site": "Google Reverse Image Search",
        "result": "Manual check recommended",
        "link": "https://images.google.com/",
        "instructions": "Upload profile image to check for reuse",
        "risk": "info"
    })
    
    results.append({
        "site": "TinEye Reverse Search",
        "result": "Manual check recommended",
        "link": "https://tineye.com/",
        "instructions": "Search for image reuse across web",
        "risk": "info"
    })
    
    # Common stock photo site patterns
    results.append({
        "site": "Stock Photo Detection",
        "result": "Check if profile images appear on stock sites",
        "common_sites": ["Unsplash", "Pexels", "Pixabay", "Shutterstock"],
        "risk": "info"
    })
    
    return results
