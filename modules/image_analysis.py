"""
Check if profile images are reused publicly (stock sites etc.)
"""

def check_image(username):
    """
    Args:
        username (str)
    Returns:
        List[Dict]: [{"site": "StockImage", "link": "..."}]
    """
    if not username:
        return []
    
    results = []
    
    # Public reverse image search engines
    # These are reference URLs for manual image verification
    results.append({
        "site": "Google Images",
        "link": "https://images.google.com/",
        "description": "Reverse image search for profile pictures"
    })
    
    results.append({
        "site": "TinEye",
        "link": "https://tineye.com/",
        "description": "Reverse image search to find image reuse"
    })
    
    results.append({
        "site": "Yandex Images",
        "link": "https://yandex.com/images/",
        "description": "Alternative reverse image search"
    })
    
    # Note: Actual image analysis would require downloading profile images
    # and uploading to reverse image search APIs, which is beyond scope
    # of this tool. We provide reference URLs for manual checking.
    
    return results
