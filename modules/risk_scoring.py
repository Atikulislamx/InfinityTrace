"""
Calculate risk score based on collected signals
"""

def calculate_risk_score(data):
    """
    Args:
        data (dict): collected results from modules
    Returns:
        Tuple[int, str]: (risk_score 0-100, risk_level)
    """
    # Weights as specified in requirements
    weights = {
        "username_reuse": 0.2,
        "profile_behavior": 0.25,
        "image_reuse": 0.15,
        "domain_reputation": 0.25,
        "language": 0.15
    }

    # Initialize individual scores (0-100 scale)
    username_reuse_score = 0
    profile_behavior_score = 0
    image_reuse_score = 0
    domain_reputation_score = 0
    language_score = 0
    
    # Calculate username reuse score
    # Based on number of platforms the username appears on
    username_results = data.get('username', [])
    if username_results:
        platform_count = len(username_results)
        if platform_count >= 4:
            username_reuse_score = 80  # High reuse
        elif platform_count >= 2:
            username_reuse_score = 50  # Medium reuse
        elif platform_count >= 1:
            username_reuse_score = 30  # Low reuse
    
    # Calculate profile behavior score
    # Based on presence of email and phone in public databases
    email_results = data.get('email', [])
    phone_results = data.get('phone', [])
    
    behavior_indicators = 0
    if email_results:
        behavior_indicators += 1
    if phone_results:
        behavior_indicators += 1
    if username_results and len(username_results) > 2:
        behavior_indicators += 1
    
    profile_behavior_score = min(behavior_indicators * 30, 100)
    
    # Calculate image reuse score
    # Based on availability of image search results
    image_results = data.get('images', [])
    if image_results:
        # Presence of image search references indicates potential reuse
        image_reuse_score = 40
    
    # Calculate domain reputation score
    # Based on associated domains
    domain_results = data.get('domains', [])
    if domain_results:
        # More domain associations = higher risk
        domain_count = len([d for d in domain_results if 'domain' in d])
        if domain_count >= 3:
            domain_reputation_score = 70
        elif domain_count >= 1:
            domain_reputation_score = 40
    
    # Calculate language/content score
    # Basic scoring based on overall presence
    total_results = len(username_results) + len(email_results) + len(phone_results)
    if total_results >= 10:
        language_score = 60
    elif total_results >= 5:
        language_score = 40
    elif total_results >= 1:
        language_score = 20
    
    # Calculate weighted total risk score
    risk_score = int(
        username_reuse_score * weights["username_reuse"] +
        profile_behavior_score * weights["profile_behavior"] +
        image_reuse_score * weights["image_reuse"] +
        domain_reputation_score * weights["domain_reputation"] +
        language_score * weights["language"]
    )
    
    # Ensure risk score is within 0-100 range
    risk_score = max(0, min(100, risk_score))
    
    # Determine risk level based on score
    if risk_score >= 61:
        risk_level = "HIGH"
    elif risk_score >= 31:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_score, risk_level
