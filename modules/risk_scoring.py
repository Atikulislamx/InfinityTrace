"""
Calculate risk score based on collected signals
"""

def calculate_risk_score(data):
    """
    Calculate weighted risk score from collected OSINT data
    
    Args:
        data (dict): collected results from modules
    Returns:
        Tuple[int, str, str, list, dict]: (risk_score 0-100, risk_level, confidence_level, risk_indicators, risk_data)
    """
    # Weights as per README specifications
    weights = {
        "username_reuse": 0.20,      # 20%
        "profile_behavior": 0.25,     # 25%
        "image_reuse": 0.15,          # 15%
        "domain_reputation": 0.25,    # 25%
        "language": 0.15              # 15%
    }
    
    # Calculate individual component scores (0-100 scale)
    scores = {
        'username': _calculate_username_score(data.get('username', [])),
        'profile': _calculate_profile_score(data),
        'image': _calculate_image_score(data.get('images', [])),
        'domain': _calculate_domain_score(data.get('domains', [])),
        'language': _calculate_language_score(data)
    }
    
    # Calculate weighted total risk score
    risk_score = int(
        scores['username'] * weights["username_reuse"] +
        scores['profile'] * weights["profile_behavior"] +
        scores['image'] * weights["image_reuse"] +
        scores['domain'] * weights["domain_reputation"] +
        scores['language'] * weights["language"]
    )
    
    # Ensure score is within 0-100 range
    risk_score = max(0, min(100, risk_score))
    
    # Determine risk level based on score
    if risk_score <= 30:
        risk_level = "LOW"
    elif risk_score <= 60:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"
    
    # Determine confidence level based on data availability
    confidence_level = _calculate_confidence(data)
    
    # Generate risk indicators list
    risk_indicators = _generate_risk_indicators(data, scores)
    
    # Generate additional risk data
    risk_data = _generate_risk_data(data)
    
    return risk_score, risk_level, confidence_level, risk_indicators, risk_data


def _calculate_username_score(username_results):
    """
    Calculate risk score from username reuse across platforms
    
    Args:
        username_results (list): results from username search
    Returns:
        int: score 0-100
    """
    if not username_results:
        return 0
    
    # More platforms = higher reuse score
    num_platforms = len([r for r in username_results if r.get('status') == 'found'])
    
    # Score increases with number of platforms
    # 1-2 platforms: low (20)
    # 3-5 platforms: medium (50)
    # 6+ platforms: high (80)
    if num_platforms <= 2:
        return 20
    elif num_platforms <= 5:
        return 50
    else:
        return 80


def _calculate_profile_score(data):
    """
    Calculate risk score from profile behavior patterns
    
    Args:
        data (dict): all collected data
    Returns:
        int: score 0-100
    """
    score = 0
    
    # Check email patterns
    email_results = data.get('email', [])
    for result in email_results:
        if result.get('risk') == 'high':
            score += 40
        elif result.get('risk') == 'medium':
            score += 20
    
    # Check phone patterns
    phone_results = data.get('phone', [])
    for result in phone_results:
        if result.get('risk') == 'medium':
            score += 20
    
    # Cap at 100
    return min(100, score)


def _calculate_image_score(image_results):
    """
    Calculate risk score from image reuse
    
    Args:
        image_results (list): results from image analysis
    Returns:
        int: score 0-100
    """
    # Since we provide manual check guidance, assign moderate score
    # if image analysis was performed
    if image_results:
        # Suggests images should be checked
        return 30
    return 0


def _calculate_domain_score(domain_results):
    """
    Calculate risk score from domain reputation
    
    Args:
        domain_results (list): results from domain intelligence
    Returns:
        int: score 0-100
    """
    if not domain_results:
        return 0
    
    score = 0
    
    # Check for active domains
    active_domains = [r for r in domain_results if r.get('status') == 'active']
    
    # Having associated domains can indicate either legitimacy or risk
    # For new/recently registered domains, higher risk
    if len(active_domains) > 0:
        score = 40  # Moderate risk - domains exist
    
    return score


def _calculate_language_score(data):
    """
    Calculate risk score from language/text patterns
    
    Args:
        data (dict): all collected data
    Returns:
        int: score 0-100
    """
    # Check for suspicious patterns in email
    score = 0
    
    email_results = data.get('email', [])
    for result in email_results:
        if 'suspicious patterns' in result.get('result', '').lower():
            score += 30
    
    return min(100, score)


def _calculate_confidence(data):
    """
    Calculate confidence level based on data availability
    
    Args:
        data (dict): all collected data
    Returns:
        str: confidence level (Low/Medium/High)
    """
    data_points = 0
    
    if data.get('username'):
        data_points += 1
    if data.get('email'):
        data_points += 1
    if data.get('phone'):
        data_points += 1
    if data.get('images'):
        data_points += 1
    if data.get('domains'):
        data_points += 1
    
    if data_points >= 4:
        return "High"
    elif data_points >= 2:
        return "Medium"
    else:
        return "Low"


def _generate_risk_indicators(data, scores):
    """
    Generate list of human-readable risk indicators
    
    Args:
        data (dict): all collected data
        scores (dict): dictionary containing individual component scores
    Returns:
        list: risk indicator messages
    """
    indicators = []
    
    # Username reuse indicator
    username_results = data.get('username', [])
    num_platforms = len([r for r in username_results if r.get('status') == 'found'])
    if num_platforms >= 3:
        indicators.append(f"Username reused on {num_platforms} platforms")
    
    # Email indicators
    email_results = data.get('email', [])
    for result in email_results:
        if result.get('risk') in ['high', 'medium']:
            indicators.append(result.get('result', 'Email-related risk detected'))
    
    # Phone indicators
    phone_results = data.get('phone', [])
    for result in phone_results:
        if result.get('risk') == 'medium':
            indicators.append(result.get('result', 'Phone-related risk detected'))
    
    # Image reuse indicator
    if scores['image'] > 0:
        indicators.append("Public profile image should be checked for reuse")
    
    # Domain indicators
    domain_results = data.get('domains', [])
    active_domains = [r for r in domain_results if r.get('status') == 'active']
    if active_domains:
        indicators.append(f"Associated domains detected: {', '.join([d['domain'] for d in active_domains[:3]])}")
    
    # Default message if no indicators
    if not indicators:
        indicators.append("No significant risk indicators detected")
    
    return indicators


def _generate_risk_data(data):
    """
    Generate additional risk data for output
    
    Args:
        data (dict): all collected data
    Returns:
        dict: additional risk data
    """
    risk_data = {}
    
    # Estimate account age based on platform presence
    username_results = data.get('username', [])
    if len(username_results) >= 5:
        risk_data['account_age'] = "~6+ months (multiple platforms)"
    elif len(username_results) >= 3:
        risk_data['account_age'] = "~3-6 months (several platforms)"
    elif len(username_results) >= 1:
        risk_data['account_age'] = "~1-3 months (limited platforms)"
    
    # Profile consistency
    if len(username_results) >= 5:
        risk_data['profile_consistency'] = "HIGH"
    elif len(username_results) >= 3:
        risk_data['profile_consistency'] = "MEDIUM"
    else:
        risk_data['profile_consistency'] = "LOW"
    
    return risk_data
