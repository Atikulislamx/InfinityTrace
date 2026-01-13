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
    # Sample weights
    weights = {
        "username_reuse": 0.2,
        "profile_behavior": 0.25,
        "image_reuse": 0.15,
        "domain_reputation": 0.25,
        "language": 0.15
    }

    # TODO: compute scores from collected data
    risk_score = 0
    risk_level = "LOW"

    # Copilot can help calculate total weighted score
    return risk_score, risk_level
