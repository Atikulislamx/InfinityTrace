"""
Professional-grade OSINT-based Risk Scoring Module for InfinityTrace

This module provides comprehensive risk scoring with explainable outputs based on
signals from multiple intelligence modules (username, email, phone, image, domain).

Key Features:
- Confidence-weighted scoring
- Category-based weighting with adaptive redistribution
- Correlation-aware risk escalation
- Rule-based overrides for high-risk patterns
- False positive reduction via legitimacy indicators
- Fully deterministic and explainable outputs

Author: Cyber Infinity
Project: InfinityTrace
"""

import math
import json
import logging
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Risk level thresholds
RISK_THRESHOLD_LOW = 30
RISK_THRESHOLD_MEDIUM = 60

# Category weights (must sum to 1.0)
DEFAULT_WEIGHTS = {
    "username_reuse": 0.20,
    "profile_behavior": 0.25,
    "image_reuse": 0.15,
    "domain_reputation": 0.25,
    "language": 0.15
}


def normalize_score(score: float, min_val: float = 0, max_val: float = 100) -> int:
    """
    Normalize a score to the 0-100 scale.
    
    Args:
        score: Raw score value
        min_val: Minimum value of the scale (default: 0)
        max_val: Maximum value of the scale (default: 100)
        
    Returns:
        int: Normalized score between 0 and 100
    """
    normalized = max(0, min(100, int((score / max_val) * 100)))
    return normalized


def calculate_confidence_level(data: Dict[str, Any]) -> Tuple[str, int]:
    """
    Calculate confidence level based on data completeness and quality.
    
    Args:
        data: Dictionary containing intelligence module results
        
    Returns:
        Tuple[str, int]: (confidence_level, confidence_score)
            - confidence_level: "LOW", "MEDIUM", or "HIGH"
            - confidence_score: 0-100 numerical confidence
    """
    confidence_score = 0
    total_categories = 0
    available_categories = 0
    
    # Check each category for data availability
    categories = {
        'username': data.get('username', []),
        'email': data.get('email', []),
        'phone': data.get('phone', []),
        'images': data.get('images', []),
        'domains': data.get('domains', [])
    }
    
    for category, results in categories.items():
        total_categories += 1
        if results:
            available_categories += 1
            # Add confidence based on result count and quality
            result_count = len(results) if isinstance(results, list) else 1
            confidence_score += min(20, result_count * 5)
    
    # Normalize confidence score
    confidence_score = min(100, confidence_score)
    
    # Determine confidence level
    if confidence_score >= 70:
        confidence_level = "HIGH"
    elif confidence_score >= 40:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"
    
    logger.info(f"Confidence calculated: {confidence_level} ({confidence_score}/100)")
    return confidence_level, confidence_score


def redistribute_weights(weights: Dict[str, float], missing_categories: List[str]) -> Dict[str, float]:
    """
    Adaptively redistribute category weights when some categories have no data.
    
    Args:
        weights: Original category weights
        missing_categories: List of categories with no data
        
    Returns:
        Dict[str, float]: Redistributed weights
    """
    if not missing_categories:
        return weights.copy()
    
    # Calculate total weight from missing categories
    missing_weight = sum(weights.get(cat, 0) for cat in missing_categories)
    
    # Get available categories
    available_categories = {k: v for k, v in weights.items() if k not in missing_categories}
    
    if not available_categories:
        return weights.copy()
    
    # Redistribute proportionally
    total_available_weight = sum(available_categories.values())
    redistributed = {}
    
    for category, weight in weights.items():
        if category in missing_categories:
            redistributed[category] = 0
        else:
            # Redistribute proportionally to available categories
            proportion = weight / total_available_weight
            redistributed[category] = weight + (missing_weight * proportion)
    
    logger.info(f"Redistributed weights for missing categories: {missing_categories}")
    return redistributed


def calculate_username_score(username_data: List[Dict[str, Any]]) -> Tuple[int, float, str]:
    """
    Calculate username reuse risk score with confidence.
    
    Args:
        username_data: List of username search results
        
    Returns:
        Tuple[int, float, str]: (score, confidence, explanation)
    """
    if not username_data:
        return 0, 0.0, "No username data available"
    
    platform_count = len(username_data)
    
    # Calculate base score
    if platform_count >= 10:
        base_score = 90
        explanation = f"Username found on {platform_count} platforms (very high reuse)"
    elif platform_count >= 5:
        base_score = 75
        explanation = f"Username found on {platform_count} platforms (high reuse)"
    elif platform_count >= 3:
        base_score = 55
        explanation = f"Username found on {platform_count} platforms (moderate reuse)"
    elif platform_count >= 2:
        base_score = 35
        explanation = f"Username found on {platform_count} platforms (low reuse)"
    else:
        base_score = 15
        explanation = f"Username found on {platform_count} platform (minimal presence)"
    
    # Calculate average confidence from results
    confidences = [r.get('confidence_score', 50) for r in username_data if isinstance(r, dict)]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 50
    normalized_confidence = avg_confidence / 100
    
    return base_score, normalized_confidence, explanation


def calculate_profile_behavior_score(email_data: List[Any], phone_data: List[Any], 
                                     username_data: List[Any]) -> Tuple[int, float, str]:
    """
    Calculate profile behavior risk score based on email, phone, and username presence.
    
    Args:
        email_data: Email analysis results
        phone_data: Phone analysis results
        username_data: Username search results
        
    Returns:
        Tuple[int, float, str]: (score, confidence, explanation)
    """
    indicators = []
    score = 0
    
    if email_data:
        score += 30
        indicators.append(f"email found in {len(email_data)} public sources")
    
    if phone_data:
        score += 30
        indicators.append(f"phone found in {len(phone_data)} public sources")
    
    if username_data and len(username_data) > 2:
        score += 25
        indicators.append(f"username on {len(username_data)} platforms")
    
    # Check for disposable email or spam indicators
    if email_data:
        for item in email_data:
            if isinstance(item, dict):
                if item.get('suspicious', False) or item.get('is_disposable', False):
                    score += 15
                    indicators.append("suspicious email indicators detected")
                    break
    
    score = min(100, score)
    confidence = 0.8 if indicators else 0.0
    explanation = "; ".join(indicators) if indicators else "No behavioral indicators detected"
    
    return score, confidence, explanation


def calculate_image_score(image_data: List[Any]) -> Tuple[int, float, str]:
    """
    Calculate image reuse risk score.
    
    Args:
        image_data: Image analysis results
        
    Returns:
        Tuple[int, float, str]: (score, confidence, explanation)
    """
    if not image_data:
        return 0, 0.0, "No image data available"
    
    count = len(image_data)
    
    if count >= 5:
        score = 70
        explanation = f"Profile image found in {count} sources (high reuse)"
    elif count >= 3:
        score = 50
        explanation = f"Profile image found in {count} sources (moderate reuse)"
    else:
        score = 30
        explanation = f"Profile image found in {count} sources (low reuse)"
    
    confidence = 0.7  # Image searches generally have moderate confidence
    return score, confidence, explanation


def calculate_domain_score(domain_data: List[Dict[str, Any]]) -> Tuple[int, float, str]:
    """
    Calculate domain reputation risk score.
    
    Args:
        domain_data: Domain intelligence results
        
    Returns:
        Tuple[int, float, str]: (score, confidence, explanation)
    """
    if not domain_data:
        return 0, 0.0, "No domain data available"
    
    # Filter actual domains (not just service references)
    actual_domains = [d for d in domain_data if isinstance(d, dict) and 'domain' in d and 'service' not in d]
    
    domain_count = len(actual_domains)
    
    if domain_count >= 5:
        score = 75
        explanation = f"Associated with {domain_count} domains (high risk)"
    elif domain_count >= 3:
        score = 60
        explanation = f"Associated with {domain_count} domains (moderate risk)"
    elif domain_count >= 1:
        score = 35
        explanation = f"Associated with {domain_count} domain(s)"
    else:
        score = 0
        explanation = "No significant domain associations"
    
    confidence = 0.75 if actual_domains else 0.0
    return score, confidence, explanation


def calculate_language_score(username_data: List[Any], email_data: List[Any], 
                             phone_data: List[Any]) -> Tuple[int, float, str]:
    """
    Calculate language/content risk score based on overall data presence.
    
    Args:
        username_data: Username results
        email_data: Email results
        phone_data: Phone results
        
    Returns:
        Tuple[int, float, str]: (score, confidence, explanation)
    """
    total_results = len(username_data) + len(email_data) + len(phone_data)
    
    if total_results >= 15:
        score = 70
        explanation = f"Very high digital footprint ({total_results} total findings)"
    elif total_results >= 10:
        score = 55
        explanation = f"High digital footprint ({total_results} total findings)"
    elif total_results >= 5:
        score = 40
        explanation = f"Moderate digital footprint ({total_results} total findings)"
    elif total_results >= 1:
        score = 20
        explanation = f"Low digital footprint ({total_results} total findings)"
    else:
        score = 0
        explanation = "No digital footprint detected"
    
    confidence = 0.6 if total_results > 0 else 0.0
    return score, confidence, explanation


def detect_correlations(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect cross-signal correlations that may escalate risk.
    
    Args:
        data: Dictionary containing all intelligence module results
        
    Returns:
        List[Dict]: List of correlation findings with escalation factors
    """
    correlations = []
    
    username_data = data.get('username', [])
    email_data = data.get('email', [])
    phone_data = data.get('phone', [])
    domain_data = data.get('domains', [])
    
    # Correlation 1: High username reuse + email presence
    if len(username_data) >= 5 and email_data:
        correlations.append({
            'type': 'username_email_correlation',
            'description': f'Username appears on {len(username_data)} platforms with public email presence',
            'escalation_factor': 1.15,
            'severity': 'MEDIUM'
        })
    
    # Correlation 2: Email + Phone + Multiple usernames
    if email_data and phone_data and len(username_data) >= 3:
        correlations.append({
            'type': 'multi_identifier_correlation',
            'description': 'Email, phone, and username all found in public sources',
            'escalation_factor': 1.20,
            'severity': 'HIGH'
        })
    
    # Correlation 3: Domain associations with username reuse
    if len(domain_data) >= 2 and len(username_data) >= 4:
        correlations.append({
            'type': 'domain_username_correlation',
            'description': f'Username reused across {len(username_data)} platforms with {len(domain_data)} domain associations',
            'escalation_factor': 1.10,
            'severity': 'MEDIUM'
        })
    
    # Correlation 4: Very high overall footprint
    total_signals = len(username_data) + len(email_data) + len(phone_data) + len(domain_data)
    if total_signals >= 20:
        correlations.append({
            'type': 'high_footprint',
            'description': f'Extensive digital footprint across {total_signals} total signals',
            'escalation_factor': 1.25,
            'severity': 'HIGH'
        })
    
    return correlations


def apply_rule_based_overrides(base_score: int, data: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Apply rule-based overrides for high-risk patterns.
    
    Args:
        base_score: Base calculated risk score
        data: Dictionary containing all intelligence module results
        
    Returns:
        Tuple[int, List[str]]: (adjusted_score, list_of_override_reasons)
    """
    override_reasons = []
    adjusted_score = base_score
    
    username_data = data.get('username', [])
    email_data = data.get('email', [])
    
    # Override 1: Extremely high username reuse
    if len(username_data) >= 15:
        if adjusted_score < 75:
            adjusted_score = 75
            override_reasons.append(f"Override: Username found on {len(username_data)}+ platforms (minimum HIGH risk)")
    
    # Override 2: Suspicious email indicators
    for item in email_data:
        if isinstance(item, dict):
            if item.get('suspicious', False) and item.get('reputation') == 'low':
                adjusted_score = min(100, adjusted_score + 15)
                override_reasons.append("Override: Low reputation email detected (+15 points)")
                break
    
    # Override 3: Multiple high-risk signals
    high_risk_count = 0
    if len(username_data) >= 10:
        high_risk_count += 1
    if len(email_data) >= 5:
        high_risk_count += 1
    if len(data.get('domains', [])) >= 5:
        high_risk_count += 1
    
    if high_risk_count >= 2:
        adjusted_score = min(100, adjusted_score + 10)
        override_reasons.append("Override: Multiple high-risk signal categories detected (+10 points)")
    
    return adjusted_score, override_reasons


def reduce_false_positives(score: int, data: Dict[str, Any]) -> Tuple[int, List[str]]:
    """
    Reduce false positives by analyzing legitimacy indicators.
    
    Args:
        score: Current risk score
        data: Dictionary containing all intelligence module results
        
    Returns:
        Tuple[int, List[str]]: (adjusted_score, list_of_reduction_reasons)
    """
    reduction_reasons = []
    adjusted_score = score
    
    username_data = data.get('username', [])
    domain_data = data.get('domains', [])
    
    # Legitimacy 1: Presence on professional platforms
    professional_platforms = ['LinkedIn', 'GitHub', 'StackOverflow']
    found_professional = [r for r in username_data if isinstance(r, dict) and 
                         r.get('platform') in professional_platforms]
    
    if len(found_professional) >= 2:
        reduction = int(score * 0.10)  # 10% reduction
        adjusted_score -= reduction
        reduction_reasons.append(f"Legitimacy: Found on {len(found_professional)} professional platforms (-{reduction} points)")
    
    # Legitimacy 2: Single username (not widespread)
    if len(username_data) == 1:
        reduction = 5
        adjusted_score -= reduction
        reduction_reasons.append(f"Legitimacy: Limited username presence (-{reduction} points)")
    
    # Legitimacy 3: No spam/disposable indicators
    has_spam_indicators = False
    for item in data.get('email', []):
        if isinstance(item, dict) and (item.get('suspicious', False) or item.get('is_disposable', False)):
            has_spam_indicators = True
            break
    
    if not has_spam_indicators and data.get('email'):
        reduction = 5
        adjusted_score -= reduction
        reduction_reasons.append(f"Legitimacy: No spam/disposable email indicators (-{reduction} points)")
    
    # Ensure score doesn't go below 0
    adjusted_score = max(0, adjusted_score)
    
    return adjusted_score, reduction_reasons


def identify_top_risk_factors(category_scores: Dict[str, Dict[str, Any]], 
                               correlations: List[Dict[str, Any]]) -> List[str]:
    """
    Identify the top contributing risk factors.
    
    Args:
        category_scores: Dictionary of category scores with explanations
        correlations: List of detected correlations
        
    Returns:
        List[str]: Top risk factors in order of importance
    """
    # Sort categories by weighted contribution
    factors = []
    
    for category, data in category_scores.items():
        weighted_score = data['score'] * data['weight']
        if weighted_score > 0:
            factors.append({
                'category': category,
                'weighted_score': weighted_score,
                'explanation': data['explanation']
            })
    
    # Sort by weighted score descending
    factors.sort(key=lambda x: x['weighted_score'], reverse=True)
    
    # Get top factors
    top_factors = []
    for factor in factors[:5]:  # Top 5 factors
        top_factors.append(f"{factor['category']}: {factor['explanation']} (contribution: {factor['weighted_score']:.1f})")
    
    # Add high-severity correlations
    for corr in correlations:
        if corr['severity'] == 'HIGH':
            top_factors.append(f"Correlation: {corr['description']}")
    
    return top_factors


def generate_reasoning(overall_score: int, risk_level: str, top_factors: List[str], 
                       correlations: List[Dict[str, Any]], overrides: List[str], 
                       reductions: List[str]) -> str:
    """
    Generate human-readable explanation for the risk score.
    
    Args:
        overall_score: Final risk score
        risk_level: Risk level (LOW/MEDIUM/HIGH)
        top_factors: List of top contributing factors
        correlations: List of detected correlations
        overrides: List of override reasons
        reductions: List of false positive reduction reasons
        
    Returns:
        str: Human-readable reasoning
    """
    reasoning_parts = []
    
    # Opening statement
    reasoning_parts.append(f"Risk assessment: {risk_level} ({overall_score}/100).")
    
    # Top factors
    if top_factors:
        reasoning_parts.append(f"The score primarily derives from: {top_factors[0].split(': ', 1)[1] if ': ' in top_factors[0] else top_factors[0]}.")
        if len(top_factors) > 1:
            other_factors = ", ".join([f.split(': ', 1)[0] for f in top_factors[1:3]])
            reasoning_parts.append(f"Additional factors include: {other_factors}.")
    
    # Correlations
    if correlations:
        high_severity = [c for c in correlations if c['severity'] == 'HIGH']
        if high_severity:
            reasoning_parts.append(f"High-severity correlation detected: {high_severity[0]['description']}.")
    
    # Overrides
    if overrides:
        reasoning_parts.append(f"Rule-based adjustments applied: {len(overrides)} override(s).")
    
    # Reductions
    if reductions:
        reasoning_parts.append(f"False positive mitigations: {len(reductions)} legitimacy indicator(s) detected.")
    
    return " ".join(reasoning_parts)


def calculate_risk_score(data: Dict[str, Any]) -> Tuple[int, str]:
    """
    Calculate comprehensive, explainable OSINT-based risk score.
    
    This is the main entry point that orchestrates all risk scoring functions
    and returns both legacy format (score, level) and detailed analysis.
    
    Args:
        data (dict): collected results from modules with keys:
            - username: List of username search results
            - email: List of email analysis results
            - phone: List of phone analysis results
            - images: List of image analysis results
            - domains: List of domain intelligence results
            
    Returns:
        Tuple[int, str]: (risk_score 0-100, risk_level)
            - risk_score: Overall risk score (0-100)
            - risk_level: "LOW", "MEDIUM", or "HIGH"
            
    Note:
        For detailed results, use calculate_detailed_risk_score()
    """
    # Call detailed function and return legacy format
    detailed = calculate_detailed_risk_score(data)
    return detailed['overall_risk_score'], detailed['risk_level']


def calculate_detailed_risk_score(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate comprehensive, explainable OSINT-based risk score with full details.
    
    This function implements the professional-grade risk scoring system with:
    - Confidence-weighted scoring
    - Adaptive weight redistribution
    - Correlation-aware escalation
    - Rule-based overrides
    - False positive reduction
    - Full explainability
    
    Args:
        data: Dictionary containing all intelligence module results
        
    Returns:
        Dict containing:
            - overall_risk_score: int (0-100)
            - risk_level: str ("LOW", "MEDIUM", "HIGH")
            - confidence_level: str ("LOW", "MEDIUM", "HIGH")
            - top_risk_factors: List[str]
            - correlation_flags: List[Dict]
            - reasoning: str
            - category_breakdown: Dict (for debugging/auditing)
    """
    logger.info("Starting comprehensive risk score calculation")
    
    # Extract data
    username_data = data.get('username', [])
    email_data = data.get('email', [])
    phone_data = data.get('phone', [])
    image_data = data.get('images', [])
    domain_data = data.get('domains', [])
    
    # Step 1: Calculate confidence level
    confidence_level, confidence_score = calculate_confidence_level(data)
    
    # Step 2: Calculate individual category scores
    username_score, username_conf, username_exp = calculate_username_score(username_data)
    behavior_score, behavior_conf, behavior_exp = calculate_profile_behavior_score(
        email_data, phone_data, username_data
    )
    image_score, image_conf, image_exp = calculate_image_score(image_data)
    domain_score, domain_conf, domain_exp = calculate_domain_score(domain_data)
    language_score, language_conf, language_exp = calculate_language_score(
        username_data, email_data, phone_data
    )
    
    # Step 3: Identify missing categories and redistribute weights
    missing_categories = []
    if username_score == 0 and not username_data:
        missing_categories.append('username_reuse')
    if behavior_score == 0 and not email_data and not phone_data:
        missing_categories.append('profile_behavior')
    if image_score == 0 and not image_data:
        missing_categories.append('image_reuse')
    if domain_score == 0 and not domain_data:
        missing_categories.append('domain_reputation')
    
    weights = redistribute_weights(DEFAULT_WEIGHTS, missing_categories)
    
    # Step 4: Apply confidence weighting to scores
    category_scores = {
        'username_reuse': {
            'score': username_score,
            'confidence': username_conf,
            'weight': weights['username_reuse'],
            'explanation': username_exp,
            'weighted_score': username_score * username_conf * weights['username_reuse']
        },
        'profile_behavior': {
            'score': behavior_score,
            'confidence': behavior_conf,
            'weight': weights['profile_behavior'],
            'explanation': behavior_exp,
            'weighted_score': behavior_score * behavior_conf * weights['profile_behavior']
        },
        'image_reuse': {
            'score': image_score,
            'confidence': image_conf,
            'weight': weights['image_reuse'],
            'explanation': image_exp,
            'weighted_score': image_score * image_conf * weights['image_reuse']
        },
        'domain_reputation': {
            'score': domain_score,
            'confidence': domain_conf,
            'weight': weights['domain_reputation'],
            'explanation': domain_exp,
            'weighted_score': domain_score * domain_conf * weights['domain_reputation']
        },
        'language': {
            'score': language_score,
            'confidence': language_conf,
            'weight': weights['language'],
            'explanation': language_exp,
            'weighted_score': language_score * language_conf * weights['language']
        }
    }
    
    # Step 5: Calculate base weighted score
    base_score = sum(cat['weighted_score'] for cat in category_scores.values())
    base_score = int(base_score)
    
    # Step 6: Detect correlations
    correlations = detect_correlations(data)
    
    # Step 7: Apply correlation escalation
    escalation_factor = 1.0
    for corr in correlations:
        escalation_factor *= corr['escalation_factor']
    
    escalated_score = int(base_score * escalation_factor)
    escalated_score = min(100, escalated_score)
    
    # Step 8: Apply rule-based overrides
    override_score, override_reasons = apply_rule_based_overrides(escalated_score, data)
    
    # Step 9: Reduce false positives
    final_score, reduction_reasons = reduce_false_positives(override_score, data)
    
    # Ensure final score is within bounds
    final_score = max(0, min(100, final_score))
    
    # Step 10: Determine risk level
    if final_score >= RISK_THRESHOLD_MEDIUM:
        risk_level = "HIGH"
    elif final_score > RISK_THRESHOLD_LOW:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    
    # Step 11: Identify top risk factors
    top_risk_factors = identify_top_risk_factors(category_scores, correlations)
    
    # Step 12: Generate reasoning
    reasoning = generate_reasoning(
        final_score, risk_level, top_risk_factors, correlations,
        override_reasons, reduction_reasons
    )
    
    # Build result
    result = {
        'overall_risk_score': final_score,
        'risk_level': risk_level,
        'confidence_level': confidence_level,
        'top_risk_factors': top_risk_factors[:5],  # Top 5
        'correlation_flags': [
            {
                'type': c['type'],
                'description': c['description'],
                'severity': c['severity']
            }
            for c in correlations
        ],
        'reasoning': reasoning,
        'category_breakdown': {
            cat: {
                'score': data['score'],
                'confidence': f"{int(data['confidence'] * 100)}%",
                'weight': f"{int(data['weight'] * 100)}%",
                'contribution': f"{data['weighted_score']:.1f}",
                'explanation': data['explanation']
            }
            for cat, data in category_scores.items()
        },
        'calculation_details': {
            'base_score': base_score,
            'escalation_factor': f"{escalation_factor:.2f}",
            'escalated_score': escalated_score,
            'overrides_applied': len(override_reasons),
            'reductions_applied': len(reduction_reasons),
            'final_score': final_score
        },
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    logger.info(f"Risk calculation complete: {risk_level} ({final_score}/100)")
    return result
