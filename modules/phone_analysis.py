"""
Advanced OSINT-based Phone Number Analysis Module for InfinityTrace

This module provides comprehensive phone number analysis using only publicly available data,
adhering to ethical OSINT standards. It analyzes phone numbers through multiple
dimensions including validation, carrier detection, line type identification,
spam/scam reputation, and public mentions discovery.

Features:
- Phone number normalization to E.164 format
- Validation using phonenumbers library
- Country and region detection
- Carrier identification (when available via public data)
- Line type detection (mobile, fixed-line, VoIP, toll-free, etc.)
- Spam and scam reputation analysis via public databases
- Public mentions discovery across web sources
- Behavioral anomaly detection
- Confidence-based risk scoring (0-100)

Author: Cyber Infinity
Project: InfinityTrace
"""

import re
import logging
import json
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone

try:
    import phonenumbers
    from phonenumbers import (
        NumberParseException, 
        PhoneNumberType,
        PhoneNumberFormat,
        geocoder,
        carrier as phonenumbers_carrier,
        timezone as phonenumbers_timezone
    )
except ImportError:
    phonenumbers = None
    logging.warning("phonenumbers library not available. Phone analysis will be limited.")

try:
    import requests
except ImportError:
    requests = None
    logging.warning("requests library not available. Some features will be limited.")

# Import normalizer with fallback for standalone execution
try:
    from utils.normalizer import normalize_phone
except ImportError:
    # Fallback for standalone execution
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.normalizer import normalize_phone

# Configure logging
logger = logging.getLogger(__name__)

# Risk scoring constants
RISK_THRESHOLD_HIGH = 61  # Scores >= 61 are HIGH risk
RISK_THRESHOLD_MEDIUM = 31  # Scores >= 31 are MEDIUM risk
# Scores < 31 are LOW risk

# Known VoIP providers patterns (partial list for detection)
VOIP_CARRIERS = {
    'voip', 'skype', 'google voice', 'vonage', 'magicjack', 
    'ringcentral', 'grasshopper', 'bandwidth', 'twilio'
}

# Phone type mapping for better readability
if phonenumbers:
    PHONE_TYPE_NAMES = {
        PhoneNumberType.FIXED_LINE: "FIXED_LINE",
        PhoneNumberType.MOBILE: "MOBILE",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
        PhoneNumberType.TOLL_FREE: "TOLL_FREE",
        PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
        PhoneNumberType.SHARED_COST: "SHARED_COST",
        PhoneNumberType.VOIP: "VOIP",
        PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
        PhoneNumberType.PAGER: "PAGER",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "VOICEMAIL",
        PhoneNumberType.UNKNOWN: "UNKNOWN"
    }
else:
    PHONE_TYPE_NAMES = {}


def validate_phone_number(phone: str, region: Optional[str] = None) -> Tuple[bool, Optional[Any]]:
    """
    Validate phone number using phonenumbers library.
    
    Args:
        phone (str): Phone number to validate
        region (str, optional): Default region code (e.g., 'US', 'GB', 'BD')
        
    Returns:
        Tuple[bool, Optional[phonenumbers.PhoneNumber]]: (is_valid, parsed_number)
    """
    if phonenumbers is None:
        logger.warning("phonenumbers library not available")
        # Fallback to basic validation
        pattern = r'^\+?\d{7,15}$'
        is_valid = bool(re.match(pattern, phone.strip()))
        return is_valid, None
    
    try:
        # Parse the phone number
        parsed = phonenumbers.parse(phone, region)
        
        # Validate if it's a possible and valid number
        is_possible = phonenumbers.is_possible_number(parsed)
        is_valid = phonenumbers.is_valid_number(parsed)
        
        if is_valid:
            logger.info(f"Phone number {phone} is valid")
            return True, parsed
        elif is_possible:
            logger.warning(f"Phone number {phone} is possible but not fully valid")
            return True, parsed
        else:
            logger.warning(f"Phone number {phone} is not valid")
            return False, None
            
    except NumberParseException as e:
        logger.error(f"Error parsing phone number {phone}: {e}")
        return False, None
    except Exception as e:
        logger.error(f"Unexpected error validating phone number: {e}")
        return False, None


def normalize_to_e164(phone: str, region: Optional[str] = None) -> str:
    """
    Normalize phone number to E.164 format (+CCXXXXXXXXXX).
    
    E.164 is the international standard format for phone numbers.
    
    Args:
        phone (str): Phone number to normalize
        region (str, optional): Default region code
        
    Returns:
        str: Normalized phone number in E.164 format or original if parsing fails
    """
    if phonenumbers is None:
        # Fallback normalization - extract string from dict
        norm_result = normalize_phone(phone)
        if isinstance(norm_result, dict):
            return norm_result.get('normalized_phone', phone)
        return norm_result if norm_result else phone
    
    try:
        is_valid, parsed = validate_phone_number(phone, region)
        if is_valid and parsed:
            normalized = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
            logger.info(f"Normalized {phone} to {normalized}")
            return normalized
        else:
            # Return cleaned version if parsing fails - extract string from dict
            norm_result = normalize_phone(phone)
            if isinstance(norm_result, dict):
                return norm_result.get('normalized_phone', phone)
            return norm_result if norm_result else phone
    except Exception as e:
        logger.error(f"Error normalizing phone number: {e}")
        # Extract string from dict on error
        norm_result = normalize_phone(phone)
        if isinstance(norm_result, dict):
            return norm_result.get('normalized_phone', phone)
        return norm_result if norm_result else phone


def get_phone_metadata(phone: str, region: Optional[str] = None) -> Dict[str, Any]:
    """
    Extract comprehensive metadata from phone number.
    
    Includes country, region, carrier, line type, and timezone information.
    
    Args:
        phone (str): Phone number to analyze
        region (str, optional): Default region code
        
    Returns:
        Dict: Phone number metadata
    """
    metadata = {
        'country_code': None,
        'country_name': None,
        'region': None,
        'carrier': None,
        'line_type': 'UNKNOWN',
        'is_valid': False,
        'is_possible': False,
        'timezones': [],
        'e164_format': None,
        'international_format': None,
        'national_format': None
    }
    
    if phonenumbers is None:
        logger.warning("phonenumbers library not available for metadata extraction")
        metadata['e164_format'] = normalize_phone(phone)
        return metadata
    
    try:
        is_valid, parsed = validate_phone_number(phone, region)
        
        if not parsed:
            return metadata
        
        metadata['is_valid'] = is_valid
        metadata['is_possible'] = phonenumbers.is_possible_number(parsed)
        
        # Get country code and name
        metadata['country_code'] = parsed.country_code
        region_code = phonenumbers.region_code_for_number(parsed)
        
        # Get geographic region description
        metadata['region'] = geocoder.description_for_number(parsed, 'en')
        if not metadata['region']:
            metadata['region'] = region_code
        
        # Get carrier name (may not be available for all numbers)
        carrier_name = phonenumbers_carrier.name_for_number(parsed, 'en')
        if carrier_name:
            metadata['carrier'] = carrier_name
        
        # Get phone number type
        number_type = phonenumbers.number_type(parsed)
        metadata['line_type'] = PHONE_TYPE_NAMES.get(number_type, 'UNKNOWN')
        
        # Get timezones
        tz_list = phonenumbers_timezone.time_zones_for_number(parsed)
        metadata['timezones'] = list(tz_list) if tz_list else []
        
        # Format in different styles
        metadata['e164_format'] = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        metadata['international_format'] = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        metadata['national_format'] = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
        
        logger.info(f"Extracted metadata for {phone}: {metadata['region']}, {metadata['line_type']}")
        
    except Exception as e:
        logger.error(f"Error extracting phone metadata: {e}")
    
    return metadata


def detect_voip_virtual(phone_metadata: Dict[str, Any]) -> Dict[str, bool]:
    """
    Detect if phone number is VoIP, virtual, or potentially a burner.
    
    Uses line type information and carrier patterns to identify
    non-traditional phone numbers.
    
    Args:
        phone_metadata (Dict): Phone metadata from get_phone_metadata()
        
    Returns:
        Dict: Detection results with is_voip, is_virtual, potentially_burner flags
    """
    detection = {
        'is_voip': False,
        'is_virtual': False,
        'potentially_burner': False,
        'confidence': 'LOW'
    }
    
    line_type = phone_metadata.get('line_type', 'UNKNOWN')
    carrier = phone_metadata.get('carrier', '')
    carrier = carrier.lower() if carrier else ''
    
    # Check if explicitly marked as VoIP
    if line_type == 'VOIP':
        detection['is_voip'] = True
        detection['is_virtual'] = True
        detection['confidence'] = 'HIGH'
    
    # Check carrier name for VoIP indicators
    if carrier:
        for voip_keyword in VOIP_CARRIERS:
            if voip_keyword in carrier:
                detection['is_voip'] = True
                detection['is_virtual'] = True
                detection['confidence'] = 'MEDIUM'
                break
    
    # Toll-free and premium numbers are often virtual services
    if line_type in ['TOLL_FREE', 'PREMIUM_RATE', 'SHARED_COST']:
        detection['is_virtual'] = True
        detection['confidence'] = 'MEDIUM'
    
    # Burner detection is speculative based on VoIP status
    # True burner detection requires additional intelligence
    if detection['is_voip'] or detection['is_virtual']:
        detection['potentially_burner'] = True
    
    return detection


def check_spam_databases(phone: str) -> List[Dict[str, Any]]:
    """
    Check phone number against public spam and scam databases.
    
    Returns references to publicly available spam reporting services
    where the number can be checked manually or via their APIs.
    
    Args:
        phone (str): Phone number to check (should be normalized)
        
    Returns:
        List[Dict]: List of spam database references
    """
    spam_sources = []
    
    # TrueCaller - Public phone number lookup and spam reports
    spam_sources.append({
        'source': 'TrueCaller',
        'link': f"https://www.truecaller.com/search/phone/{phone}",
        'description': 'Public phone number lookup and spam reports',
        'type': 'spam_database'
    })
    
    # WhoCalledMe - Community-reported phone database
    spam_sources.append({
        'source': 'WhoCalledMe',
        'link': f"https://whocalled.us/lookup/{phone}",
        'description': 'Community-reported phone number database',
        'type': 'spam_database'
    })
    
    # 800Notes - Public phone spam database
    spam_sources.append({
        'source': '800Notes',
        'link': f"https://800notes.com/Phone.aspx/{phone}",
        'description': 'Public phone spam database',
        'type': 'spam_database'
    })
    
    # SpamCalls - International spam phone database
    spam_sources.append({
        'source': 'SpamCalls',
        'link': f"https://spamcalls.net/en/number/{phone}",
        'description': 'International spam phone database',
        'type': 'spam_database'
    })
    
    # Tellows - Spam identification community
    spam_sources.append({
        'source': 'Tellows',
        'link': f"https://www.tellows.com/num/{phone}",
        'description': 'Community-based spam phone identification',
        'type': 'spam_database'
    })
    
    # CallerSmart
    spam_sources.append({
        'source': 'CallerSmart',
        'link': f"https://www.callersmart.com/number/{phone}",
        'description': 'Caller ID and spam detection service',
        'type': 'spam_database'
    })
    
    logger.info(f"Generated {len(spam_sources)} spam database references for {phone}")
    return spam_sources


def discover_public_mentions(phone: str) -> List[Dict[str, Any]]:
    """
    Discover public mentions of phone number across web sources.
    
    Provides search URLs for forums, paste sites, and search engines
    where the phone number might be mentioned publicly.
    
    Args:
        phone (str): Phone number to search
        
    Returns:
        List[Dict]: List of public search sources
    """
    public_sources = []
    
    # Google Search
    google_query = phone.replace('+', '%2B')
    public_sources.append({
        'source': 'Google Search',
        'link': f"https://www.google.com/search?q={google_query}",
        'description': 'Search for public mentions on the web',
        'type': 'search_engine'
    })
    
    # DuckDuckGo Search (privacy-focused)
    public_sources.append({
        'source': 'DuckDuckGo',
        'link': f"https://duckduckgo.com/?q={phone}",
        'description': 'Privacy-focused search for public mentions',
        'type': 'search_engine'
    })
    
    # Social media search references
    public_sources.append({
        'source': 'Facebook',
        'link': f"https://www.facebook.com/search/top?q={phone}",
        'description': 'Search Facebook for public posts',
        'type': 'social_media'
    })
    
    public_sources.append({
        'source': 'Twitter/X',
        'link': f"https://twitter.com/search?q={phone}",
        'description': 'Search Twitter/X for public mentions',
        'type': 'social_media'
    })
    
    public_sources.append({
        'source': 'LinkedIn',
        'link': f"https://www.linkedin.com/search/results/all/?keywords={phone}",
        'description': 'Search LinkedIn for professional profiles',
        'type': 'social_media'
    })
    
    # Phone number directories
    public_sources.append({
        'source': 'WhitePages',
        'link': f"https://www.whitepages.com/phone/{phone}",
        'description': 'Public phone directory lookup',
        'type': 'directory'
    })
    
    logger.info(f"Generated {len(public_sources)} public mention sources for {phone}")
    return public_sources


def detect_behavioral_anomalies(phone_metadata: Dict[str, Any], voip_detection: Dict[str, bool]) -> List[str]:
    """
    Detect pattern-based behavioral anomalies.
    
    Analyzes phone characteristics to identify unusual patterns that might
    indicate suspicious activity or non-standard usage.
    
    Args:
        phone_metadata (Dict): Phone metadata
        voip_detection (Dict): VoIP detection results
        
    Returns:
        List[str]: List of detected anomalies
    """
    anomalies = []
    
    # Anomaly 1: Invalid or unparseable number
    if not phone_metadata.get('is_valid', False):
        anomalies.append("Phone number validation failed")
    
    # Anomaly 2: VoIP or virtual number
    if voip_detection.get('is_voip', False):
        anomalies.append("Number identified as VoIP service")
    
    if voip_detection.get('is_virtual', False) and not voip_detection.get('is_voip', False):
        anomalies.append("Number identified as virtual/non-standard service")
    
    # Anomaly 3: Premium rate or toll numbers
    line_type = phone_metadata.get('line_type', 'UNKNOWN')
    if line_type in ['PREMIUM_RATE', 'SHARED_COST']:
        anomalies.append(f"Premium or shared-cost number type: {line_type}")
    
    # Anomaly 4: No carrier information available
    if not phone_metadata.get('carrier') and phone_metadata.get('is_valid', False):
        if line_type == 'MOBILE':
            anomalies.append("No carrier information available for mobile number")
    
    # Anomaly 5: No geographic region
    if not phone_metadata.get('region'):
        anomalies.append("No geographic region associated with number")
    
    # Anomaly 6: Pager or legacy technology
    if line_type in ['PAGER', 'VOICEMAIL']:
        anomalies.append(f"Legacy or unusual number type: {line_type}")
    
    logger.info(f"Detected {len(anomalies)} behavioral anomalies")
    return anomalies


def calculate_risk_score(analysis_data: Dict[str, Any]) -> Tuple[int, str]:
    """
    Calculate confidence-based risk score (0-100) and risk level.
    
    Risk scoring considers multiple factors:
    - Phone validation status
    - Line type (VoIP, mobile, fixed-line)
    - VoIP/virtual/burner detection
    - Carrier availability
    - Behavioral anomalies
    - Geographic information availability
    
    Args:
        analysis_data (Dict): Complete phone analysis data
        
    Returns:
        Tuple[int, str]: (risk_score, risk_level) where risk_level is LOW/MEDIUM/HIGH
    """
    risk_score = 0
    
    metadata = analysis_data.get('metadata', {})
    voip_detection = analysis_data.get('voip_detection', {})
    anomalies = analysis_data.get('anomalies', [])
    
    # Factor 1: Invalid phone number (+30 high risk)
    if not metadata.get('is_valid', False):
        risk_score += 30
    
    # Factor 2: VoIP detection (+25 for VoIP, +15 for virtual)
    if voip_detection.get('is_voip', False):
        risk_score += 25
    elif voip_detection.get('is_virtual', False):
        risk_score += 15
    
    # Factor 3: Potentially burner phone (+20)
    if voip_detection.get('potentially_burner', False):
        risk_score += 20
    
    # Factor 4: Premium/Toll-free numbers (+10 moderate risk)
    line_type = metadata.get('line_type', 'UNKNOWN')
    if line_type in ['PREMIUM_RATE', 'TOLL_FREE', 'SHARED_COST']:
        risk_score += 10
    
    # Factor 5: Unknown line type (+5)
    if line_type == 'UNKNOWN':
        risk_score += 5
    
    # Factor 6: Missing carrier info for mobile (+10)
    if line_type == 'MOBILE' and not metadata.get('carrier'):
        risk_score += 10
    
    # Factor 7: Behavioral anomalies (+5 per anomaly, max +25)
    anomaly_score = min(len(anomalies) * 5, 25)
    risk_score += anomaly_score
    
    # Factor 8: No geographic info (+10)
    if not metadata.get('region'):
        risk_score += 10
    
    # Reduce risk for valid mobile/fixed-line with carrier (-10)
    if metadata.get('is_valid', False) and line_type in ['MOBILE', 'FIXED_LINE']:
        if metadata.get('carrier'):
            risk_score -= 10
    
    # Ensure score is within 0-100 range
    risk_score = max(0, min(100, risk_score))
    
    # Determine risk level using defined thresholds
    if risk_score >= RISK_THRESHOLD_HIGH:
        risk_level = 'HIGH'
    elif risk_score >= RISK_THRESHOLD_MEDIUM:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    logger.info(f"Calculated risk score: {risk_score}/100 ({risk_level})")
    return risk_score, risk_level


def analyze_phone(phone: str, region: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform comprehensive OSINT-based phone number analysis.
    
    This is the main entry point that orchestrates all phone analysis
    functions and returns a complete analysis report.
    
    Args:
        phone (str): Phone number to analyze
        region (str, optional): Default region code for parsing
        
    Returns:
        Dict: Complete analysis results including all intelligence gathered
        
    Example:
        >>> result = analyze_phone("+8801300228105")
        >>> print(result['risk_level'])
        'MEDIUM'
    """
    logger.info(f"Starting comprehensive analysis for phone: {phone}")
    
    # Normalize phone number
    normalized_phone = normalize_to_e164(phone, region)
    
    # Initialize result structure
    result = {
        'phone': normalized_phone,
        'original_input': phone,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'metadata': {},
        'voip_detection': {},
        'spam_databases': [],
        'public_mentions': [],
        'anomalies': [],
        'risk_score': 0,
        'risk_level': 'LOW'
    }
    
    # Step 1: Extract phone metadata (use normalized phone for consistency)
    try:
        result['metadata'] = get_phone_metadata(normalized_phone, region)
        logger.info(f"Metadata: {result['metadata']['region']}, {result['metadata']['line_type']}")
    except Exception as e:
        logger.error(f"Error extracting metadata: {e}")
        result['metadata'] = {'error': str(e)}
    
    # Step 2: Detect VoIP/Virtual/Burner
    try:
        result['voip_detection'] = detect_voip_virtual(result['metadata'])
        logger.info(f"VoIP detection: {result['voip_detection']}")
    except Exception as e:
        logger.error(f"Error in VoIP detection: {e}")
        result['voip_detection'] = {'error': str(e)}
    
    # Step 3: Check spam databases
    try:
        result['spam_databases'] = check_spam_databases(normalized_phone)
        logger.info(f"Found {len(result['spam_databases'])} spam database references")
    except Exception as e:
        logger.error(f"Error checking spam databases: {e}")
        result['spam_databases'] = []
    
    # Step 4: Discover public mentions
    try:
        result['public_mentions'] = discover_public_mentions(normalized_phone)
        logger.info(f"Found {len(result['public_mentions'])} public mention sources")
    except Exception as e:
        logger.error(f"Error discovering public mentions: {e}")
        result['public_mentions'] = []
    
    # Step 5: Detect behavioral anomalies
    try:
        result['anomalies'] = detect_behavioral_anomalies(
            result['metadata'], 
            result['voip_detection']
        )
        logger.info(f"Detected {len(result['anomalies'])} anomalies")
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        result['anomalies'] = []
    
    # Step 6: Calculate risk score
    try:
        result['risk_score'], result['risk_level'] = calculate_risk_score(result)
    except Exception as e:
        logger.error(f"Error calculating risk score: {e}")
        result['risk_score'] = 0
        result['risk_level'] = 'LOW'
    
    logger.info(f"Phone analysis complete for {phone}")
    return result


def check_phone(phone: str) -> List[Dict[str, Any]]:
    """
    Legacy function for backward compatibility with existing code.
    
    This function maintains the interface expected by infinitytrace.py
    while using the new comprehensive analysis internally.
    
    Args:
        phone (str): Phone number to analyze
        
    Returns:
        List[Dict]: List of results formatted for legacy compatibility
    """
    # Perform comprehensive analysis
    analysis = analyze_phone(phone)
    
    # Convert to legacy format (list of dictionaries)
    results = []
    
    # Add spam database references
    for spam_db in analysis.get('spam_databases', []):
        results.append({
            'source': spam_db.get('source', 'Unknown'),
            'link': spam_db.get('link', ''),
            'description': spam_db.get('description', ''),
            'type': spam_db.get('type', 'spam_database')
        })
    
    # Add public mention sources (limit to avoid overwhelming output)
    for mention in analysis.get('public_mentions', [])[:3]:  # Limit to 3 for brevity
        results.append({
            'source': mention.get('source', 'Unknown'),
            'link': mention.get('link', ''),
            'description': mention.get('description', ''),
            'type': mention.get('type', 'public_mention')
        })
    
    return results


def export_to_json(analysis: Dict[str, Any]) -> str:
    """
    Export analysis results to JSON format.
    
    Args:
        analysis (Dict): Analysis results from analyze_phone()
        
    Returns:
        str: JSON-formatted string
    """
    return json.dumps(analysis, indent=2, ensure_ascii=False)


# Example usage and testing
if __name__ == "__main__":
    # Test with sample phone numbers
    test_phones = [
        "+8801300228105",  # Bangladesh mobile
        "+14155552671",    # US number
        "+442071838750",   # UK number
    ]
    
    for test_phone in test_phones:
        print(f"\nAnalyzing: {test_phone}")
        print("=" * 60)
        
        result = analyze_phone(test_phone)
        
        metadata = result.get('metadata', {})
        voip = result.get('voip_detection', {})
        
        print(f"Phone: {result['phone']}")
        print(f"Valid: {metadata.get('is_valid', False)}")
        print(f"Country: {metadata.get('region', 'Unknown')}")
        print(f"Carrier: {metadata.get('carrier', 'Unknown')}")
        print(f"Line Type: {metadata.get('line_type', 'Unknown')}")
        print(f"VoIP: {voip.get('is_voip', False)}")
        print(f"Virtual: {voip.get('is_virtual', False)}")
        print(f"Spam Databases: {len(result.get('spam_databases', []))}")
        print(f"Public Mentions: {len(result.get('public_mentions', []))}")
        print(f"Anomalies: {len(result.get('anomalies', []))}")
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        
        if result.get('anomalies'):
            print("\nDetected Anomalies:")
            for anomaly in result['anomalies']:
                print(f"  - {anomaly}")
        
        print("\n" + "=" * 60)
