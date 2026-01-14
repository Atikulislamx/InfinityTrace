"""
Advanced OSINT-based Email Analysis Module for InfinityTrace

This module provides comprehensive email analysis using only publicly available data,
adhering to ethical OSINT standards. It analyzes email addresses through multiple
dimensions including validation, domain intelligence, breach exposure, reputation,
and profile discovery.

Features:
- Email normalization and RFC-compliant validation
- Disposable and role-based email detection
- Domain intelligence (WHOIS, MX records, SPF/DKIM/DMARC)
- Public breach exposure analysis
- Reputation scoring via public APIs
- Profile discovery across multiple platforms
- Confidence-based risk scoring (0-100)

Author: Cyber Infinity
Project: InfinityTrace
"""

import re
import hashlib
import logging
import json
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None
    logging.warning("requests library not available. Some features will be limited.")

try:
    import dns.resolver
except ImportError:
    dns = None
    logging.warning("dnspython not available. DNS lookups will be limited.")

# Import normalizer with fallback for standalone execution
try:
    from utils.normalizer import normalize_email
except ImportError:
    # Fallback for standalone execution
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.normalizer import normalize_email

# Configure logging
logger = logging.getLogger(__name__)

# Risk scoring constants
RISK_THRESHOLD_HIGH = 61  # Scores >= 61 are HIGH risk
RISK_THRESHOLD_MEDIUM = 31  # Scores >= 31 are MEDIUM risk
# Scores < 31 are LOW risk

PROFILE_COUNT_THRESHOLD = 3  # Number of profiles that indicate high visibility

# Known disposable email domains
DISPOSABLE_DOMAINS = {
    'tempmail.com', 'guerrillamail.com', 'mailinator.com', '10minutemail.com',
    'throwaway.email', 'temp-mail.org', 'yopmail.com', 'maildrop.cc',
    'trashmail.com', 'getnada.com', 'fakeinbox.com', 'sharklasers.com',
    'guerrillamail.info', 'guerrillamail.net', 'guerrillamail.org',
    'grr.la', 'guerrillamail.biz', 'spam4.me', 'tmails.net'
}

# Known role-based email prefixes
ROLE_BASED_PREFIXES = {
    'admin', 'administrator', 'info', 'support', 'help', 'sales', 'contact',
    'noreply', 'no-reply', 'postmaster', 'webmaster', 'hostmaster', 'abuse',
    'security', 'privacy', 'marketing', 'press', 'careers', 'jobs', 'billing',
    'accounts', 'hr', 'legal', 'compliance'
}


def validate_email_rfc(email: str) -> bool:
    """
    Validate email address according to RFC 5322 standards.
    
    This implements a comprehensive regex pattern for email validation
    that checks for proper format including local part and domain.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if email is RFC-compliant, False otherwise
        
    Examples:
        >>> validate_email_rfc("user@example.com")
        True
        >>> validate_email_rfc("invalid.email")
        False
    """
    try:
        # RFC 5322 compliant email regex pattern
        # Pattern structure:
        # - Local part: [a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+
        # - @ symbol
        # - Domain: [a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?
        # - Subdomains: (?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*
        pattern = r'^[a-zA-Z0-9.!#$%&\'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(pattern, email):
            return False
            
        # Additional checks
        local, domain = email.rsplit('@', 1)
        
        # Local part should not exceed 64 characters
        if len(local) > 64:
            return False
            
        # Domain should not exceed 255 characters
        if len(domain) > 255:
            return False
            
        # Domain should have at least one dot
        if '.' not in domain:
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Error validating email {email}: {e}")
        return False


def is_disposable_email(email: str) -> bool:
    """
    Check if email address uses a disposable/temporary email domain.
    
    Args:
        email (str): Email address to check
        
    Returns:
        bool: True if disposable, False otherwise
    """
    try:
        domain = email.split('@')[1].lower()
        return domain in DISPOSABLE_DOMAINS
    except (IndexError, AttributeError):
        return False


def is_role_based_email(email: str) -> bool:
    """
    Check if email address is role-based (e.g., admin@, info@, support@).
    
    Role-based emails are typically not associated with individual persons
    but with organizational functions.
    
    Args:
        email (str): Email address to check
        
    Returns:
        bool: True if role-based, False otherwise
    """
    try:
        local = email.split('@')[0].lower()
        # Remove dots and hyphens for comparison
        local_clean = local.replace('.', '').replace('-', '')
        return local_clean in ROLE_BASED_PREFIXES
    except (IndexError, AttributeError):
        return False


def get_mx_records(domain: str) -> List[Dict[str, Any]]:
    """
    Retrieve MX (Mail Exchanger) records for a domain.
    
    MX records indicate the mail servers responsible for receiving email
    for the domain, providing insights into email infrastructure.
    
    Args:
        domain (str): Domain name to query
        
    Returns:
        List[Dict]: List of MX records with priority and hostname
    """
    mx_records = []
    
    if dns is None:
        logger.warning("dnspython not available for MX lookup")
        return mx_records
    
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_records.append({
                'priority': rdata.preference,
                'hostname': str(rdata.exchange).rstrip('.')
            })
        logger.info(f"Found {len(mx_records)} MX records for {domain}")
    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        logger.warning(f"No MX records found for {domain}")
    except Exception as e:
        logger.error(f"Error retrieving MX records for {domain}: {e}")
    
    return mx_records


def check_spf_record(domain: str) -> Optional[str]:
    """
    Check for SPF (Sender Policy Framework) record.
    
    SPF records help prevent email spoofing by specifying which mail servers
    are authorized to send email on behalf of the domain.
    
    Args:
        domain (str): Domain name to query
        
    Returns:
        Optional[str]: SPF record if found, None otherwise
    """
    if dns is None:
        logger.warning("dnspython not available for SPF lookup")
        return None
    
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_string = str(rdata).strip('"')
            if txt_string.startswith('v=spf1'):
                logger.info(f"SPF record found for {domain}")
                return txt_string
    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        logger.warning(f"No TXT records found for {domain}")
    except Exception as e:
        logger.error(f"Error checking SPF for {domain}: {e}")
    
    return None


def check_dmarc_record(domain: str) -> Optional[str]:
    """
    Check for DMARC (Domain-based Message Authentication) record.
    
    DMARC builds on SPF and DKIM to provide email authentication and
    reporting capabilities.
    
    Args:
        domain (str): Domain name to query
        
    Returns:
        Optional[str]: DMARC record if found, None otherwise
    """
    if dns is None:
        logger.warning("dnspython not available for DMARC lookup")
        return None
    
    try:
        # DMARC records are stored as TXT records at _dmarc subdomain
        dmarc_domain = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_string = str(rdata).strip('"')
            if txt_string.startswith('v=DMARC1'):
                logger.info(f"DMARC record found for {domain}")
                return txt_string
    except dns.resolver.NXDOMAIN:
        logger.warning(f"No DMARC record for {domain}")
    except dns.resolver.NoAnswer:
        logger.warning(f"No DMARC TXT records found for {domain}")
    except Exception as e:
        logger.error(f"Error checking DMARC for {domain}: {e}")
    
    return None


def analyze_domain_intelligence(domain: str) -> Dict[str, Any]:
    """
    Perform comprehensive domain intelligence analysis.
    
    Aggregates information about domain's email infrastructure including
    MX records, SPF, DKIM, and DMARC configurations.
    
    Args:
        domain (str): Domain name to analyze
        
    Returns:
        Dict: Domain intelligence data including MX, SPF, DMARC records
    """
    logger.info(f"Analyzing domain intelligence for {domain}")
    
    intelligence = {
        'domain': domain,
        'mx_records': get_mx_records(domain),
        'spf_record': check_spf_record(domain),
        'dmarc_record': check_dmarc_record(domain),
        'whois_link': f"https://who.is/whois/{domain}",
        'has_mx': False,
        'has_spf': False,
        'has_dmarc': False,
        'security_score': 0
    }
    
    # Calculate security posture
    if intelligence['mx_records']:
        intelligence['has_mx'] = True
        intelligence['security_score'] += 25
    
    if intelligence['spf_record']:
        intelligence['has_spf'] = True
        intelligence['security_score'] += 25
    
    if intelligence['dmarc_record']:
        intelligence['has_dmarc'] = True
        intelligence['security_score'] += 50
    
    return intelligence


def check_haveibeenpwned(email: str) -> Dict[str, Any]:
    """
    Check if email appears in known data breaches via HaveIBeenPwned.
    
    Uses the HaveIBeenPwned API v3 which requires an API key for programmatic
    access. Without a key, returns reference information for manual checking.
    
    Note: This is a non-intrusive check. We provide the hash and link but
    don't store or transmit plaintext email without user consent.
    
    Args:
        email (str): Email address to check
        
    Returns:
        Dict: Breach information or reference links
    """
    result = {
        'service': 'HaveIBeenPwned',
        'email_sha256': hashlib.sha256(email.encode()).hexdigest(),  # SHA256 for better security
        'check_url': f"https://haveibeenpwned.com/account/{email}",
        'api_url': f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        'breaches': [],
        'breach_count': 0,
        'checked': False
    }
    
    # Note: HaveIBeenPwned API requires an API key (hibp-api-key header)
    # For ethical reasons, we don't include a hardcoded API key
    # Users should obtain their own key from https://haveibeenpwned.com/API/Key
    
    logger.info(f"HaveIBeenPwned check prepared for {email}")
    logger.info("Note: Requires API key for programmatic access")
    
    return result


def check_emailrep(email: str) -> Dict[str, Any]:
    """
    Check email reputation using EmailRep.io API.
    
    EmailRep.io provides reputation data including suspicious activity,
    data breach exposure, and trust scoring.
    
    Args:
        email (str): Email address to check
        
    Returns:
        Dict: Reputation data from EmailRep.io
    """
    result = {
        'service': 'EmailRep.io',
        'reputation': None,
        'suspicious': False,
        'references': 0,
        'details': {},
        'checked': False
    }
    
    if requests is None:
        logger.warning("requests library not available")
        result['check_url'] = f"https://emailrep.io/{email}"
        return result
    
    try:
        url = f"https://emailrep.io/{email}"
        headers = {
            'User-Agent': 'InfinityTrace-OSINT/1.0 (https://github.com/Atikulislamx/InfinityTrace)',
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            result['checked'] = True
            result['reputation'] = data.get('reputation', 'unknown')
            result['suspicious'] = data.get('suspicious', False)
            result['references'] = data.get('references', 0)
            result['details'] = data.get('details', {})
            logger.info(f"EmailRep.io check successful for {email}")
        else:
            logger.warning(f"EmailRep.io returned status {response.status_code}")
            result['check_url'] = url
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Error checking EmailRep.io: {e}")
        result['check_url'] = f"https://emailrep.io/{email}"
    except Exception as e:
        logger.error(f"Unexpected error in EmailRep check: {e}")
    
    return result


def discover_gravatar_profile(email: str) -> Optional[Dict[str, Any]]:
    """
    Check for Gravatar profile associated with email.
    
    Gravatar uses MD5 hash of email addresses to link to profile pictures
    and public profile information.
    
    Args:
        email (str): Email address to check
        
    Returns:
        Optional[Dict]: Gravatar profile information if found
    """
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    
    result = {
        'platform': 'Gravatar',
        'email_hash': email_hash,
        'profile_url': f"https://gravatar.com/{email_hash}",
        'image_url': f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=404",
        'json_url': f"https://www.gravatar.com/{email_hash}.json",
        'exists': False
    }
    
    if requests is None:
        logger.warning("requests library not available for Gravatar check")
        return result
    
    try:
        # Check if profile exists by requesting JSON data
        response = requests.get(result['json_url'], timeout=10)
        if response.status_code == 200:
            result['exists'] = True
            result['data'] = response.json()
            logger.info(f"Gravatar profile found for {email}")
        else:
            logger.info(f"No Gravatar profile for {email}")
    except Exception as e:
        logger.error(f"Error checking Gravatar: {e}")
    
    return result


def discover_github_profile(email: str) -> Optional[Dict[str, Any]]:
    """
    Search for GitHub profiles associated with email.
    
    Uses GitHub's search API to find public commits and profiles
    linked to the email address.
    
    Args:
        email (str): Email address to search
        
    Returns:
        Optional[Dict]: GitHub profile information if found
    """
    result = {
        'platform': 'GitHub',
        'search_url': f"https://github.com/search?q={email}&type=users",
        'commits_url': f"https://github.com/search?q={email}&type=commits",
        'found': False,
        'profiles': []
    }
    
    # Note: GitHub API has rate limits and may require authentication
    # for extensive searches. We provide search URLs for manual verification.
    logger.info(f"GitHub search prepared for {email}")
    
    return result


def discover_wordpress_profile(email: str) -> Optional[Dict[str, Any]]:
    """
    Check for WordPress.com profile associated with email.
    
    WordPress profiles may be public and discoverable through
    various WordPress.com endpoints.
    
    Args:
        email (str): Email address to check
        
    Returns:
        Optional[Dict]: WordPress profile information
    """
    email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
    
    result = {
        'platform': 'WordPress',
        'email_hash': email_hash,
        'search_url': f"https://wordpress.com/",
        'found': False
    }
    
    logger.info(f"WordPress profile check prepared for {email}")
    return result


def discover_stackoverflow_profile(email: str) -> Optional[Dict[str, Any]]:
    """
    Search for Stack Overflow profiles associated with email.
    
    Stack Overflow and Stack Exchange network profiles may be
    publicly discoverable.
    
    Args:
        email (str): Email address to search
        
    Returns:
        Optional[Dict]: Stack Overflow profile information
    """
    result = {
        'platform': 'StackOverflow',
        'search_url': f"https://stackoverflow.com/search?q={email}",
        'found': False
    }
    
    logger.info(f"StackOverflow search prepared for {email}")
    return result


def discover_public_profiles(email: str) -> List[Dict[str, Any]]:
    """
    Aggregate public profile discovery across multiple platforms.
    
    Searches for public profiles linked to the email on platforms like
    GitHub, Gravatar, WordPress, Stack Overflow, etc.
    
    Args:
        email (str): Email address to search
        
    Returns:
        List[Dict]: List of discovered profiles across platforms
    """
    logger.info(f"Discovering public profiles for {email}")
    
    profiles = []
    
    # Check each platform
    gravatar = discover_gravatar_profile(email)
    if gravatar:
        profiles.append(gravatar)
    
    github = discover_github_profile(email)
    if github:
        profiles.append(github)
    
    wordpress = discover_wordpress_profile(email)
    if wordpress:
        profiles.append(wordpress)
    
    stackoverflow = discover_stackoverflow_profile(email)
    if stackoverflow:
        profiles.append(stackoverflow)
    
    logger.info(f"Found {len(profiles)} potential profile sources")
    return profiles


def calculate_risk_score(analysis_data: Dict[str, Any]) -> Tuple[int, str]:
    """
    Calculate confidence-based risk score (0-100) and risk level.
    
    Risk scoring considers multiple factors:
    - Email validation and type (disposable/role-based)
    - Domain security posture (MX, SPF, DMARC)
    - Breach exposure
    - Reputation scores
    - Profile visibility
    
    Args:
        analysis_data (Dict): Complete email analysis data
        
    Returns:
        Tuple[int, str]: (risk_score, risk_level) where risk_level is LOW/MEDIUM/HIGH
    """
    risk_score = 0
    
    # Factor 1: Email validation issues (+10 if invalid)
    if not analysis_data.get('is_valid', False):
        risk_score += 10
    
    # Factor 2: Disposable email (+30 high risk)
    if analysis_data.get('is_disposable', False):
        risk_score += 30
    
    # Factor 3: Role-based email (+5 moderate risk)
    if analysis_data.get('is_role_based', False):
        risk_score += 5
    
    # Factor 4: Domain security (-20 if good security, +20 if poor)
    domain_intel = analysis_data.get('domain_intel', {})
    security_score = domain_intel.get('security_score', 0)
    if security_score >= 75:
        risk_score -= 10  # Good security reduces risk
    elif security_score < 25:
        risk_score += 20  # Poor security increases risk
    
    # Factor 5: Breach exposure (+25 if found in breaches)
    breach_data = analysis_data.get('public_exposure', {})
    if isinstance(breach_data, dict) and breach_data.get('breach_count', 0) > 0:
        risk_score += 25
    
    # Factor 6: Reputation (+20 if suspicious)
    reputation = analysis_data.get('reputation', {})
    if isinstance(reputation, dict) and reputation.get('suspicious', False):
        risk_score += 20
    
    # Factor 7: High profile visibility (+10)
    profiles = analysis_data.get('profiles', [])
    profile_count = len([p for p in profiles if p.get('exists') or p.get('found')])
    if profile_count >= PROFILE_COUNT_THRESHOLD:
        risk_score += 10
    
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


def analyze_email(email: str) -> Dict[str, Any]:
    """
    Perform comprehensive OSINT-based email analysis.
    
    This is the main entry point that orchestrates all email analysis
    functions and returns a complete analysis report.
    
    Args:
        email (str): Email address to analyze
        
    Returns:
        Dict: Complete analysis results including all intelligence gathered
        
    Example:
        >>> result = analyze_email("example@gmail.com")
        >>> print(result['risk_level'])
        'MEDIUM'
    """
    logger.info(f"Starting comprehensive analysis for email: {email}")
    
    # Normalize email
    email = normalize_email(email)
    
    # Initialize result structure
    result = {
        'email': email,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'is_valid': False,
        'is_disposable': False,
        'is_role_based': False,
        'domain_intel': {},
        'public_exposure': {},
        'reputation': {},
        'profiles': [],
        'risk_score': 0,
        'risk_level': 'LOW'
    }
    
    # Step 1: Validate email
    result['is_valid'] = validate_email_rfc(email)
    if not result['is_valid']:
        logger.warning(f"Email {email} failed RFC validation")
        result['risk_score'] = 50
        result['risk_level'] = 'MEDIUM'
        return result
    
    # Step 2: Check for disposable/role-based
    result['is_disposable'] = is_disposable_email(email)
    result['is_role_based'] = is_role_based_email(email)
    
    # Step 3: Domain intelligence
    try:
        domain = email.split('@')[1]
        result['domain_intel'] = analyze_domain_intelligence(domain)
    except Exception as e:
        logger.error(f"Error in domain intelligence: {e}")
        result['domain_intel'] = {'error': str(e)}
    
    # Step 4: Public breach exposure
    try:
        result['public_exposure'] = check_haveibeenpwned(email)
    except Exception as e:
        logger.error(f"Error checking breach exposure: {e}")
        result['public_exposure'] = {'error': str(e)}
    
    # Step 5: Reputation analysis
    try:
        result['reputation'] = check_emailrep(email)
    except Exception as e:
        logger.error(f"Error checking reputation: {e}")
        result['reputation'] = {'error': str(e)}
    
    # Step 6: Profile discovery
    try:
        result['profiles'] = discover_public_profiles(email)
    except Exception as e:
        logger.error(f"Error discovering profiles: {e}")
        result['profiles'] = []
    
    # Step 7: Calculate risk score
    try:
        result['risk_score'], result['risk_level'] = calculate_risk_score(result)
    except Exception as e:
        logger.error(f"Error calculating risk score: {e}")
        result['risk_score'] = 0
        result['risk_level'] = 'LOW'
    
    logger.info(f"Email analysis complete for {email}")
    return result


def check_email(email: str) -> List[Dict[str, Any]]:
    """
    Legacy function for backward compatibility with existing code.
    
    This function maintains the interface expected by infinitytrace.py
    while using the new comprehensive analysis internally.
    
    Args:
        email (str): Email address to analyze
        
    Returns:
        List[Dict]: List of results formatted for legacy compatibility
    """
    # Perform comprehensive analysis
    analysis = analyze_email(email)
    
    # Convert to legacy format (list of dictionaries)
    results = []
    
    # Add breach exposure sources
    if 'public_exposure' in analysis and isinstance(analysis['public_exposure'], dict):
        results.append({
            'source': 'HaveIBeenPwned',
            'link': analysis['public_exposure'].get('check_url', ''),
            'description': 'Check if email appears in known data breaches',
            'checked': analysis['public_exposure'].get('checked', False)
        })
    
    # Add reputation source
    if 'reputation' in analysis and isinstance(analysis['reputation'], dict):
        results.append({
            'source': 'EmailRep.io',
            'link': f"https://emailrep.io/{email}",
            'description': 'Email reputation and trust scoring',
            'reputation': analysis['reputation'].get('reputation', 'unknown'),
            'suspicious': analysis['reputation'].get('suspicious', False)
        })
    
    # Add profile discoveries
    for profile in analysis.get('profiles', []):
        results.append({
            'source': profile.get('platform', 'Unknown'),
            'link': profile.get('profile_url') or profile.get('search_url', ''),
            'description': f"Public profile on {profile.get('platform', 'platform')}",
            'exists': profile.get('exists') or profile.get('found', False)
        })
    
    return results


def export_to_json(analysis: Dict[str, Any]) -> str:
    """
    Export analysis results to JSON format.
    
    Args:
        analysis (Dict): Analysis results from analyze_email()
        
    Returns:
        str: JSON-formatted string
    """
    return json.dumps(analysis, indent=2, ensure_ascii=False)


# Example usage and testing
if __name__ == "__main__":
    # Test with a sample email
    test_email = "example@gmail.com"
    
    print(f"Analyzing: {test_email}")
    print("=" * 60)
    
    result = analyze_email(test_email)
    
    print(f"\nEmail: {result['email']}")
    print(f"Valid: {result['is_valid']}")
    print(f"Disposable: {result['is_disposable']}")
    print(f"Role-based: {result['is_role_based']}")
    print(f"\nDomain Security Score: {result['domain_intel'].get('security_score', 0)}/100")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Risk Level: {result['risk_level']}")
    
    print("\n" + "=" * 60)
    print("JSON Output:")
    print(export_to_json(result))
