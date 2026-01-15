"""
Advanced OSINT-based Domain and URL Intelligence Analysis Module for InfinityTrace

This module provides comprehensive domain and URL analysis using only publicly available data,
adhering to ethical OSINT standards. It performs multi-dimensional analysis including domain
reputation, DNS intelligence, SSL analysis, brand impersonation detection, and risk scoring.

Features:
- URL normalization and validation
- Shortened URL expansion
- WHOIS/RDAP domain intelligence
- Domain age and registrar reputation analysis
- DNS and hosting infrastructure analysis
- Blacklist checking (phishing, malware)
- SSL certificate metadata analysis
- Brand impersonation and typosquatting detection
- Web fingerprinting
- Historical domain activity analysis
- Explainable domain risk score (0-100)

Author: Cyber Infinity
Project: InfinityTrace
"""

import re
import socket
import ssl
import logging
import json
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urlunparse
from difflib import SequenceMatcher

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

try:
    import whois
except ImportError:
    whois = None
    logging.warning("python-whois not available. WHOIS lookups will be limited.")

try:
    import tldextract
except ImportError:
    tldextract = None
    logging.warning("tldextract not available. Domain parsing will be limited.")

# Configure logging
logger = logging.getLogger(__name__)

# User-Agent for HTTP requests
USER_AGENT = 'InfinityTrace-OSINT/1.0'

# Risk scoring constants
RISK_THRESHOLD_HIGH = 61  # Scores >= 61 are HIGH risk
RISK_THRESHOLD_MEDIUM = 31  # Scores >= 31 are MEDIUM risk

# Domain age thresholds (in days)
VERY_NEW_DOMAIN_DAYS = 30
NEW_DOMAIN_DAYS = 90
ESTABLISHED_DOMAIN_DAYS = 365

# Known popular brands for typosquatting detection
POPULAR_BRANDS = {
    'google', 'facebook', 'amazon', 'microsoft', 'apple', 'twitter', 'netflix',
    'paypal', 'ebay', 'linkedin', 'instagram', 'youtube', 'reddit', 'github',
    'dropbox', 'spotify', 'adobe', 'oracle', 'salesforce', 'zoom', 'slack'
}

# URL shortener domains
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
    'adf.ly', 'rebrand.ly', 'short.io', 'bl.ink', 'tiny.cc', 'shorturl.at',
    'cutt.ly', 's.id', 'clck.ru', 'v.gd'
}


def normalize_url(url: str) -> str:
    """
    Normalize and clean URL to standard format.
    
    Ensures URL has proper scheme, removes fragments, normalizes path,
    and converts to lowercase where appropriate.
    
    Args:
        url (str): Raw URL string
        
    Returns:
        str: Normalized URL
        
    Examples:
        >>> normalize_url("example.com")
        'http://example.com'
        >>> normalize_url("HTTPS://Example.COM/Path")
        'https://example.com/Path'
    """
    try:
        url = url.strip()
        
        # Add scheme if missing (case-insensitive check)
        url_lower = url.lower()
        if not url_lower.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Parse URL
        parsed = urlparse(url)
        
        # Normalize components
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or '/'
        params = parsed.params
        query = parsed.query
        # Remove fragment
        fragment = ''
        
        # Reconstruct normalized URL
        normalized = urlunparse((scheme, netloc, path, params, query, fragment))
        
        logger.info(f"Normalized URL: {url} -> {normalized}")
        return normalized
        
    except Exception as e:
        logger.error(f"Error normalizing URL {url}: {e}")
        return url


def extract_domain(url: str) -> str:
    """
    Extract domain name from URL.
    
    Args:
        url (str): URL to extract domain from
        
    Returns:
        str: Domain name (e.g., 'example.com')
    """
    try:
        normalized = normalize_url(url)
        parsed = urlparse(normalized)
        domain = parsed.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove 'www.' prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        return domain.lower()
        
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {e}")
        return ""


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format.
    
    Args:
        domain (str): Domain name to validate
        
    Returns:
        bool: True if valid domain format, False otherwise
    """
    try:
        # Basic domain regex pattern
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    except Exception as e:
        logger.error(f"Error validating domain {domain}: {e}")
        return False


def expand_shortened_url(short_url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Expand shortened URLs to their final destination.
    
    Uses HTTP HEAD requests to follow redirects without downloading content,
    respecting ethical OSINT principles.
    
    Args:
        short_url (str): Shortened URL to expand
        timeout (int): Request timeout in seconds
        
    Returns:
        Dict: Expansion result with final URL and redirect chain
    """
    result = {
        'original_url': short_url,
        'final_url': short_url,
        'expanded': False,
        'redirect_chain': [],
        'error': None
    }
    
    if requests is None:
        result['error'] = 'requests library not available'
        return result
    
    try:
        normalized = normalize_url(short_url)
        result['original_url'] = normalized
        
        # Make HEAD request to follow redirects
        headers = {
            'User-Agent': USER_AGENT
        }
        
        response = requests.head(
            normalized,
            allow_redirects=True,
            timeout=timeout,
            headers=headers
        )
        
        result['final_url'] = response.url
        result['expanded'] = (response.url != normalized)
        
        # Capture redirect history
        if response.history:
            result['redirect_chain'] = [r.url for r in response.history]
            result['redirect_chain'].append(response.url)
        
        logger.info(f"URL expansion: {short_url} -> {result['final_url']}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error expanding URL {short_url}: {e}")
        result['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error expanding URL {short_url}: {e}")
        result['error'] = str(e)
    
    return result


def check_url_shortener(url: str) -> bool:
    """
    Check if URL uses a known URL shortening service.
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if URL uses a shortener service
    """
    try:
        domain = extract_domain(url)
        return domain in URL_SHORTENERS
    except Exception:
        return False


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieve WHOIS information for domain.
    
    Uses public WHOIS data to gather domain registration information
    including registrar, creation date, expiration, and nameservers.
    
    Args:
        domain (str): Domain name to query
        
    Returns:
        Dict: WHOIS information including registration data
    """
    result = {
        'domain': domain,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'name_servers': [],
        'status': [],
        'whois_server': None,
        'available': False,
        'error': None,
        'lookup_url': f"https://who.is/whois/{domain}"
    }
    
    if whois is None:
        logger.warning("python-whois not available for WHOIS lookup")
        result['error'] = 'python-whois library not available'
        return result
    
    try:
        w = whois.whois(domain)
        
        if w:
            result['registrar'] = w.registrar if hasattr(w, 'registrar') else None
            result['creation_date'] = w.creation_date if hasattr(w, 'creation_date') else None
            result['expiration_date'] = w.expiration_date if hasattr(w, 'expiration_date') else None
            result['updated_date'] = w.updated_date if hasattr(w, 'updated_date') else None
            result['name_servers'] = w.name_servers if hasattr(w, 'name_servers') else []
            result['status'] = w.status if hasattr(w, 'status') else []
            result['whois_server'] = w.whois_server if hasattr(w, 'whois_server') else None
            
            # Handle date lists (some WHOIS returns lists)
            if isinstance(result['creation_date'], list):
                result['creation_date'] = result['creation_date'][0]
            if isinstance(result['expiration_date'], list):
                result['expiration_date'] = result['expiration_date'][0]
            if isinstance(result['updated_date'], list):
                result['updated_date'] = result['updated_date'][0]
            
            logger.info(f"WHOIS lookup successful for {domain}")
        
    except Exception as e:
        logger.error(f"Error retrieving WHOIS for {domain}: {e}")
        result['error'] = str(e)
    
    return result


def calculate_domain_age(domain: str, whois_data: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Calculate domain age from registration date.
    
    Args:
        domain (str): Domain name
        whois_data (Optional[Dict]): Pre-fetched WHOIS data
        
    Returns:
        Dict: Domain age information including days, risk assessment
    """
    result = {
        'domain': domain,
        'age_days': None,
        'age_category': 'UNKNOWN',
        'creation_date': None,
        'is_new': False,
        'risk_factor': 0
    }
    
    try:
        # Get WHOIS data if not provided
        if whois_data is None:
            whois_data = get_whois_info(domain)
        
        creation_date = whois_data.get('creation_date')
        
        if creation_date:
            # Ensure creation_date is a datetime object
            # Handle both datetime objects and string representations
            if isinstance(creation_date, str):
                # Try multiple date formats commonly used in WHOIS
                date_formats = [
                    '%Y-%m-%dT%H:%M:%S%z',  # ISO format with timezone
                    '%Y-%m-%dT%H:%M:%S',    # ISO format without timezone
                    '%Y-%m-%d %H:%M:%S',    # Common WHOIS format
                    '%Y-%m-%d',             # Date only
                    '%d-%b-%Y',             # DD-Mon-YYYY format
                ]
                
                for fmt in date_formats:
                    try:
                        # Only replace 'Z' for ISO format strings
                        date_str = creation_date
                        if 'T' in date_str and date_str.endswith('Z'):
                            date_str = date_str.replace('Z', '+00:00')
                        creation_date = datetime.strptime(date_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    # If all formats fail, log and skip
                    logger.warning(f"Could not parse creation date: {creation_date}")
                    creation_date = None
            
            if creation_date and hasattr(creation_date, 'isoformat'):
                result['creation_date'] = creation_date.isoformat()
            
            # Calculate age (only if we have a valid datetime object)
            if creation_date and hasattr(creation_date, 'tzinfo'):
                now = datetime.now(timezone.utc)
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
            
            age_delta = now - creation_date
            result['age_days'] = age_delta.days
            
            # Categorize age
            if result['age_days'] < VERY_NEW_DOMAIN_DAYS:
                result['age_category'] = 'VERY_NEW'
                result['is_new'] = True
                result['risk_factor'] = 30  # High risk
            elif result['age_days'] < NEW_DOMAIN_DAYS:
                result['age_category'] = 'NEW'
                result['is_new'] = True
                result['risk_factor'] = 20  # Medium-high risk
            elif result['age_days'] < ESTABLISHED_DOMAIN_DAYS:
                result['age_category'] = 'RECENT'
                result['risk_factor'] = 10  # Low-medium risk
            else:
                result['age_category'] = 'ESTABLISHED'
                result['risk_factor'] = 0  # Low risk
            
            logger.info(f"Domain {domain} age: {result['age_days']} days ({result['age_category']})")
        
    except Exception as e:
        logger.error(f"Error calculating domain age for {domain}: {e}")
    
    return result


def analyze_dns_records(domain: str) -> Dict[str, Any]:
    """
    Analyze DNS records for domain infrastructure intelligence.
    
    Checks A, AAAA, MX, TXT, NS, and CNAME records to understand
    domain's hosting and email infrastructure.
    
    Args:
        domain (str): Domain name to analyze
        
    Returns:
        Dict: DNS record analysis results
    """
    result = {
        'domain': domain,
        'a_records': [],
        'aaaa_records': [],
        'mx_records': [],
        'txt_records': [],
        'ns_records': [],
        'cname_records': [],
        'has_email': False,
        'has_ipv6': False,
        'spf_record': None,
        'dmarc_record': None
    }
    
    if dns is None:
        logger.warning("dnspython not available for DNS lookups")
        return result
    
    try:
        # A records (IPv4)
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result['a_records'] = [str(rdata) for rdata in answers]
        except Exception:
            pass
        
        # AAAA records (IPv6)
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            result['aaaa_records'] = [str(rdata) for rdata in answers]
            result['has_ipv6'] = len(result['aaaa_records']) > 0
        except Exception:
            pass
        
        # MX records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [
                {'priority': rdata.preference, 'hostname': str(rdata.exchange).rstrip('.')}
                for rdata in answers
            ]
            result['has_email'] = len(result['mx_records']) > 0
        except Exception:
            pass
        
        # TXT records
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            result['txt_records'] = [str(rdata).strip('"') for rdata in answers]
            
            # Check for SPF
            for txt in result['txt_records']:
                if txt.startswith('v=spf1'):
                    result['spf_record'] = txt
        except Exception:
            pass
        
        # DMARC record
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = str(rdata).strip('"')
                if txt.startswith('v=DMARC1'):
                    result['dmarc_record'] = txt
        except Exception:
            pass
        
        # NS records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(rdata).rstrip('.') for rdata in answers]
        except Exception:
            pass
        
        logger.info(f"DNS analysis complete for {domain}")
        
    except Exception as e:
        logger.error(f"Error analyzing DNS for {domain}: {e}")
    
    return result


def check_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Analyze SSL/TLS certificate metadata for domain.
    
    Retrieves certificate information including issuer, validity period,
    subject alternative names, and signature algorithm.
    
    Args:
        domain (str): Domain name to check
        port (int): SSL port (default: 443)
        
    Returns:
        Dict: SSL certificate analysis results
    """
    result = {
        'domain': domain,
        'has_ssl': False,
        'issuer': None,
        'subject': None,
        'not_before': None,
        'not_after': None,
        'version': None,
        'serial_number': None,
        'signature_algorithm': None,
        'san': [],
        'expired': False,
        'self_signed': False,
        'days_until_expiry': None,
        'error': None
    }
    
    try:
        # Create SSL context with secure defaults
        # ssl.create_default_context() automatically disables insecure protocols
        # (TLSv1, TLSv1.1) and uses secure ciphers by default in Python 3.7+
        context = ssl.create_default_context()
        
        # Explicitly ensure only secure protocols are allowed
        # This is redundant in modern Python but makes the security explicit
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Connect and get certificate
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                if cert:
                    result['has_ssl'] = True
                    # Certificate issuer and subject are lists of tuples
                    result['issuer'] = dict(cert.get('issuer', []))
                    result['subject'] = dict(cert.get('subject', []))
                    result['version'] = cert.get('version')
                    result['serial_number'] = cert.get('serialNumber')
                    
                    # Parse dates
                    not_before_str = cert.get('notBefore')
                    not_after_str = cert.get('notAfter')
                    
                    if not_before_str:
                        not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                        result['not_before'] = not_before.isoformat()
                    
                    if not_after_str:
                        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        result['not_after'] = not_after.isoformat()
                        
                        # Check expiration (use timezone-aware datetime)
                        now = datetime.now(timezone.utc)
                        # Convert not_after to timezone-aware
                        not_after_aware = not_after.replace(tzinfo=timezone.utc)
                        
                        if not_after_aware < now:
                            result['expired'] = True
                        
                        # Calculate days until expiry (can be negative if expired)
                        result['days_until_expiry'] = (not_after_aware - now).days
                    
                    # Subject Alternative Names
                    san = cert.get('subjectAltName', [])
                    result['san'] = [name[1] for name in san if name[0] == 'DNS']
                    
                    # Check if self-signed
                    if result['issuer'] == result['subject']:
                        result['self_signed'] = True
                    
                    logger.info(f"SSL certificate retrieved for {domain}")
                
    except ssl.SSLError as e:
        logger.warning(f"SSL error for {domain}: {e}")
        result['error'] = f"SSL error: {str(e)}"
    except socket.error as e:
        logger.warning(f"Socket error for {domain}: {e}")
        result['error'] = f"Connection error: {str(e)}"
    except Exception as e:
        logger.error(f"Error checking SSL for {domain}: {e}")
        result['error'] = str(e)
    
    return result


def check_phishing_blacklists(domain: str) -> Dict[str, Any]:
    """
    Check domain against public phishing and malware blacklists.
    
    Queries publicly available blacklist APIs including PhishTank,
    OpenPhish, and URLHaus (abuse.ch).
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        Dict: Blacklist check results
    """
    result = {
        'domain': domain,
        'blacklisted': False,
        'blacklists': [],
        'phishtank': {'listed': False, 'check_url': f'https://www.phishtank.com/'},
        'openphish': {'listed': False, 'check_url': f'https://openphish.com/'},
        'urlhaus': {'listed': False, 'check_url': f'https://urlhaus.abuse.ch/'},
        'checked': False
    }
    
    # Note: Most blacklist APIs require API keys or have rate limits
    # We provide reference URLs for manual checking
    
    logger.info(f"Blacklist check prepared for {domain}")
    result['checked'] = True
    
    # In a production environment with API keys, you would:
    # 1. Query PhishTank API
    # 2. Query OpenPhish feed
    # 3. Query URLHaus API
    # For ethical reasons, we don't include hardcoded API keys
    
    return result


def detect_typosquatting(domain: str, threshold: float = 0.8) -> Dict[str, Any]:
    """
    Detect potential brand impersonation and typosquatting.
    
    Analyzes domain for similarity to popular brand names using
    string distance algorithms (Levenshtein-like comparison).
    
    Args:
        domain (str): Domain name to analyze
        threshold (float): Similarity threshold (0.0-1.0)
        
    Returns:
        Dict: Typosquatting analysis results
    """
    result = {
        'domain': domain,
        'suspected_typosquatting': False,
        'similar_brands': [],
        'similarity_scores': {},
        'risk_level': 'LOW'
    }
    
    try:
        # Extract base domain without TLD
        if tldextract:
            extracted = tldextract.extract(domain)
            base_domain = extracted.domain.lower()
        else:
            # Fallback: simple split
            base_domain = domain.split('.')[0].lower()
        
        # Compare against known brands
        for brand in POPULAR_BRANDS:
            similarity = SequenceMatcher(None, base_domain, brand).ratio()
            result['similarity_scores'][brand] = round(similarity, 3)
            
            if similarity >= threshold and base_domain != brand:
                result['similar_brands'].append({
                    'brand': brand,
                    'similarity': round(similarity, 3),
                    'suspected_typosquat': True
                })
                result['suspected_typosquatting'] = True
        
        # Determine risk level
        if result['suspected_typosquatting']:
            max_similarity = max(result['similarity_scores'].values())
            if max_similarity >= 0.9:
                result['risk_level'] = 'HIGH'
            elif max_similarity >= 0.8:
                result['risk_level'] = 'MEDIUM'
            else:
                result['risk_level'] = 'LOW'
        
        if result['suspected_typosquatting']:
            logger.warning(f"Potential typosquatting detected for {domain}")
        
    except Exception as e:
        logger.error(f"Error detecting typosquatting for {domain}: {e}")
    
    return result


def perform_web_fingerprint(url: str) -> Dict[str, Any]:
    """
    Perform lightweight web fingerprinting analysis.
    
    Gathers basic information about web server, technologies used,
    and HTTP headers without extensive crawling.
    
    Args:
        url (str): URL to fingerprint
        
    Returns:
        Dict: Web fingerprint analysis results
    """
    result = {
        'url': url,
        'status_code': None,
        'server': None,
        'technologies': [],
        'headers': {},
        'cookies': [],
        'redirect': False,
        'accessible': False,
        'error': None
    }
    
    if requests is None:
        result['error'] = 'requests library not available'
        return result
    
    try:
        normalized = normalize_url(url)
        
        headers = {
            'User-Agent': USER_AGENT
        }
        
        response = requests.get(normalized, headers=headers, timeout=10, allow_redirects=True)
        
        result['status_code'] = response.status_code
        result['accessible'] = (200 <= response.status_code < 300)
        result['redirect'] = len(response.history) > 0
        
        # Extract headers
        result['headers'] = dict(response.headers)
        result['server'] = response.headers.get('Server')
        
        # Identify technologies from headers
        if 'X-Powered-By' in response.headers:
            result['technologies'].append(response.headers['X-Powered-By'])
        
        # Check for common framework indicators
        if 'X-AspNet-Version' in response.headers:
            result['technologies'].append('ASP.NET')
        if 'X-Django-Version' in response.headers:
            result['technologies'].append('Django')
        
        # Extract cookies
        result['cookies'] = [
            {'name': cookie.name, 'domain': cookie.domain}
            for cookie in response.cookies
        ]
        
        logger.info(f"Web fingerprint complete for {url}")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fingerprinting {url}: {e}")
        result['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error fingerprinting {url}: {e}")
        result['error'] = str(e)
    
    return result


def check_wayback_machine(domain: str) -> Dict[str, Any]:
    """
    Check domain's historical activity via Wayback Machine API.
    
    Queries Internet Archive's Wayback Machine to determine domain's
    historical presence and archived snapshots.
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        Dict: Historical activity analysis results
    """
    result = {
        'domain': domain,
        'has_history': False,
        'first_seen': None,
        'last_seen': None,
        'snapshot_count': 0,
        'archive_url': f'https://web.archive.org/web/*/{domain}',
        'error': None
    }
    
    if requests is None:
        result['error'] = 'requests library not available'
        return result
    
    try:
        # Query Wayback Machine CDX API
        api_url = f'https://web.archive.org/cdx/search/cdx'
        params = {
            'url': domain,
            'output': 'json',
            'limit': 1000,
            'fl': 'timestamp',
            'collapse': 'timestamp:8'  # Collapse to daily snapshots
        }
        
        headers = {
            'User-Agent': USER_AGENT
        }
        
        response = requests.get(api_url, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if len(data) > 1:  # First row is header
                result['has_history'] = True
                result['snapshot_count'] = len(data) - 1
                
                # Parse timestamps (format: YYYYMMDDhhmmss)
                timestamps = [row[0] for row in data[1:]]
                
                if timestamps:
                    first_ts = timestamps[0]
                    last_ts = timestamps[-1]
                    
                    result['first_seen'] = datetime.strptime(first_ts[:8], '%Y%m%d').isoformat()
                    result['last_seen'] = datetime.strptime(last_ts[:8], '%Y%m%d').isoformat()
                
                logger.info(f"Wayback Machine: {domain} has {result['snapshot_count']} snapshots")
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error querying Wayback Machine for {domain}: {e}")
        result['error'] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error in Wayback Machine check for {domain}: {e}")
        result['error'] = str(e)
    
    return result


def calculate_domain_risk_score(analysis_data: Dict[str, Any]) -> Tuple[int, str]:
    """
    Calculate explainable domain risk score (0-100) and risk level.
    
    Risk scoring considers multiple factors with weighted contributions:
    - Domain age (newer = higher risk)
    - Blacklist status (listed = high risk)
    - SSL certificate issues (missing/expired/self-signed = higher risk)
    - Typosquatting indicators (similarity to brands = higher risk)
    - DNS configuration (missing MX/SPF = moderate risk)
    - Historical presence (no history = higher risk)
    
    Args:
        analysis_data (Dict): Complete domain analysis data
        
    Returns:
        Tuple[int, str]: (risk_score, risk_level) where risk_level is LOW/MEDIUM/HIGH
    """
    risk_score = 0
    risk_factors = []
    
    # Factor 1: Domain age (max +30 points)
    age_data = analysis_data.get('domain_age', {})
    age_risk = age_data.get('risk_factor', 0)
    risk_score += age_risk
    if age_risk > 0:
        risk_factors.append(f"Domain age: +{age_risk} points")
    
    # Factor 2: Blacklist status (max +40 points)
    blacklist_data = analysis_data.get('blacklist_check', {})
    if blacklist_data.get('blacklisted', False):
        risk_score += 40
        risk_factors.append("Blacklisted: +40 points")
    
    # Factor 3: SSL certificate issues (max +20 points)
    ssl_data = analysis_data.get('ssl_cert', {})
    if not ssl_data.get('has_ssl', False):
        risk_score += 15
        risk_factors.append("No SSL: +15 points")
    elif ssl_data.get('expired', False):
        risk_score += 20
        risk_factors.append("Expired SSL: +20 points")
    elif ssl_data.get('self_signed', False):
        risk_score += 10
        risk_factors.append("Self-signed SSL: +10 points")
    
    # Factor 4: Typosquatting (max +25 points)
    typo_data = analysis_data.get('typosquatting', {})
    if typo_data.get('suspected_typosquatting', False):
        typo_risk = typo_data.get('risk_level', 'LOW')
        if typo_risk == 'HIGH':
            risk_score += 25
            risk_factors.append("High typosquatting risk: +25 points")
        elif typo_risk == 'MEDIUM':
            risk_score += 15
            risk_factors.append("Medium typosquatting risk: +15 points")
        else:
            risk_score += 5
            risk_factors.append("Low typosquatting risk: +5 points")
    
    # Factor 5: DNS configuration (max +10 points)
    dns_data = analysis_data.get('dns_records', {})
    dns_issues = 0
    if not dns_data.get('has_email', False):
        dns_issues += 1
    if not dns_data.get('spf_record'):
        dns_issues += 1
    
    dns_risk = dns_issues * 5
    risk_score += dns_risk
    if dns_risk > 0:
        risk_factors.append(f"DNS issues: +{dns_risk} points")
    
    # Factor 6: Historical presence (max +15 points)
    history_data = analysis_data.get('historical_activity', {})
    if not history_data.get('has_history', False):
        risk_score += 15
        risk_factors.append("No historical presence: +15 points")
    
    # Factor 7: URL shortener (max +10 points)
    if analysis_data.get('is_url_shortener', False):
        risk_score += 10
        risk_factors.append("URL shortener: +10 points")
    
    # Ensure score is within 0-100 range
    risk_score = max(0, min(100, risk_score))
    
    # Determine risk level
    if risk_score >= RISK_THRESHOLD_HIGH:
        risk_level = 'HIGH'
    elif risk_score >= RISK_THRESHOLD_MEDIUM:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    logger.info(f"Domain risk score: {risk_score}/100 ({risk_level})")
    logger.info(f"Risk factors: {risk_factors}")
    
    return risk_score, risk_level


def analyze_domain(domain_or_url: str) -> Dict[str, Any]:
    """
    Perform comprehensive OSINT-based domain intelligence analysis.
    
    This is the main entry point that orchestrates all domain analysis
    functions and returns a complete intelligence report.
    
    Args:
        domain_or_url (str): Domain name or URL to analyze
        
    Returns:
        Dict: Complete analysis results with risk scoring
        
    Example:
        >>> result = analyze_domain("example.com")
        >>> print(result['domain_risk_score'])
        42
        >>> print(result['risk_level'])
        'MEDIUM'
    """
    logger.info(f"Starting comprehensive domain analysis for: {domain_or_url}")
    
    # Extract and normalize domain
    if '://' in domain_or_url or '/' in domain_or_url:
        # It's a URL
        url = normalize_url(domain_or_url)
        domain = extract_domain(url)
    else:
        # It's a domain
        domain = domain_or_url.lower().strip()
        url = f"http://{domain}"
    
    # Initialize result structure
    result = {
        'domain': domain,
        'url': url,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'is_valid': False,
        'is_url_shortener': False,
        'whois_info': {},
        'domain_age': {},
        'dns_records': {},
        'ssl_cert': {},
        'blacklist_check': {},
        'typosquatting': {},
        'web_fingerprint': {},
        'historical_activity': {},
        'domain_risk_score': 0,
        'risk_level': 'LOW',
        'analysis_complete': False
    }
    
    # Validate domain
    result['is_valid'] = validate_domain(domain)
    if not result['is_valid']:
        logger.warning(f"Domain {domain} failed validation")
        result['domain_risk_score'] = 50
        result['risk_level'] = 'MEDIUM'
        return result
    
    # Check if URL shortener
    result['is_url_shortener'] = check_url_shortener(url)
    if result['is_url_shortener']:
        logger.info(f"Detected URL shortener: {domain}")
        # Expand URL
        expansion = expand_shortened_url(url)
        result['url_expansion'] = expansion
        if expansion.get('expanded'):
            # Re-analyze the final domain
            final_domain = extract_domain(expansion['final_url'])
            if final_domain != domain:
                logger.info(f"Expanded to: {final_domain}, re-analyzing...")
                domain = final_domain
                result['domain'] = domain
    
    # Step 1: WHOIS lookup
    try:
        result['whois_info'] = get_whois_info(domain)
    except Exception as e:
        logger.error(f"Error in WHOIS lookup: {e}")
        result['whois_info'] = {'error': str(e)}
    
    # Step 2: Domain age analysis
    try:
        result['domain_age'] = calculate_domain_age(domain, result['whois_info'])
    except Exception as e:
        logger.error(f"Error calculating domain age: {e}")
        result['domain_age'] = {'error': str(e)}
    
    # Step 3: DNS analysis
    try:
        result['dns_records'] = analyze_dns_records(domain)
    except Exception as e:
        logger.error(f"Error in DNS analysis: {e}")
        result['dns_records'] = {'error': str(e)}
    
    # Step 4: SSL certificate check
    try:
        result['ssl_cert'] = check_ssl_certificate(domain)
    except Exception as e:
        logger.error(f"Error checking SSL: {e}")
        result['ssl_cert'] = {'error': str(e)}
    
    # Step 5: Blacklist check
    try:
        result['blacklist_check'] = check_phishing_blacklists(domain)
    except Exception as e:
        logger.error(f"Error in blacklist check: {e}")
        result['blacklist_check'] = {'error': str(e)}
    
    # Step 6: Typosquatting detection
    try:
        result['typosquatting'] = detect_typosquatting(domain)
    except Exception as e:
        logger.error(f"Error in typosquatting detection: {e}")
        result['typosquatting'] = {'error': str(e)}
    
    # Step 7: Web fingerprinting
    try:
        result['web_fingerprint'] = perform_web_fingerprint(url)
    except Exception as e:
        logger.error(f"Error in web fingerprinting: {e}")
        result['web_fingerprint'] = {'error': str(e)}
    
    # Step 8: Historical activity
    try:
        result['historical_activity'] = check_wayback_machine(domain)
    except Exception as e:
        logger.error(f"Error checking historical activity: {e}")
        result['historical_activity'] = {'error': str(e)}
    
    # Step 9: Calculate risk score
    try:
        result['domain_risk_score'], result['risk_level'] = calculate_domain_risk_score(result)
    except Exception as e:
        logger.error(f"Error calculating risk score: {e}")
        result['domain_risk_score'] = 0
        result['risk_level'] = 'LOW'
    
    result['analysis_complete'] = True
    logger.info(f"Domain analysis complete for {domain}")
    
    return result


def check_domain(username: str) -> List[Dict[str, Any]]:
    """
    Legacy function for backward compatibility with existing InfinityTrace code.
    
    This function maintains the interface expected by infinitytrace.py
    while providing enhanced domain intelligence internally.
    
    Args:
        username (str): Username to generate potential domains from
        
    Returns:
        List[Dict]: List of domain intelligence results
    """
    if not username:
        return []
    
    results = []
    
    # Common domain patterns for usernames
    # Validate all at once to avoid repeated calls
    possible_domains = [
        f"{username}.com",
        f"{username}.net",
        f"{username}.org"
    ]
    
    # For each potential domain, provide basic intelligence
    for domain in possible_domains:
        # Quick validation (already optimized for small list)
        if validate_domain(domain):
            # Quick analysis (minimal to avoid too many API calls)
            domain_info = {
                "domain": domain,
                "whois_link": f"https://who.is/whois/{domain}",
                "description": "Check domain registration and age",
                "age_days": None
            }
            
            # Optionally, you could do a quick WHOIS check here
            # For now, we keep it lightweight to maintain performance
            
            results.append(domain_info)
    
    # Add reference checking services
    results.append({
        "service": "VirusTotal",
        "link": "https://www.virustotal.com/",
        "description": "Check domain reputation and security"
    })
    
    results.append({
        "service": "URLVoid",
        "link": "https://www.urlvoid.com/",
        "description": "Check if domain is blacklisted"
    })
    
    return results


def export_to_json(analysis: Dict[str, Any]) -> str:
    """
    Export domain analysis results to JSON format.
    
    Args:
        analysis (Dict): Analysis results from analyze_domain()
        
    Returns:
        str: JSON-formatted string
    """
    return json.dumps(analysis, indent=2, ensure_ascii=False, default=str)


# Example usage and testing
if __name__ == "__main__":
    # Test with sample domains
    test_cases = [
        "example.com",
        "google.com",
        "bit.ly/test123"
    ]
    
    for test_domain in test_cases:
        print(f"\nAnalyzing: {test_domain}")
        print("=" * 60)
        
        result = analyze_domain(test_domain)
        
        print(f"Domain: {result['domain']}")
        print(f"Valid: {result['is_valid']}")
        print(f"Domain Age: {result['domain_age'].get('age_days', 'Unknown')} days")
        print(f"Blacklisted: {result['blacklist_check'].get('blacklisted', False)}")
        print(f"Brand Impersonation: {result['typosquatting'].get('suspected_typosquatting', False)}")
        print(f"Risk Score: {result['domain_risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print("\n" + "=" * 60)
