"""
validators.py — Advanced Heuristic Validation Engine for Normalized OSINT Inputs

Purpose:
    Evaluates trustworthiness, plausibility, and risk for normalized data (username, email, phone, domain, URL, name, image input)
    using local heuristics. No external/premium APIs. Designed for OSINT, risk, and trust analysis.

Features:
    - Each validation returns a JSON-serializable dict:
        {
          "valid": bool,
          "confidence": float [0–1],
          "risk_flags": [str],
          "notes": str
        }
    - Defensive coding, graceful failure, logging-ready.
    - OSINT compliant, analyst-supportive (not authoritative).

Typical fields accepted:
    - username, email, phone, domain, url, name, image_input

Author: InfinityTrace Project Team
"""

import re
import math
import mimetypes
import os
from typing import Optional, Dict, Any, List

try:
    import phonenumbers
except ImportError:
    phonenumbers = None

# Import configuration
from config import (
    DISPOSABLE_EMAIL_DOMAINS, SUSPICIOUS_TLDS, URL_SHORTENERS,
    ROLE_BASED_EMAIL_PREFIXES
)

RE_MIME_IMAGE = re.compile(r'^image\/')

def _entropy(s: str) -> float:
    """
    Calculate Shannon entropy for input string
    """
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    probs = [f / len(s) for f in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def _risk_response(valid: bool, confidence: float, risk_flags: List[str], notes: str) -> Dict[str, Any]:
    return {
        "valid": valid,
        "confidence": max(0.0, min(1.0, round(confidence, 2))),
        "risk_flags": risk_flags,
        "notes": notes
    }

def validate_username(username: str) -> Dict[str, Any]:
    """
    Validate username: regex, length, entropy, bot pattern heuristics
    """
    risk_flags = []
    notes = []
    if not username or not isinstance(username, str):
        return _risk_response(False, 0.0, ["empty"], "Username missing or not a string.")

    # Syntax
    pattern = r"^[a-zA-Z0-9_.-]{3,30}$"
    valid = bool(re.match(pattern, username))
    if not valid:
        risk_flags.append("invalid_syntax")
        notes.append("Username does not match allowed format.")

    # Length heuristics
    if len(username) < 4:
        risk_flags.append("too_short")
        notes.append("Unusually short username.")

    # Bot/entropy heuristics
    ent = _entropy(username)
    if ent > 3.6:
        risk_flags.append("high_entropy")
        notes.append(f"Username entropy ({ent:.2f}) is suspiciously high.")
        confidence = 0.45 if valid else 0.25
    elif re.match(r"^[a-z]+\d{2,}$", username):
        risk_flags.append("bot_pattern")
        notes.append("Username resembles auto-generated/bot pattern.")
        confidence = 0.55 if valid else 0.3
    else:
        confidence = 0.8 if valid else 0.5

    return _risk_response(valid, confidence, risk_flags, "; ".join(notes))

def validate_email(email: str) -> Dict[str, Any]:
    """
    Validates Email: RFC format, disposable, typo-squatting heuristics
    """
    risk_flags = []
    notes = []

    if not email or not isinstance(email, str):
        return _risk_response(False, 0.0, ["empty"], "Email missing or not a string.")

    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    valid = bool(re.match(pattern, email))
    confidence = 0.7 if valid else 0.0

    try:
        local_part, domain = email.rsplit('@', 1)
    except Exception:
        domain = ""
        risk_flags.append("invalid_format")
        notes.append("Cannot extract email domain.")

    # Disposable detection
    disp_flag = False
    if domain.lower() in DISPOSABLE_EMAIL_DOMAINS:
        risk_flags.append("disposable_email")
        notes.append("Email domain appears disposable.")
        confidence -= 0.4
        disp_flag = True

    # Typo-squatting detection (simple: missing common mail domains)
    if not disp_flag and domain and re.search(r'gmali|hotnail|yaoo|outlok', domain):
        risk_flags.append("typosquatting")
        notes.append("Possible typo-squatting domain in email.")
        confidence -= 0.5

    return _risk_response(valid, max(confidence, 0.0), risk_flags, "; ".join(notes))

def validate_phone(phone: str, region: Optional[str]=None) -> Dict[str, Any]:
    """
    Phone: phonenumbers validation, region sanity, basic pattern fallback.
    """
    risk_flags = []
    notes = []

    valid = False
    confidence = 0.5 if phone else 0.0

    pattern = r"^\+?\d{7,16}$"
    if not phone or not isinstance(phone, str):
        return _risk_response(False, 0.0, ["empty"], "Phone missing or not a string.")

    if phonenumbers:
        try:
            parsed = phonenumbers.parse(phone, region)
            valid = phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed)
            region_code = phonenumbers.region_code_for_number(parsed)
            if region and region != region_code:
                risk_flags.append("region_mismatch")
                notes.append(f"Region '{region}' does not match phone detected region '{region_code}'.")
                confidence -= 0.3
            confidence += 0.2 if valid else -0.2
        except phonenumbers.NumberParseException:
            notes.append("Phonenumbers parse failed; fallback to regex.")
            valid = bool(re.match(pattern, phone))
            risk_flags.append("parse_fail")
            confidence -= 0.15
    else:
        valid = bool(re.match(pattern, phone))
        risk_flags.append("no_phonenumbers_library")
        notes.append("Phonenumbers library not available. Fallback pattern check.")

    if not valid:
        risk_flags.append("invalid_format")
        notes.append("Failed phone pattern or region checks.")
        confidence = max(confidence, 0.2)

    return _risk_response(valid, max(0.0, min(1.0, confidence)), risk_flags, "; ".join(notes))

def validate_domain(domain: str) -> Dict[str, Any]:
    """
    Domain: syntax, IDN spoof risk, suspicious keywords/TLDs
    """
    risk_flags = []
    notes = []
    valid = False
    confidence = 0.5

    if not domain or not isinstance(domain, str):
        return _risk_response(False, 0.0, ["empty"], "Domain missing or not a string.")

    # Syntax check
    pattern = r"^(?=.{4,253}$)([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[a-zA-Z]{2,}$"
    valid = bool(re.match(pattern, domain))
    if not valid:
        risk_flags.append("invalid_syntax")
        notes.append("Domain does not match DNS pattern.")
        confidence = 0.3

    # Suspicious TLDs
    tld = domain.rsplit('.', 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        risk_flags.append("suspicious_tld")
        notes.append(f"Domain TLD '{tld}' is known for abuse/phishing.")
        confidence -= 0.25

    # IDN (punycode) spoof risk
    if domain.startswith("xn--"):
        risk_flags.append("idn_spoof_risk")
        notes.append("Domain is encoded as IDN (punycode), common for spoofing.")

    # Suspicious keywords
    if "login" in domain or "secure" in domain or "account" in domain:
        risk_flags.append("suspicious_keyword")
        notes.append("Domain contains phishing-attractive keywords.")

    return _risk_response(valid, max(confidence, 0.0), risk_flags, "; ".join(notes))

def validate_url(url: str) -> Dict[str, Any]:
    """
    URL: structure, shortening, IP URLs, path abuse, risk flags.
    """
    risk_flags = []
    notes = []
    valid = False
    confidence = 0.6

    if not url or not isinstance(url, str):
        return _risk_response(False, 0.0, ["empty"], "URL missing or not a string.")
    
    # RFC URL
    pattern = r"^(https?://)?([a-zA-Z0-9\-_\.]+)(:\d+)?(/.*)?$"
    valid = bool(re.match(pattern, url))
    if not valid:
        risk_flags.append("invalid_structure")
        notes.append("URL failed basic RFC structure.")
        confidence = 0.25

    # Shortener detection
    for sh_domain in URL_SHORTENERS:
        if sh_domain in url:
            risk_flags.append("shortened_url")
            notes.append(f"URL uses known shortener: {sh_domain}")
            confidence -= 0.2

    # IP-address URLs (suspicious)
    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url):
        risk_flags.append("ip_url")
        notes.append("URL uses direct IP address (often suspicious).")
        confidence -= 0.2

    # Suspicious path / abuse checks
    if '/track' in url or '/redirect' in url or '/login' in url:
        risk_flags.append("tracking_abuse")
        notes.append("URL path contains typical tracking/attack vectors.")

    return _risk_response(valid, max(confidence, 0.0), risk_flags, "; ".join(notes))

def validate_name(name: str) -> Dict[str, Any]:
    """
    Name: letters and spaces, length, non-bot heuristics
    """
    risk_flags = []
    notes = []

    if not name or not isinstance(name, str):
        return _risk_response(False, 0.0, ["empty"], "Name missing or not a string.")

    pattern = r"^[A-Za-z ]{2,100}$"
    valid = bool(re.match(pattern, name))
    confidence = 0.8 if valid else 0.0

    if len(name) < 2:
        risk_flags.append("too_short")
        notes.append("Name too short.")

    if len(name.split()) > 4:
        risk_flags.append("many_words")
        notes.append("Name has unusually many segments; check plausibility.")
        confidence -= 0.2

    return _risk_response(valid, max(confidence, 0.0), risk_flags, "; ".join(notes))

def validate_image_input(image_input: str) -> Dict[str, Any]:
    """
    Image Input: path or URL, MIME, plausible size, extension
    """
    risk_flags = []
    notes = []
    valid = False
    confidence = 0.6

    if not image_input or not isinstance(image_input, str):
        return _risk_response(False, 0.0, ["empty"], "Image input missing or not a string.")

    ext = os.path.splitext(image_input)[-1].lower()
    mime_type, _ = mimetypes.guess_type(image_input)

    # Basic extension check
    if ext not in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff']:
        risk_flags.append("unusual_extension")
        notes.append(f"Unusual image extension: {ext}")

    # Only allow plausible MIME types
    if mime_type and not RE_MIME_IMAGE.match(mime_type):
        risk_flags.append("non_image_mime")
        notes.append(f"MIME type {mime_type} does not look like image.")

    # If local file path, check file size if possible
    if os.path.exists(image_input):
        try:
            size = os.path.getsize(image_input)
            if size < 1000 or size > 50_000_000:  # <1kB or >50MB
                risk_flags.append("implausible_size")
                notes.append(f"File size {size} bytes is questionable.")
            valid = True
            confidence += 0.1
        except Exception as e:
            risk_flags.append("size_check_error")
            notes.append(f"Error determining file size: {e}")
    else:
        # If it's an URL, appear valid, but raise risk on extension/mime
        valid = mime_type is not None and mime_type.startswith("image/")
        if not valid:
            risk_flags.append("unknown_image_input")
            notes.append("Input is not a recognizable image URL/path.")

    return _risk_response(valid, max(confidence, 0.0), risk_flags, "; ".join(notes))

def cross_field_consistency(email: Optional[str]=None, domain: Optional[str]=None, phone: Optional[str]=None, region: Optional[str]=None) -> Dict[str, Any]:
    """
    Cross-field check: email ↔ domain ↔ phone ↔ region.
    Flags mismatches (e.g., domain does not match email), region conflicts.
    """
    risk_flags = []
    notes = []
    confidence = 0.7

    # Email-domain
    domain_extracted = ""
    if email:
        try:
            domain_extracted = email.split("@")[1].lower()
        except Exception:
            pass

    if domain and domain_extracted and domain != domain_extracted:
        risk_flags.append("email_domain_mismatch")
        notes.append("Email domain does not match given domain.")
        confidence -= 0.2

    # Region check via phone parsing if library available
    if phone and region and phonenumbers:
        try:
            parsed = phonenumbers.parse(phone, None)
            region_code = phonenumbers.region_code_for_number(parsed)
            if region and region.lower() != region_code.lower():
                risk_flags.append("region_mismatch")
                notes.append("Phone region does not match expected region.")
                confidence -= 0.2
        except Exception:
            pass

    return _risk_response(True, max(confidence, 0.0), risk_flags, "; ".join(notes))

# === Simple Boolean Wrapper Functions for infinitytrace.py Compatibility ===

def is_valid_username(username: str) -> bool:
    """Simple boolean wrapper for validate_username()."""
    result = validate_username(username)
    return result.get("valid", False)

def is_valid_email(email: str) -> bool:
    """Simple boolean wrapper for validate_email()."""
    result = validate_email(email)
    return result.get("valid", False)

def is_valid_phone(phone: str) -> bool:
    """Simple boolean wrapper for validate_phone()."""
    result = validate_phone(phone)
    return result.get("valid", False)

def is_valid_name(name: str) -> bool:
    """Simple boolean wrapper for validate_name()."""
    result = validate_name(name)
    return result.get("valid", False)

# End of validators.py
