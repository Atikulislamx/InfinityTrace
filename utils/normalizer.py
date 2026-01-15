"""
InfinityTrace Normalizer Module
--------------------------------------
Professional-grade input normalization for OSINT intelligence:
- Usernames (unicode-safe, platform-agnostic)
- Emails (Gmail canonicalization)
- Phone numbers (E.164)
- Domains / URLs
- Full Names
- Image paths/URLs (type & existence)
- Canonical identity keys
- Confidence scores per normalization

Open-source friendly. No external API calls. Defensive, deterministic logic.
"""

import re
import unicodedata
import phonenumbers
import urllib.parse
import hashlib
import email.utils
import idna
import logging
import os
from typing import Optional, Dict, Any

# Import configuration
try:
    from config import DEFAULT_PHONE_REGION
except ImportError:
    DEFAULT_PHONE_REGION = 'BD'

logger = logging.getLogger("InfinityTraceNormalizer")
logger.setLevel(logging.INFO)

def confidence_score(success: bool, details: str = "") -> float:
    """
    Basic confidence logic, extensible for real-world scoring.
    """
    if not success:
        return 0.2
    if "valid" in details.lower():
        return 0.95
    if "normal" in details.lower():
        return 0.8
    return 0.5


def normalize_username(username: str) -> Dict[str, Any]:
    """
    Unicode, platform, and length safe normalization.
    """
    if not isinstance(username, str) or not username:
        return {"normalized_username": None, "confidence": 0.2, "notes": "Missing or invalid username"}
    orig = username
    username = username.strip()
    username = unicodedata.normalize("NFKC", username)
    username = re.sub(r"\s+", "", username)
    username = username.lower()
    # Highly permissive for global platforms: keep Unicode letters/digits, _ and .
    username = re.sub(r"[^\w\.\u00C0-\uFFFF]", "", username)
    # Truncate if absurdly long (>64 chars)
    if len(username) > 64:
        username = username[:64]
        notes = "Normalized & truncated to 64 chars"
    else:
        notes = "Unicode/strip/length normal"
    return {
        "normalized_username": username,
        "confidence": confidence_score(True, notes),
        "notes": notes,
        "original": orig
    }


def normalize_email(email_: str) -> Dict[str, Any]:
    """
    Canonicalize email, gmail dot/plus handling.
    """
    result = {"normalized_email": None, "confidence": 0.2, "notes": "Invalid email"}
    try:
        email_ = email_.strip().lower()
        parsed = email.utils.parseaddr(email_)[1]
        if not parsed or "@" not in parsed:
            result["notes"] = "Not an email address"
            return result
        local, domain = parsed.split("@", 1)
        domain = idna.encode(domain).decode("ascii")
        if domain in ("gmail.com", "googlemail.com"):
            # Gmail ignores dots, anything after +
            local = local.split('+', 1)[0].replace('.', '')
        norm_email = f"{local}@{domain}"
        result.update({
            "normalized_email": norm_email,
            "confidence": confidence_score(True, "Gmail canonical" if domain == "gmail.com" else "Valid email"),
            "notes": "Email parsed and canonicalized",
            "original": email_
        })
    except Exception as e:
        logger.debug(f"Email normalization failed: {e}")
        result["notes"] = f"Error: {e}"
    return result


def normalize_phone(phone: str, default_region: str = DEFAULT_PHONE_REGION) -> Dict[str, Any]:
    """
    E.164 normal; fallback to digit-only.
    """
    result = {"normalized_phone": None, "confidence": 0.2, "notes": "Invalid phone"}
    try:
        cleaned = re.sub(r"[^\d+]", "", phone)
        parsed = phonenumbers.parse(cleaned, default_region)
        if phonenumbers.is_valid_number(parsed):
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            result.update({
                "normalized_phone": e164,
                "confidence": confidence_score(True, "Valid mobile number"),
                "notes": "Valid E.164",
                "original": phone
            })
        elif phonenumbers.is_possible_number(parsed):
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            result.update({
                "normalized_phone": e164,
                "confidence": confidence_score(True, "Possible number"),
                "notes": "Possible E.164",
                "original": phone
            })
        else:
            result["notes"] = "Not valid phone number"
    except (phonenumbers.NumberParseException, Exception) as e:
        # Fallback: digits only
        logger.debug(f"Phone normalization failed: {e}")
        cleaned = re.sub(r"[^\d+]", "", phone)
        if cleaned:
            result.update({
                "normalized_phone": cleaned,
                "confidence": confidence_score(True, "Digit-only fallback"),
                "notes": "Digit-only cleaned"
            })
        else:
            result["notes"] = f"Error: {e}"
    return result


def normalize_domain(domain: str) -> Dict[str, Any]:
    """
    IDNA & minimal strip, safe for OSINT.
    """
    result = {"normalized_domain": None, "confidence": 0.2, "notes": "Invalid domain"}
    try:
        domain = domain.strip().lower()
        domain = re.sub(r"^https?://", "", domain)
        domain = domain.split("/")[0]
        domain_ascii = idna.encode(domain).decode("ascii")
        # Basic TLD check
        if re.match(r"^[a-z0-9\-\.]+\.[a-z]{2,}$", domain_ascii):
            result.update({
                "normalized_domain": domain_ascii,
                "confidence": confidence_score(True, "Valid domain"),
                "notes": "IDNA encoded",
                "original": domain
            })
        else:
            result["notes"] = "Domain structure invalid"
    except Exception as e:
        logger.debug(f"Domain normalization failed: {e}")
        result["notes"] = f"Error: {e}"
    return result


def normalize_url(url: str) -> Dict[str, Any]:
    """
    Safe URL normalization.
    """
    result = {"normalized_url": None, "confidence": 0.2, "notes": "Invalid URL"}
    try:
        url = url.strip()
        p = urllib.parse.urlparse(url)
        if p.scheme and p.netloc:
            # Netloc domain as IDNA
            norm_domain = idna.encode(p.hostname or "").decode("ascii") if p.hostname else ""
            norm_url = urllib.parse.urlunparse((
                p.scheme,
                norm_domain,
                p.path,
                p.params,
                p.query,
                p.fragment
            ))
            result.update({
                "normalized_url": norm_url,
                "confidence": confidence_score(True, "Valid URL"),
                "notes": "Schemed & encoded",
                "original": url
            })
        else:
            result["notes"] = "Missing scheme or netloc"
    except Exception as e:
        logger.debug(f"URL normalization failed: {e}")
        result["notes"] = f"Error: {e}"
    return result


def normalize_name(name: str) -> Dict[str, Any]:
    """
    Soft intelligence: Clean, title-case, Unicode safe.
    """
    if not isinstance(name, str) or not name.strip():
        return {"normalized_name": None, "confidence": 0.2, "notes": "Missing or invalid name"}
    orig = name
    name = " ".join(name.strip().split())
    name = unicodedata.normalize("NFC", name)
    name = name.title()
    # Remove obvious garbage/emoji
    name = re.sub(r"[^\w\s\.,\-']", "", name, flags=re.UNICODE)
    # If lots of single-letter words, penalize score.
    if sum(1 for part in name.split() if len(part) == 1) > 1:
        conf = 0.65
        notes = "Short/suspicious name"
    else:
        conf = confidence_score(True, "Valid name")
        notes = "Normal"
    return {
        "normalized_name": name,
        "confidence": conf,
        "notes": notes,
        "original": orig
    }


def normalize_image(image_path_or_url: str) -> Dict[str, Any]:
    """
    Detect image format; check existence if local; returns type.
    """
    result = {"normalized_image": None, "confidence": 0.2, "notes": "Invalid image"}
    image = image_path_or_url.strip()
    if re.match(r"^https?://", image, re.IGNORECASE):
        # URL: check pattern
        ext = os.path.splitext(urllib.parse.urlparse(image).path)[1].lower()
        if ext in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"):
            result.update({
                "normalized_image": image,
                "confidence": confidence_score(True, "Valid image URL"),
                "notes": f"Extension {ext} recognized",
                "original": image_path_or_url
            })
        else:
            result["notes"] = "Unknown or missing image extension"
    else:
        # Local file: check existence and extension
        ext = os.path.splitext(image)[1].lower()
        if ext in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp") and os.path.isfile(image):
            result.update({
                "normalized_image": os.path.abspath(image),
                "confidence": confidence_score(True, "Existing image file"),
                "notes": f"Local file {ext}",
                "original": image_path_or_url
            })
        elif ext in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"):
            result.update({
                "normalized_image": os.path.abspath(image),
                "confidence": 0.7,
                "notes": f"Extension OK but file not found",
                "original": image_path_or_url
            })
        else:
            result["notes"] = "Invalid or unknown image file"
    return result


def canonical_identity(
    username: Optional[str] = None,
    email_: Optional[str] = None,
    phone: Optional[str] = None,
    domain: Optional[str] = None,
    name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Deterministic identity fingerprint.
    """
    # Normalize each and concatenate in stable order
    parts = []
    meta_notes = []
    norm_username = normalize_username(username or "")
    norm_email = normalize_email(email_ or "")
    norm_phone = normalize_phone(phone or "") if phone else {"normalized_phone": ""}
    norm_domain = normalize_domain(domain or "") if domain else {"normalized_domain": ""}
    norm_name = normalize_name(name or "")
    # Only use non-empty canonicalized forms
    for norm in [norm_username, norm_email, norm_phone, norm_domain, norm_name]:
        for k, v in norm.items():
            if k.startswith("normalized_") and v:
                parts.append(v)
        if norm.get("notes"):
            meta_notes.append(norm.get("notes"))
    canonical = "|".join(parts).encode("utf-8")
    key = hashlib.sha256(canonical).hexdigest()
    confidence = min(
        norm_username["confidence"], norm_email["confidence"],
        norm_phone.get("confidence", 1),
        norm_domain.get("confidence", 1),
        norm_name["confidence"]
    )
    return {
        "identity_key": key,
        "confidence": confidence,
        "notes": "; ".join(meta_notes)
    }


def normalize_input(input_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Master normalizer – normalizes all fields in structure.
    Returns JSON-compatible output.
    """
    output = {}
    if "username" in input_dict:
        output.update(normalize_username(input_dict.get("username", "")))
    if "email" in input_dict:
        output.update(normalize_email(input_dict.get("email", "")))
    if "phone" in input_dict:
        output.update(normalize_phone(input_dict.get("phone", "")))
    if "domain" in input_dict:
        output.update(normalize_domain(input_dict.get("domain", "")))
    if "url" in input_dict:
        output.update(normalize_url(input_dict.get("url", "")))
    if "name" in input_dict:
        output.update(normalize_name(input_dict.get("name", "")))
    if "image" in input_dict:
        output.update(normalize_image(input_dict.get("image", "")))
    # Compute canonical identity
    output.update(canonical_identity(
        username=output.get("normalized_username"),
        email_=output.get("normalized_email"),
        phone=output.get("normalized_phone"),
        domain=output.get("normalized_domain"),
        name=output.get("normalized_name")
    ))
    return output

# Example Usage:
# result = normalize_input({
#     "username": "Winston🌟 Smith ",
#     "email": "winston.smith+osint@gmail.com",
#     "phone": "01300-228-105",
#     "domain": "infinitytrace.org",
#     "url": "https://infinitytrace.org/about",
#     "name": "Winston Smith",
#     "image": "images/winston_smith.jpg"
# })
# print(result)
