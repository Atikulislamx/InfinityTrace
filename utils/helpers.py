"""
InfinityTrace – OSINT Correlation & Explainability Helpers

This module aggregates, correlates, and explains intelligence gathered from
multiple OSINT analysis modules (usernames, emails, phones, domains, images, validators).
It produces deterministic, transparent, analyst-ready intelligence – never authoritative,
always explainable and OSINT-compliant.

Design: Modular, defensive, JSON-serializable, deterministic, no paid/external APIs.
"""

import json
import hashlib
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from collections import defaultdict
from datetime import datetime

# --- Lightweight in-memory cache with thread safety ---
_cache_lock = threading.Lock()
_CACHE = {}

def _cache_get(key: str) -> Any:
    with _cache_lock:
        record = _CACHE.get(key)
        if record and (time.time() < record['expires']):
            return record['value']
    return None

def _cache_set(key: str, value: Any, ttl: int = 300) -> None:
    with _cache_lock:
        _CACHE[key] = {'value': value, 'expires': time.time() + ttl}

def cache_analysis(func):
    """Decorator for caching analysis results by deterministic hash of input argument."""
    def wrapper(data: dict, *args, **kwargs):
        hash_input = json.dumps(data, sort_keys=True, ensure_ascii=True).encode()
        cache_key = hashlib.sha256(hash_input).hexdigest()
        cached = _cache_get(cache_key)
        if cached:
            return cached
        result = func(data, *args, **kwargs)
        _cache_set(cache_key, result)
        return result
    return wrapper

# --- Safe Networking Utilities ---
import requests

def safe_get(url: str, timeout: float = 3.5, retries: int = 2) -> Optional[requests.Response]:
    """Performs a GET request with timeout and retries, returning None on failure."""
    for _ in range(retries + 1):
        try:
            return requests.get(url, timeout=timeout)
        except (requests.Timeout, requests.ConnectionError):
            continue
    return None

# --- Helpers for Deduplication and Normalization ---

def normalize_str(val: Optional[str]) -> str:
    """Normalize string for correlation (lowercase, strip)."""
    return (val or '').strip().lower()

def dedupe_evidence(evidence: List[Dict], keys: List[str]) -> List[Dict]:
    """Remove evidence entries that have identical values for the specified keys."""
    seen = set()
    result = []
    for entry in evidence:
        id_tuple = tuple(entry.get(k, '').lower() for k in keys)
        if id_tuple not in seen:
            result.append(entry)
            seen.add(id_tuple)
    return result

# --- Timeline Heuristics ---

def build_timeline(
    evidence: List[Dict],
    date_keys: Tuple[str, ...] = ("first_seen", "created_at", "date")
) -> Dict[str, Optional[str]]:
    """
    Build a simple timeline using known timestamp fields across evidence.
    Returns earliest and latest year as crude first/last seen estimates.
    """
    years = []
    for item in evidence:
        for k in date_keys:
            if k in item and item[k]:
                try:
                    dt = parse_year(item[k])
                    if dt:
                        years.append(dt.year)
                except Exception:
                    continue
    if years:
        return {
            "first_seen": str(min(years)),
            "last_seen": str(max(years)),
            "activity_span": str(max(years) - min(years)) + " years" if max(years) != min(years) else "1 year"
        }
    else:
        return {"first_seen": None, "last_seen": None, "activity_span": None}

def parse_year(dtval: Union[str, int, float]) -> Optional[datetime]:
    """Try parsing a string/int date to a datetime, favoring year granularity."""
    if isinstance(dtval, int):
        if 1900 < dtval < 2100:
            return datetime(dtval, 1, 1)
    elif isinstance(dtval, float):
        try:
            return datetime.fromtimestamp(dtval)
        except Exception:
            return None
    elif isinstance(dtval, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%m-%Y", "%Y"):
            try:
                return datetime.strptime(dtval[:10], fmt)
            except Exception:
                continue
        # Extract numeric year
        for token in dtval.split():
            if token.isdigit() and 1900 < int(token) < 2100:
                return datetime(int(token), 1, 1)
    return None

# --- Behavioral Patterns ---

def detect_patterns(
    usernames: List[Dict], emails: List[Dict], phones: List[Dict], domains: List[Dict]
) -> Set[str]:
    """
    Infers simple patterns: username reuse, email-domain match, multi-platform, etc.
    Returns a set of code-friendly pattern tags.
    """
    patterns = set()
    usernames_normalized = {normalize_str(u.get("username") or u.get("handle")) for u in usernames}
    usernames_normalized.discard("")
    if len(usernames_normalized) == 1 and len(usernames) > 1:
        patterns.add("username_reuse")
    elif len(usernames_normalized) > 1:
        patterns.add("platform_hopping")

    # Email-domain match
    domain_set = {normalize_str(d.get("domain")) for d in domains if d.get("domain")}
    for e in emails:
        email = e.get("email", "") or e.get("address", "")
        if "@" in email:
            edomain = normalize_str(email.split("@")[-1])
            if edomain and edomain in domain_set:
                patterns.add("email_domain_match")

    # Consistency: Multiple profiles with common elements (username or email part reused)
    username_parts = {u.split(".")[0] for u in usernames_normalized if u}
    email_names = {normalize_str(e.get("email", "").split("@")[0]) for e in emails if "email" in e}
    if username_parts & email_names:
        patterns.add("username_email_overlap")

    if phones and any(p.get("phone") for p in phones):
        patterns.add("phone_found")

    return patterns

# --- Correlation & Confidence Scoring ---

def correlate_identities(
    usernames: List[Dict], emails: List[Dict], phones: List[Dict], domains: List[Dict]
) -> float:
    """
    Compute a correlation score [0,1] to represent confidence that these pieces relate to one real-world entity.
    Simple weighted logic with penalties for conflicts/mismatches.
    """
    weights = {
        "username": 0.35,
        "email": 0.35,
        "phone": 0.2,
        "domain": 0.1
    }
    base = 0.0
    present = {k: bool(v) for k, v in [("username", usernames), ("email", emails), ("phone", phones), ("domain", domains)]}
    for k, v in present.items():
        if v:
            base += weights[k]
    # Penalty if conflicting usernames/email local part (not matching)
    usernames_set = {normalize_str(u.get("username") or u.get("handle")) for u in usernames}
    emails_set = {normalize_str(e.get("email", "").split("@")[0]) for e in emails if "email" in e}
    if len(usernames_set) > 1 and usernames_set & emails_set == set():
        base -= 0.15  # conflicting usernames/emails
    # Clamp to [0, 1]
    return round(max(0.0, min(1.0, base)), 2)

# --- Explainability Notes Generation ---

def explain_patterns(
    patterns: Set[str], usernames: List[Dict], emails: List[Dict], domains: List[Dict]
) -> List[str]:
    """
    Return formatted English explanations for detected patterns.
    """
    notes = []
    if "username_reuse" in patterns:
        if usernames:
            sites = {u.get("platform", u.get("site", "platform")) for u in usernames}
            uname = next((u.get("username") or u.get("handle") for u in usernames if u.get("username") or u.get("handle")), None)
            notes.append(
                f'The same username "{uname}" appears across multiple platforms: {", ".join(sorted(sites))}'
            )
    if "platform_hopping" in patterns:
        notes.append("A variety of distinct usernames or handles was found, which may indicate platform hopping or intentional alias use.")
    if "email_domain_match" in patterns:
        for e in emails:
            email = e.get("email", "") or e.get("address", "")
            domain = email.split('@')[-1] if "@" in email else None
            if domain and any(normalize_str(domain) == normalize_str(d.get("domain", "")) for d in domains):
                notes.append(f'The email domain "{domain}" matches a discovered related domain.')
                break
    if "username_email_overlap" in patterns:
        notes.append("Part of the username appears in the email address, which supports cross-identity linkage.")
    if "phone_found" in patterns:
        notes.append("A phone number was located, aiding triangulation, but its ownership is not guaranteed.")
    if not notes:
        notes.append("No significant cross-platform or cross-identifier behavioral patterns detected.")
    return notes

# --- Top-level Aggregate Intelligence Function ---

@cache_analysis
def correlate_and_explain(
    data: Dict[str, Any],
    *,
    cache: bool = True
) -> Dict[str, Any]:
    """
    Correlate, aggregate, and explain analysis results across input modules.

    Args:
        data: Dict containing at least keys: 'username', 'email', 'phone', 'domain'.
        cache: Whether to use the internal caching layer.

    Returns:
        Dict[str, Any]: Structured, JSON-serializable analyst intelligence summary.
    """
    # Defensive assignment
    usernames = data.get('username') or []
    emails = data.get('email') or []
    phones = data.get('phone') or []
    domains = data.get('domain') or data.get('domains') or []

    usernames = [u for u in usernames if isinstance(u, dict)]
    emails = [e for e in emails if isinstance(e, dict)]
    phones = [p for p in phones if isinstance(p, dict)]
    domains = [d for d in domains if isinstance(d, dict)]

    usernames = dedupe_evidence(usernames, ["platform", "username"])
    emails = dedupe_evidence(emails, ["email"])
    phones = dedupe_evidence(phones, ["phone"])
    domains = dedupe_evidence(domains, ["domain"])

    patterns = detect_patterns(usernames, emails, phones, domains)
    timeline_evidence = usernames + emails + phones + domains
    timeline = build_timeline(timeline_evidence)
    correlation_score = correlate_identities(usernames, emails, phones, domains)
    explainability = explain_patterns(patterns, usernames, emails, domains)

    return {
        "correlation_score": correlation_score,
        "patterns": sorted(list(patterns)),
        "timeline": timeline,
        "explainability": explainability
    }

# --- Wrapper functions for infinitytrace.py compatibility ---

def correlate_context(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Wrapper for correlate_and_explain() to match infinitytrace.py expectations.
    Accepts analysis dict and returns correlation intelligence.
    """
    return correlate_and_explain(analysis)

def explain_findings(ctx) -> str:
    """
    Generate human-readable explanation from AnalysisContext.
    
    Args:
        ctx: AnalysisContext object with analysis results
        
    Returns:
        str: Human-readable explanation of findings
    """
    correlation = ctx.correlation
    explainability = correlation.get('explainability', [])
    
    if not explainability:
        return "No significant findings from the analysis."
    
    return "\n".join(f"• {note}" for note in explainability)

def print_banner():
    """
    Print ASCII art banner for InfinityTrace.
    """
    banner = r"""
    ___        _____ _       _ _          _____                   
   |_ _|_ __  |  ___(_)_ __ (_) |_ _   _|_   _| __ __ _  ___ ___ 
    | || '_ \ | |_  | | '_ \| | __| | | | | || '__/ _` |/ __/ _ \
    | || | | ||  _| | | | | | | |_| |_| | | || | | (_| | (_|  __/
   |___|_| |_||_|   |_|_| |_|_|\__|\__, | |_||_|  \__,_|\___\___|
                                   |___/                          
    """
    print(banner)
    print("    OSINT Footprint Analysis Framework")
    print("    =====================================\n")

def write_output_txt(ctx, filename: str = "output.txt") -> None:
    """
    Write analysis results to a formatted text file.
    
    Args:
        ctx: AnalysisContext object with all analysis data
        filename: Output file path
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("InfinityTrace - OSINT Analysis Report\n")
        f.write("=" * 80 + "\n\n")
        
        # Metadata
        f.write("REPORT METADATA\n")
        f.write("-" * 80 + "\n")
        f.write(f"Generated: {ctx.run_metadata.get('start_time', 'N/A')}\n")
        f.write(f"Duration: {ctx.run_metadata.get('duration_sec', 'N/A')} seconds\n")
        f.write("\n")
        
        # Input Summary
        f.write("INPUT SUMMARY\n")
        f.write("-" * 80 + "\n")
        for key, value in ctx.input.items():
            if value:
                f.write(f"{key.capitalize():15}: {value}\n")
        f.write("\n")
        
        # Normalized Inputs
        if ctx.normalized:
            f.write("NORMALIZED INPUTS\n")
            f.write("-" * 80 + "\n")
            for key, value in ctx.normalized.items():
                if value:
                    # Handle dict returns from normalizers
                    if isinstance(value, dict):
                        norm_val = value.get('normalized_' + key, value.get('normalized', str(value)))
                    else:
                        norm_val = value
                    f.write(f"{key.capitalize():15}: {norm_val}\n")
            f.write("\n")
        
        # Validity Status
        if ctx.validity:
            f.write("VALIDATION STATUS\n")
            f.write("-" * 80 + "\n")
            for key, valid in ctx.validity.items():
                status = "✓ VALID" if valid else "⚠ WARNING"
                f.write(f"{key.capitalize():15}: {status}\n")
            f.write("\n")
        
        # Analysis Results
        f.write("ANALYSIS RESULTS\n")
        f.write("-" * 80 + "\n")
        for module, results in ctx.analysis.items():
            if results:
                if isinstance(results, list):
                    f.write(f"\n{module.upper()} ({len(results)} result(s)):\n")
                    for i, item in enumerate(results[:10], 1):  # Limit to first 10
                        if isinstance(item, dict):
                            # Format dict results
                            for k, v in list(item.items())[:5]:  # Limit to 5 keys
                                f.write(f"  {k}: {v}\n")
                            f.write("\n")
                        else:
                            f.write(f"  {i}. {item}\n")
                    if len(results) > 10:
                        f.write(f"  ... and {len(results) - 10} more\n")
                else:
                    f.write(f"\n{module.upper()}: {results}\n")
        f.write("\n")
        
        # Correlation & Patterns
        if ctx.correlation:
            f.write("CORRELATION ANALYSIS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Correlation Score: {ctx.correlation.get('correlation_score', 'N/A')}\n")
            patterns = ctx.correlation.get('patterns', [])
            if patterns:
                f.write(f"Patterns Detected: {', '.join(patterns)}\n")
            timeline = ctx.correlation.get('timeline', {})
            if timeline:
                f.write(f"First Seen: {timeline.get('first_seen', 'N/A')}\n")
                f.write(f"Last Seen: {timeline.get('last_seen', 'N/A')}\n")
                f.write(f"Activity Span: {timeline.get('activity_span', 'N/A')}\n")
            f.write("\n")
        
        # Explanation
        if ctx.explanation:
            f.write("FINDINGS EXPLANATION\n")
            f.write("-" * 80 + "\n")
            f.write(ctx.explanation + "\n\n")
        
        # Risk Assessment
        f.write("RISK ASSESSMENT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Risk Score: {ctx.risk_score if ctx.risk_score is not None else 'N/A'} / 100\n")
        f.write(f"Risk Level: {ctx.risk_level if ctx.risk_level else 'N/A'}\n")
        f.write("\n")
        
        # Disclaimer
        f.write("DISCLAIMER\n")
        f.write("-" * 80 + "\n")
        f.write("This analysis is based solely on publicly available data.\n")
        f.write("Results do not confirm identity and should be used for informational purposes only.\n")
        f.write("This tool is for ethical OSINT research only.\n")
        f.write("\n")
        f.write("=" * 80 + "\n")

def write_output_json(ctx, filename: str = "output.json") -> None:
    """
    Write analysis results to a JSON file.
    
    Args:
        ctx: AnalysisContext object with all analysis data
        filename: Output file path
    """
    data = ctx.to_json()
    
    # Handle dict returns from normalizers in JSON output
    if 'normalized' in data:
        normalized_clean = {}
        for key, value in data['normalized'].items():
            if isinstance(value, dict):
                # Extract the normalized value from dict
                normalized_clean[key] = value.get('normalized_' + key, value.get('normalized', str(value)))
            else:
                normalized_clean[key] = value
        data['normalized'] = normalized_clean
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# --- Main: Demo / Direct Use Example ---
if __name__ == "__main__":
    # Example data for demonstration only
    example_input = {
        "username": [
            {"username": "jackdoe", "platform": "Twitter", "first_seen": "2018-11-20"},
            {"username": "jackdoe", "platform": "Reddit", "first_seen": "2019-02-10"},
            {"username": "jackdoe", "platform": "GitHub", "first_seen": "2021-05-01"}
        ],
        "email": [
            {"email": "jackdoe@gmail.com", "source": "public_breach", "first_seen": "2019"},
        ],
        "phone": [],
        "domain": [
            {"domain": "gmail.com", "first_seen": "2010"}
        ]
    }
    intelligence = correlate_and_explain(example_input)
    print(json.dumps(intelligence, indent=2, ensure_ascii=False))
