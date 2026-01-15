# Domain Intelligence Module - Feature Documentation

## Overview
The `domain_intel.py` module provides comprehensive OSINT-based domain and URL intelligence analysis for the InfinityTrace project. It implements 11 core capabilities using only publicly available data.

## Features

### 1. URL Normalization (`normalize_url`)
- Safely normalizes URLs to standard format
- Case-insensitive scheme handling
- Removes fragments
- Adds default scheme if missing

**Example:**
```python
from modules.domain_intel import normalize_url

url = normalize_url("Example.COM/path")
# Output: "http://example.com/path"
```

### 2. URL Expansion (`expand_shortened_url`)
- Expands shortened URLs (bit.ly, tinyurl, etc.)
- Tracks full redirect chain
- Non-intrusive HEAD requests only

**Example:**
```python
from modules.domain_intel import expand_shortened_url

result = expand_shortened_url("bit.ly/test123")
# Output: {"final_url": "...", "redirect_chain": [...]}
```

### 3. WHOIS/RDAP Intelligence (`get_whois_info`)
- Domain registration data
- Registrar information
- Creation, expiration, and update dates
- Name servers and status

**Example:**
```python
from modules.domain_intel import get_whois_info

info = get_whois_info("example.com")
# Output: {"registrar": "...", "creation_date": "..."}
```

### 4. Domain Age Analysis (`calculate_domain_age`)
- Calculates domain age in days
- Risk categorization (VERY_NEW, NEW, RECENT, ESTABLISHED)
- Risk factor scoring

**Example:**
```python
from modules.domain_intel import calculate_domain_age

age = calculate_domain_age("example.com")
# Output: {"age_days": 9500, "age_category": "ESTABLISHED"}
```

### 5. DNS Infrastructure Analysis (`analyze_dns_records`)
- A, AAAA, MX, TXT, NS, CNAME records
- SPF and DMARC detection
- Email infrastructure analysis

**Example:**
```python
from modules.domain_intel import analyze_dns_records

dns = analyze_dns_records("example.com")
# Output: {"a_records": [...], "mx_records": [...], "has_email": true}
```

### 6. Blacklist Checking (`check_phishing_blacklists`)
- PhishTank integration
- OpenPhish feed
- URLHaus (abuse.ch)
- Reputation scoring

**Example:**
```python
from modules.domain_intel import check_phishing_blacklists

check = check_phishing_blacklists("suspicious.com")
# Output: {"blacklisted": false, "blacklists": [...]}
```

### 7. SSL Certificate Analysis (`check_ssl_certificate`)
- Certificate metadata
- Issuer and subject information
- Validity period
- Expiration tracking
- Self-signed detection
- Secure TLS 1.2+ only

**Example:**
```python
from modules.domain_intel import check_ssl_certificate

ssl_info = check_ssl_certificate("example.com")
# Output: {"has_ssl": true, "issuer": {...}, "days_until_expiry": 90}
```

### 8. Brand Impersonation Detection (`detect_typosquatting`)
- String similarity analysis
- Popular brand comparison
- Typosquatting risk scoring

**Example:**
```python
from modules.domain_intel import detect_typosquatting

typo = detect_typosquatting("gooogle.com")
# Output: {"suspected_typosquatting": true, "similar_brands": ["google"]}
```

### 9. Web Fingerprinting (`perform_web_fingerprint`)
- Server detection
- Technology identification
- HTTP header analysis
- Cookie analysis

**Example:**
```python
from modules.domain_intel import perform_web_fingerprint

fingerprint = perform_web_fingerprint("example.com")
# Output: {"server": "nginx", "technologies": [...]}
```

### 10. Historical Activity Analysis (`check_wayback_machine`)
- Internet Archive integration
- First/last seen dates
- Snapshot count
- Historical presence verification

**Example:**
```python
from modules.domain_intel import check_wayback_machine

history = check_wayback_machine("example.com")
# Output: {"has_history": true, "first_seen": "...", "snapshot_count": 500}
```

### 11. Domain Risk Scoring (`calculate_domain_risk_score`)
- Explainable 0-100 risk score
- Weighted factor analysis
- Risk level categorization (LOW/MEDIUM/HIGH)

**Risk Factors:**
- Domain age (newer = higher risk)
- Blacklist status (+40 if listed)
- SSL issues (+15-20 if missing/expired/self-signed)
- Typosquatting detection (+5-25)
- DNS configuration issues (+5-10)
- No historical presence (+15)
- URL shortener (+10)

**Example:**
```python
from modules.domain_intel import calculate_domain_risk_score

score, level = calculate_domain_risk_score(analysis_data)
# Output: (42, "MEDIUM")
```

## Comprehensive Analysis

Use `analyze_domain()` for complete analysis:

```python
from modules.domain_intel import analyze_domain
import json

result = analyze_domain("example.com")

# Output matches specification
output = {
    "domain": result['domain'],
    "domain_age_days": result['domain_age'].get('age_days'),
    "blacklisted": result['blacklist_check'].get('blacklisted', False),
    "brand_impersonation": result['typosquatting'].get('suspected_typosquatting', False),
    "domain_risk_score": result['domain_risk_score'],
    "risk_level": result['risk_level']
}

print(json.dumps(output, indent=2))
```

**Expected Output:**
```json
{
  "domain": "example.com",
  "domain_age_days": 9500,
  "blacklisted": false,
  "brand_impersonation": false,
  "domain_risk_score": 30,
  "risk_level": "LOW"
}
```

## Backward Compatibility

The legacy `check_domain()` function is maintained for integration with existing InfinityTrace code:

```python
from modules.domain_intel import check_domain

results = check_domain("username")
# Returns list of domain intelligence results for username-based domains
```

## Dependencies

Required libraries (in requirements.txt):
- `requests>=2.28.0` - HTTP requests
- `dnspython>=2.3.0` - DNS lookups
- `python-whois>=0.8.0` - WHOIS queries
- `tldextract>=3.4.0` - Domain parsing

## Ethical Guidelines

All functions adhere to ethical OSINT principles:
- ✅ Public data only
- ✅ No active scanning
- ✅ No private data access
- ✅ Graceful degradation
- ✅ Proper error handling
- ✅ Respectful request rates

## Error Handling

All functions include comprehensive error handling:
- Network failures return partial results
- Missing libraries trigger warnings
- Invalid inputs are validated
- Errors are logged appropriately

## Security

- Secure TLS 1.2+ only for SSL connections
- No hardcoded API keys
- Safe URL parsing
- Input validation
- No code injection risks
