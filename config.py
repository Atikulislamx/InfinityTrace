"""
InfinityTrace Configuration
----------------------------
Centralized configuration for constants, thresholds, and settings.

This allows easy customization without modifying core logic.
"""

# === Risk Scoring Thresholds ===
RISK_THRESHOLD_LOW = 30
RISK_THRESHOLD_MEDIUM = 60
RISK_THRESHOLD_HIGH = 100

# === Execution Modes ===
EXECUTION_MODES = ['fast', 'deep', 'username-only', 'contact-only']

# === Default Settings ===
DEFAULT_OUTPUT_FILE = "output.txt"
DEFAULT_MODE = "fast"
DEFAULT_PHONE_REGION = "BD"  # Bangladesh - change to your default region

# === Timeouts and Limits ===
REQUEST_TIMEOUT = 10  # seconds
MAX_PARALLEL_JOBS = 10
RATE_LIMIT_DELAY = 1  # seconds between requests

# === Disposable Email Domains ===
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", 
    "trashmail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "temp-mail.org", "sharklasers.com"
}

# === Role-Based Email Prefixes ===
ROLE_BASED_EMAIL_PREFIXES = {
    "admin", "support", "info", "contact", "sales", "help",
    "noreply", "postmaster", "webmaster", "abuse", "security"
}

# === Suspicious TLDs ===
SUSPICIOUS_TLDS = {
    "zip", "xyz", "link", "top", "live", "work", "click", 
    "country", "support", "gq", "ml", "cf", "tk", "ga"
}

# === URL Shorteners ===
URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", 
    "ow.ly", "buff.ly", "adf.ly", "rebrand.ly", "short.io"
}

# === VoIP Carriers ===
VOIP_CARRIERS = {
    "google voice", "skype", "twilio", "vonage", "magicjack",
    "ooma", "ringcentral", "grasshopper"
}

# === Popular Brands for Typosquatting Detection ===
POPULAR_BRANDS = [
    "google", "facebook", "amazon", "microsoft", "apple",
    "paypal", "netflix", "twitter", "instagram", "linkedin"
]

# === Logging Configuration ===
LOG_LEVEL = "INFO"
LOG_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s'
LOG_DATE_FORMAT = '%H:%M:%S'

# === Output Configuration ===
MAX_RESULTS_PER_MODULE = 100  # Limit results to prevent overwhelming output
REPORT_WIDTH = 80  # Character width for text reports

# === Security Settings ===
ENABLE_RATE_LIMITING = True
MAX_RETRIES = 3
SANITIZE_INPUTS = True

# === Ethical Use Settings ===
ETHICAL_MODE = True  # Enforces ethical use guidelines
PUBLIC_DATA_ONLY = True  # Only query public data sources
NO_CREDENTIAL_HARVESTING = True  # Never attempt to harvest credentials
