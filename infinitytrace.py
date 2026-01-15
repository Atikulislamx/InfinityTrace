#!/usr/bin/env python3
"""
InfinityTrace – Central Orchestration CLI for Open-Source Public OSINT Footprint Analysis

Coordinates analysis modules, enforces ethical principles, aggregates context, 
and generates professional analyst reports.

Usage examples:
    python infinitytrace.py --username john_doe
    python infinitytrace.py --username john_doe --email john@example.com --mode deep --json
    python infinitytrace.py --email jane@example.com --mode contact-only

For details, see ETHICAL_USE.md.

Author: InfinityTrace contributors
License: MIT
"""

import argparse
import logging
import time
import sys
import concurrent.futures
from typing import Any, Dict, Optional, List

# === Module imports (assumed present) ===
from modules.username_search import search_username
from modules.email_analysis import check_email
from modules.phone_analysis import check_phone
from modules.image_analysis import check_image
from modules.domain_intel import check_domain
from modules.risk_scoring import calculate_risk_score
from utils.helpers import (write_output_txt, write_output_json, 
                           correlate_context, explain_findings, print_banner)
from utils.normalizer import (
    normalize_username, normalize_email, normalize_phone, normalize_name
)
from utils.validators import (
    is_valid_username, is_valid_email, is_valid_phone, is_valid_name
)

# === Configuration Import ===
from config import (
    EXECUTION_MODES, DEFAULT_OUTPUT_FILE, DEFAULT_MODE,
    LOG_LEVEL, LOG_FORMAT, LOG_DATE_FORMAT
)

# === Global Constants ===
ETHICAL_BANNER = """
==================================================
InfinityTrace: Ethical OSINT Analysis
This tool ONLY uses publicly available data.
It is strictly prohibited to use for unlawful, abusive, or private-data scraping purposes.
See ETHICAL_USE.md for full guidelines.
==================================================
"""

# === Logging Setup ===
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT
)
logger = logging.getLogger("InfinityTrace")

# === Data Structure for Internal State ===
class AnalysisContext:
    """
    Holds the unified, JSON-serializable internal state and results 
    for an InfinityTrace analysis run.
    """
    def __init__(self):
        self.run_metadata: Dict[str, Any] = {
            'start_time': time.strftime("%Y-%m-%d %H:%M:%S"),
            'duration_sec': None,
        }
        self.input: Dict[str, Optional[str]] = {
            'username': None,
            'email': None,
            'phone': None,
            'name': None,
            'mode': None,
        }
        self.normalized: Dict[str, Optional[str]] = {}
        self.validity: Dict[str, bool] = {}
        self.analysis: Dict[str, Any] = {}
        self.correlation: Dict[str, Any] = {}
        self.explanation: str = ""
        self.risk_score: Optional[int] = None
        self.risk_level: Optional[str] = None

    def to_json(self) -> Dict[str, Any]:
        "Export context as JSON-serializable dict."
        return {
            'run_metadata': self.run_metadata,
            'input': self.input,
            'normalized': self.normalized,
            'validity': self.validity,
            'analysis': self.analysis,
            'correlation': self.correlation,
            'explanation': self.explanation,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
        }


# === Argument Parsing ===

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="InfinityTrace – Analyst-Grade OSINT Footprint Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python infinitytrace.py --username john_doe --email x@y.com --mode deep --json
  python infinitytrace.py --phone 1234567890 --name "Jane Smith" --output analysis.txt

MODES:
  fast           : Minimal, quick analysis (default)
  deep           : Full, thorough analysis of all inputs
  username-only  : Run only username-related checks
  contact-only   : Skip username/image/domain, do contact + risk only

NOTE: This tool uses only PUBLIC data and abides by strict ethical guidelines.
        """
    )
    parser.add_argument("--username", type=str, help="Username to search/analyze")
    parser.add_argument("--email", type=str, help="Email to analyze (public only)")
    parser.add_argument("--phone", type=str, help="Phone to analyze (public only)")
    parser.add_argument("--name", type=str, help="Full name for soft search")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT_FILE, help=f"TXT report filename (default: {DEFAULT_OUTPUT_FILE})")
    parser.add_argument("--json", action="store_true", help="Export JSON-format report alongside TXT")
    parser.add_argument("--mode", type=str, choices=EXECUTION_MODES, default=DEFAULT_MODE,
                        help=f"Execution mode: {', '.join(EXECUTION_MODES)} (default: {DEFAULT_MODE})")
    return parser.parse_args()


# === Input Validation & Normalization ===

def sanitize_input(value: str, max_length: int = 256) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        value: Input string to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized string
    """
    if not value:
        return ""
    
    # Truncate to max length
    value = str(value)[:max_length]
    
    # Remove null bytes
    value = value.replace('\x00', '')
    
    # Remove control characters except common whitespace
    value = ''.join(char for char in value if char.isprintable() or char in '\t\n\r ')
    
    # Trim whitespace
    value = value.strip()
    
    return value

def validate_and_normalize_inputs(args: argparse.Namespace, ctx: AnalysisContext) -> None:
    # Sanitize all inputs first
    if args.username:
        args.username = sanitize_input(args.username, 64)
    if args.email:
        args.email = sanitize_input(args.email, 254)  # Max email length per RFC
    if args.phone:
        args.phone = sanitize_input(args.phone, 20)
    if args.name:
        args.name = sanitize_input(args.name, 128)
    
    # Validate each input and normalize
    if args.username:
        valid = is_valid_username(args.username)
        ctx.validity["username"] = valid
        ctx.input["username"] = args.username
        if not valid:
            logger.warning(f"Username '{args.username}' may not be valid (3-30 chars, alphanumeric, _, . allowed)")
        norm_result = normalize_username(args.username)
        # Handle dict return from normalizer
        if isinstance(norm_result, dict):
            ctx.normalized["username"] = norm_result.get("normalized_username") or norm_result.get("normalized") or args.username
        else:
            ctx.normalized["username"] = norm_result
    if args.email:
        valid = is_valid_email(args.email)
        ctx.validity["email"] = valid
        ctx.input["email"] = args.email
        if not valid:
            logger.warning(f"Email '{args.email}' may not be valid (RFC 5322)")
        norm_result = normalize_email(args.email)
        # Handle dict return from normalizer
        if isinstance(norm_result, dict):
            ctx.normalized["email"] = norm_result.get("normalized_email") or norm_result.get("normalized") or args.email
        else:
            ctx.normalized["email"] = norm_result
    if args.phone:
        valid = is_valid_phone(args.phone)
        ctx.validity["phone"] = valid
        ctx.input["phone"] = args.phone
        if not valid:
            logger.warning(f"Phone '{args.phone}' may not be valid (7-15 digits, international formats allowed)")
        norm_result = normalize_phone(args.phone)
        # Handle dict return from normalizer
        if isinstance(norm_result, dict):
            ctx.normalized["phone"] = norm_result.get("normalized_phone") or norm_result.get("normalized") or args.phone
        else:
            ctx.normalized["phone"] = norm_result
    if args.name:
        valid = is_valid_name(args.name)
        ctx.validity["name"] = valid
        ctx.input["name"] = args.name
        if not valid:
            logger.warning(f"Name '{args.name}' may not be valid (letters and spaces only)")
        norm_result = normalize_name(args.name)
        # Handle dict return from normalizer
        if isinstance(norm_result, dict):
            ctx.normalized["name"] = norm_result.get("normalized_name") or norm_result.get("normalized") or args.name
        else:
            ctx.normalized["name"] = norm_result
    ctx.input["mode"] = args.mode

def required_inputs_present(args: argparse.Namespace) -> bool:
    return any([args.username, args.email, args.phone, args.name])


# === Parallelizable Module Orchestration ===

def run_parallel_functions(jobs: Dict[str, Any]) -> Dict[str, Any]:
    """
    jobs: dict mapping output key -> tuple(func, arg)
    returns: dict mapping key -> result
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_map = {
            executor.submit(func, arg): key
            for key, (func, arg) in jobs.items()
        }
        for future in concurrent.futures.as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                logger.error(f"{key} analysis failed: {exc}")
                results[key] = []
    return results

# === Main Orchestration Logic ===

def main() -> None:
    print_banner()  # Optional: pretty ASCII banner, if present in helpers
    print(ETHICAL_BANNER)
    overall_timer = time.perf_counter()
    ctx = AnalysisContext()
    args = parse_args()

    if not required_inputs_present(args):
        print("\n[ERROR] Please provide at least one input (--username, --email, --phone, or --name)\n")
        print("Usage example:")
        print("  python infinitytrace.py --username john_doe --email john@example.com --mode deep --json\n")
        sys.exit(1)
    validate_and_normalize_inputs(args, ctx)
    logger.info(f"Execution mode: {args.mode}")

    # === Dynamic Module Plan ===
    username = ctx.normalized.get('username')
    email = ctx.normalized.get('email')
    phone = ctx.normalized.get('phone')
    name = ctx.normalized.get('name')

    # Define work plan based on mode and inputs
    module_jobs = {}
    if args.mode in ["username-only", "deep", "fast"]:
        if username:
            module_jobs['username'] = (search_username, username)
            if args.mode != "contact-only":  # images/domains rely on username
                module_jobs['images'] = (check_image, username)
                module_jobs['domains'] = (check_domain, username)
    if args.mode in ["contact-only", "deep", "fast"]:
        if email:
            module_jobs['email'] = (check_email, email)
        if phone:
            module_jobs['phone'] = (check_phone, phone)
    # Name analysis treated as soft normalizer, not public search.
    if name:
        ctx.analysis["name"] = name

    logger.info("Starting OSINT module execution...")

    # === Module Execution (parallel where possible) ===
    module_results = run_parallel_functions(module_jobs) if module_jobs else {}

    # Unpack and post-process module results
    for key, result in module_results.items():
        ctx.analysis[key] = result
        logger.info(f"{key.capitalize()} module: {len(result) if hasattr(result, '__len__') else 'OK'} result(s)")

    # Aggregate input context for risk/correlation
    logger.info("Correlating results and aggregating context for explainability...")
    ctx.correlation = correlate_context(ctx.analysis)
    ctx.explanation = explain_findings(ctx)

    # === Risk Scoring (always run) ===
    logger.info("Calculating risk/footprint score...")
    try:
        risk_score, risk_level = calculate_risk_score(ctx.analysis)
        ctx.risk_score = risk_score
        ctx.risk_level = risk_level
    except Exception as e:
        logger.error(f"Risk scoring failed: {e}")
        ctx.risk_score = None
        ctx.risk_level = "undetermined"

    # === Final Reporting ===
    elapsed = time.perf_counter() - overall_timer
    ctx.run_metadata['duration_sec'] = round(elapsed, 2)

    print("\n================ OSINT SUMMARY ================\n")
    for k, v in ctx.input.items():
        if v:
            print(f"Input: {k:10}: {v}")
    print(f"Mode:           {args.mode}")
    print(f"Risk:           {ctx.risk_level} ({ctx.risk_score}/100)")
    print("\n--- Short Findings ---")
    print(ctx.explanation if ctx.explanation else "No major findings.")
    print("\n  (Full report written to output files below)")

    # TXT Report
    write_output_txt(ctx, filename=args.output)
    print(f"✓ TXT report written: {args.output}")

    # JSON Report (if requested)
    if args.json:
        json_filename = args.output.rsplit('.', 1)[0] + ".json"
        write_output_json(ctx, filename=json_filename)
        print(f"✓ JSON report written: {json_filename}")

    print("\n===============================================")
    print("Analysis complete. Review the reports for details.")
    print("Reminder: Results use public data only and do NOT confirm identity.")
    print("================================================\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user. Exiting gracefully.")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(2)
