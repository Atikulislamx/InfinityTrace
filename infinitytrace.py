import argparse
from modules.username_search import search_username
from modules.email_analysis import check_email
from modules.phone_analysis import check_phone
from modules.image_analysis import check_image
from modules.domain_intel import check_domain
from modules.risk_scoring import calculate_risk_score
from utils.helpers import write_output_txt, write_output_json
from utils.normalizer import normalize_username, normalize_email, normalize_phone, normalize_name
from utils.validators import is_valid_username, is_valid_email, is_valid_phone, is_valid_name

def main():
    parser = argparse.ArgumentParser(
        description="InfinityTrace - Public OSINT Footprint Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python infinitytrace.py --username john_doe
  python infinitytrace.py --username john_doe --email john@example.com
  python infinitytrace.py --username john_doe --output report.txt --json

Note: This tool uses only publicly available data.
        """
    )
    
    parser.add_argument("--username", type=str, help="Username to search")
    parser.add_argument("--email", type=str, help="Email to analyze (public only)")
    parser.add_argument("--phone", type=str, help="Phone to analyze (public only)")
    parser.add_argument("--name", type=str, help="Full name for soft search")
    parser.add_argument("--output", type=str, default="output.txt", help="Output filename (default: output.txt)")
    parser.add_argument("--json", action="store_true", help="Export JSON format")
    
    args = parser.parse_args()
    
    # Check if at least one input is provided
    if not any([args.username, args.email, args.phone, args.name]):
        parser.print_help()
        print("\nError: Please provide at least one input (--username, --email, --phone, or --name)")
        return

    results = {}
    
    # Process username
    if args.username:
        # Validate username
        if not is_valid_username(args.username):
            print(f"Warning: Username '{args.username}' may not be valid (3-30 chars, alphanumeric, _, .)")
        
        # Normalize and search
        normalized_username = normalize_username(args.username)
        print(f"Searching for username: {normalized_username}...")
        results['username'] = search_username(normalized_username)
        results['username_input'] = normalized_username
        print(f"  Found {len(results['username'])} platforms")
    
    # Process email
    if args.email:
        # Validate email
        if not is_valid_email(args.email):
            print(f"Warning: Email '{args.email}' may not be valid")
        
        # Normalize and check
        normalized_email = normalize_email(args.email)
        print(f"Checking email: {normalized_email}...")
        results['email'] = check_email(normalized_email)
        results['email_input'] = normalized_email
        print(f"  Found {len(results['email'])} public reference sources")
    
    # Process phone
    if args.phone:
        # Validate phone
        if not is_valid_phone(args.phone):
            print(f"Warning: Phone '{args.phone}' may not be valid (7-15 digits)")
        
        # Normalize and check
        normalized_phone = normalize_phone(args.phone)
        print(f"Checking phone: {normalized_phone}...")
        results['phone'] = check_phone(normalized_phone)
        results['phone_input'] = normalized_phone
        print(f"  Found {len(results['phone'])} public reference sources")
    
    # Process name
    if args.name:
        # Validate name
        if not is_valid_name(args.name):
            print(f"Warning: Name '{args.name}' may not be valid (letters and spaces only)")
        
        # Normalize
        normalized_name = normalize_name(args.name)
        results['name'] = normalized_name
        print(f"Name provided: {normalized_name}")

    # Image and domain analysis (only if username provided)
    print("\nRunning additional analysis...")
    results['images'] = check_image(args.username) if args.username else []
    results['domains'] = check_domain(args.username) if args.username else []
    
    print(f"  Image analysis: {len(results['images'])} reference sources")
    print(f"  Domain intel: {len(results['domains'])} reference sources")

    # Calculate overall risk
    print("\nCalculating risk score...")
    results['risk_score'], results['risk_level'] = calculate_risk_score(results)
    print(f"  Risk Score: {results['risk_score']}/100")
    print(f"  Risk Level: {results['risk_level']}")

    # Write output
    print(f"\nGenerating reports...")
    write_output_txt(results, filename=args.output)
    print(f"  ✓ Text report written to {args.output}")
    
    if args.json:
        # Create JSON filename by replacing extension or appending .json
        if args.output.endswith('.txt'):
            json_filename = args.output[:-4] + '.json'
        else:
            json_filename = args.output + '.json'
        write_output_json(results, filename=json_filename)
        print(f"  ✓ JSON report written to {json_filename}")
    
    print("\n" + "="*50)
    print("Analysis complete!")
    print("="*50)
    print(f"\nRisk Assessment: {results['risk_level']} ({results['risk_score']}/100)")
    print(f"Review the full report in: {args.output}")
    print("\nDisclaimer: This tool uses only public data and does not confirm identity.")

if __name__ == "__main__":
    main()
