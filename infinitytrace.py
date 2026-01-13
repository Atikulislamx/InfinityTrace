import argparse
from modules.username_search import search_username
from modules.email_analysis import check_email
from modules.phone_analysis import check_phone
from modules.image_analysis import check_image
from modules.domain_intel import check_domain
from modules.risk_scoring import calculate_risk_score
from utils.helpers import write_output_txt

def main():
    parser = argparse.ArgumentParser(description="InfinityTrace - Public OSINT Footprint Analyzer")
    parser.add_argument("--username", type=str, help="Username to search")
    parser.add_argument("--email", type=str, help="Email to analyze (public only)")
    parser.add_argument("--phone", type=str, help="Phone to analyze (public only)")
    parser.add_argument("--name", type=str, help="Full name for soft search")
    parser.add_argument("--output", type=str, default="output.txt", help="Output filename")
    parser.add_argument("--json", action="store_true", help="Export JSON format")
    
    args = parser.parse_args()

    results = {}
    
    if args.username:
        results['username'] = search_username(args.username)
    
    if args.email:
        results['email'] = check_email(args.email)
    
    if args.phone:
        results['phone'] = check_phone(args.phone)
    
    if args.name:
        results['name'] = args.name  # optional soft search logic

    # Image and domain analysis
    results['images'] = check_image(args.username) if args.username else []
    results['domains'] = check_domain(args.username) if args.username else []

    # Calculate overall risk
    results['risk_score'], results['risk_level'] = calculate_risk_score(results)

    # Write output
    write_output_txt(results, filename=args.output)
    print(f"Output written to {args.output}")

if __name__ == "__main__":
    main()
