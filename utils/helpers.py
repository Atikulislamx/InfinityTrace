"""
Write structured output to text or JSON
"""

def write_output_txt(data, filename="output.txt"):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("TARGET SUMMARY\n")
        f.write("--------------\n")
        for key, value in data.items():
            f.write(f"{key}: {value}\n")
        f.write("\nFINAL ASSESSMENT\n--------------\n")
        f.write(f"Risk Score: {data.get('risk_score', 0)}\n")
        f.write(f"Risk Level: {data.get('risk_level', 'LOW')}\n")
