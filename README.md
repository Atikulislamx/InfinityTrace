# InfinityTrace

![InfinityTrace Banner](https://github.com/Atikulislamx/InfinityTrace/blob/main/assets/image/banner.jpeg)

**InfinityTrace** is an open-source OSINT (Open-Source Intelligence) tool for discovering and analyzing **public digital footprints** across social media platforms and the web.

It maps publicly available accounts, references, and behavioral risk signals associated with usernames, emails, phone numbers, and names — **without accessing private data or confirming real-world identities**.

> 🔍 Trace signals, not people.

Maintained by **Cyber Infinity**

---

## ✨ Key Features

- Cross-platform username discovery with direct profile URLs  
- Public email footprint & reputation checks (non-sensitive)  
- Phone number public references & spam reputation  
- Public profile image reuse detection  
- Domain & external link intelligence  
- Language and behavioral risk pattern analysis  
- Unified risk score with confidence level  
- Human-readable `output.txt` report  

---

## ⚖️ Ethical Scope

InfinityTrace strictly follows **ethical OSINT practices**:

- ✅ Uses publicly available data only  
- ❌ No private, locked, or restricted content  
- ❌ No identity confirmation or personal profiling  
- ❌ No doxxing, harassment, or surveillance  

All outputs are **informational risk indicators**, not factual claims.

---

## 📥 Supported Inputs

You may provide one or more of the following:

- `username`
- `email` (reputation only)
- `phone` (public reference only)
- `name` (soft search, low confidence)

---

## 🛠️ How InfinityTrace Works

1. **Input Normalization**  
   Standardizes usernames, emails, phone numbers, and names.

2. **Public Footprint Discovery**  
   Searches public social platforms, indexed websites, and open datasets.

3. **Correlation Analysis**  
   Identifies overlaps in usernames, bios, images, and links.

4. **Risk Signal Detection**  
   Evaluates behavior patterns, domain age, keyword usage, and reuse signals.

5. **Report Generation**  
   Produces a structured `output.txt` and optional JSON output.

---

## ▶️ Installation & Usage

### Clone the Repository
```bash
git clone https://github.com/Atikulislamx/InfinityTrace.git
cd InfinityTrace
````

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Tool

```bash
python infinitytrace.py --username example_user --email test@gmail.com --phone +8801XXXXXXXXX
```

---

## 🧪 CLI Help Screen (Design)

```bash
InfinityTrace - Public OSINT Footprint Analyzer

Usage:
  infinitytrace.py [options]

Options:
  --username <value>    Search public accounts by username
  --email <value>       Check public email footprint & reputation
  --phone <value>       Check phone number public references
  --name <value>        Soft search using full name
  --output <file>       Output file name (default: output.txt)
  --json                Export machine-readable JSON output
  --help                Show this help message and exit

Note:
  This tool uses public data only and does not confirm identities.
```

---

## 📄 Output Format (`output.txt`)

```
TARGET SUMMARY
--------------
Username: example_user
Platforms Found:
- Instagram: https://instagram.com/example_user
- GitHub: https://github.com/example_user

Account Age (Estimated): ~3 months
Profile Consistency: LOW

RISK INDICATORS
---------------
• Username reused across multiple platforms
• Public profile image reused
• High-risk keywords detected in bio
• Recently registered external domain

EMAIL / PHONE CHECK
-------------------
Email reputation: Referenced in public datasets
Phone reputation: Flagged in public spam reports

FINAL ASSESSMENT
----------------
Overall Risk Score: 78 / 100
Risk Level: HIGH
Confidence Level: Medium

DISCLAIMER
----------
Public data only. No identity confirmation.
```

---

## 📊 Risk Score Formula (Documentation)

InfinityTrace calculates risk using weighted public signals:

| Signal Category           | Weight |
| ------------------------- | ------ |
| Username reuse            | 20%    |
| Profile behavior patterns | 25%    |
| Image reuse               | 15%    |
| Domain & link reputation  | 25%    |
| Language manipulation     | 15%    |

### Formula

```
Risk Score = Σ (Signal Score × Weight)
```

### Risk Levels

* **0–30** → LOW
* **31–60** → MEDIUM
* **61–100** → HIGH

⚠️ Scores represent **risk likelihood**, not proof.

---

## 📁 Project Structure

```
InfinityTrace/
│
├── assets/
│   └── image/
│       └── banner.jpeg
│
├── modules/
│   ├── username_search.py
│   ├── email_analysis.py
│   ├── phone_analysis.py
│   ├── image_analysis.py
│   ├── domain_intel.py
│   └── risk_scoring.py
│
├── utils/
│   ├── normalizer.py
│   ├── validators.py
│   └── helpers.py
│
├── infinitytrace.py
├── requirements.txt
├── output.txt
└── README.md
```

---

## 🤝 CONTRIBUTING (Community Guidelines)

InfinityTrace is a **community-driven open-source project**.

You are welcome to contribute by:

* Adding new public data sources
* Improving detection accuracy
* Refactoring or optimizing code
* Improving documentation

### Contribution Rules

* Public data only
* No identity confirmation logic
* No invasive techniques
* Respect ethical OSINT principles

Pull requests violating these rules will not be accepted.

---

## 🛡️ ETHICAL USE POLICY

By using InfinityTrace, you agree that:

* The tool will be used for research, awareness, and prevention
* Results will not be used for harassment or targeting
* No individual will be claimed as verified or identified

InfinityTrace is **not** a surveillance or hacking tool.

---

## ⚠️ Limitations

* Private or locked profiles are not accessed
* Results may contain false positives
* Data availability depends on public indexing
* Identity ownership is never confirmed

---

## 📜 License & Disclaimer

InfinityTrace is released as an open-source project.
See the `LICENSE` file for details.

The maintainers are not responsible for misuse of this tool.

---

**InfinityTrace**
Maintained by **Cyber Infinity**

```
