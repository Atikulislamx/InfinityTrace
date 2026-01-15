# Risk Scoring Module - Technical Documentation

## Overview

The `risk_scoring.py` module provides professional-grade, explainable OSINT-based risk assessment for the InfinityTrace project. It calculates comprehensive risk scores based on signals from multiple intelligence modules (username, email, phone, image, and domain).

## Key Features

### 1. Confidence-Weighted Scoring
- Each category score is weighted by its confidence level
- Confidence is calculated based on data completeness and quality
- Lower confidence signals contribute less to the overall score

### 2. Adaptive Weight Redistribution
- Handles missing data categories gracefully
- Redistributes weights proportionally when categories have no data
- Ensures fair scoring even with incomplete information

### 3. Correlation-Aware Risk Escalation
- Detects cross-signal correlations that indicate higher risk
- Applies escalation factors when multiple signals reinforce each other
- Examples:
  - Username on many platforms + email presence → MEDIUM escalation
  - Email + phone + username all public → HIGH escalation
  - Domain associations + username reuse → MEDIUM escalation

### 4. Rule-Based Overrides
- Applies minimum risk levels for extremely high-risk patterns
- Examples:
  - Username on 15+ platforms → minimum HIGH risk
  - Low reputation email → +15 points
  - Multiple high-risk signal categories → +10 points

### 5. False Positive Reduction
- Analyzes legitimacy indicators to reduce false positives
- Factors:
  - Professional platform presence (GitHub, LinkedIn, StackOverflow) → -10%
  - Limited username presence → -5 points
  - No spam/disposable indicators → -5 points

### 6. Full Explainability
- Every scoring decision is documented
- Provides human-readable reasoning
- Includes detailed category breakdown
- Lists top contributing factors

## API Documentation

### Main Functions

#### `calculate_risk_score(data: Dict[str, Any]) -> Tuple[int, str]`

**Legacy-compatible function** that returns the basic risk score and level.

**Parameters:**
- `data`: Dictionary containing intelligence module results with keys:
  - `username`: List of username search results
  - `email`: List of email analysis results
  - `phone`: List of phone analysis results
  - `images`: List of image analysis results
  - `domains`: List of domain intelligence results

**Returns:**
- `Tuple[int, str]`: (risk_score, risk_level)
  - `risk_score`: Integer from 0-100
  - `risk_level`: String ("LOW", "MEDIUM", or "HIGH")

**Example:**
```python
from modules.risk_scoring import calculate_risk_score

data = {
    'username': [
        {'platform': 'GitHub', 'confidence_score': 90},
        {'platform': 'Twitter', 'confidence_score': 80}
    ],
    'email': [{'source': 'HaveIBeenPwned'}],
    'phone': [],
    'images': [],
    'domains': []
}

score, level = calculate_risk_score(data)
print(f"Risk: {score}/100 ({level})")
# Output: Risk: 17/100 (LOW)
```

#### `calculate_detailed_risk_score(data: Dict[str, Any]) -> Dict[str, Any]`

**Comprehensive function** that returns detailed risk analysis with full explainability.

**Parameters:**
- `data`: Same as `calculate_risk_score()`

**Returns:**
- Dictionary containing:
  - `overall_risk_score`: int (0-100)
  - `risk_level`: str ("LOW", "MEDIUM", "HIGH")
  - `confidence_level`: str ("LOW", "MEDIUM", "HIGH")
  - `top_risk_factors`: List[str] - Top contributing factors
  - `correlation_flags`: List[Dict] - Detected correlations
  - `reasoning`: str - Human-readable explanation
  - `category_breakdown`: Dict - Detailed breakdown by category
  - `calculation_details`: Dict - Step-by-step calculation info
  - `timestamp`: str - ISO 8601 timestamp

**Example:**
```python
from modules.risk_scoring import calculate_detailed_risk_score
import json

result = calculate_detailed_risk_score(data)
print(json.dumps(result, indent=2))
```

**Sample Output:**
```json
{
  "overall_risk_score": 52,
  "risk_level": "MEDIUM",
  "confidence_level": "MEDIUM",
  "top_risk_factors": [
    "profile_behavior: email found in 2 public sources (contribution: 21.2)",
    "username_reuse: Username found on 5 platforms (contribution: 15.0)"
  ],
  "correlation_flags": [
    {
      "type": "username_email_correlation",
      "description": "Username appears on 5 platforms with public email presence",
      "severity": "MEDIUM"
    }
  ],
  "reasoning": "Risk assessment: MEDIUM (52/100). The score primarily derives from...",
  "category_breakdown": {
    "username_reuse": {
      "score": 75,
      "confidence": "83%",
      "weight": "20%",
      "contribution": "12.5",
      "explanation": "Username found on 5 platforms (high reuse)"
    }
  },
  "calculation_details": {
    "base_score": 42,
    "escalation_factor": "1.52",
    "escalated_score": 63,
    "overrides_applied": 0,
    "reductions_applied": 2,
    "final_score": 52
  }
}
```

## Risk Level Thresholds

- **LOW**: 0-30 points
- **MEDIUM**: 31-60 points
- **HIGH**: 61-100 points

## Category Weights (Default)

| Category | Weight | Description |
|----------|--------|-------------|
| Username Reuse | 20% | Number of platforms where username appears |
| Profile Behavior | 25% | Email/phone presence and patterns |
| Image Reuse | 15% | Profile image reuse across platforms |
| Domain Reputation | 25% | Associated domain count and reputation |
| Language | 15% | Overall digital footprint size |

**Note:** Weights are automatically redistributed when categories have no data.

## Scoring Algorithm

### Step 1: Calculate Individual Category Scores (0-100)

**Username Reuse:**
- 1 platform: 15 points
- 2 platforms: 35 points
- 3-4 platforms: 55 points
- 5-9 platforms: 75 points
- 10+ platforms: 90 points

**Profile Behavior:**
- Email present: +30 points
- Phone present: +30 points
- Username on 3+ platforms: +25 points
- Suspicious email: +15 points

**Image Reuse:**
- 1-2 sources: 30 points
- 3-4 sources: 50 points
- 5+ sources: 70 points

**Domain Reputation:**
- 1 domain: 35 points
- 2-3 domains: 60 points
- 5+ domains: 75 points

**Language/Footprint:**
- 1-4 signals: 20 points
- 5-9 signals: 40 points
- 10-14 signals: 55 points
- 15+ signals: 70 points

### Step 2: Apply Confidence Weighting

Each category score is multiplied by its confidence (0.0-1.0) and weight:

```
weighted_score = category_score × confidence × weight
```

### Step 3: Calculate Base Score

Sum all weighted category scores:

```
base_score = Σ(weighted_scores)
```

### Step 4: Detect Correlations

Check for cross-signal patterns and calculate escalation factor (product of all correlation escalation factors):

```
escalation_factor = Π(correlation_escalation_factors)
```

### Step 5: Apply Escalation

```
escalated_score = base_score × escalation_factor
```

### Step 6: Apply Rule-Based Overrides

Check for high-risk patterns and apply minimum thresholds or point additions.

### Step 7: Reduce False Positives

Check for legitimacy indicators and reduce score accordingly.

### Step 8: Determine Risk Level

Based on final score and thresholds.

## Correlation Types

### 1. Username-Email Correlation (MEDIUM)
- **Trigger**: 5+ platforms + email present
- **Escalation**: 1.15x
- **Reasoning**: Cross-identifier presence increases risk

### 2. Multi-Identifier Correlation (HIGH)
- **Trigger**: Email + phone + 3+ usernames
- **Escalation**: 1.20x
- **Reasoning**: Multiple public identifiers suggest high exposure

### 3. Domain-Username Correlation (MEDIUM)
- **Trigger**: 4+ platforms + 2+ domains
- **Escalation**: 1.10x
- **Reasoning**: Domain associations with username reuse

### 4. High Footprint (HIGH)
- **Trigger**: 20+ total signals
- **Escalation**: 1.25x
- **Reasoning**: Extensive digital presence

## Legitimacy Indicators

### Professional Platform Presence
- **Trigger**: Found on 2+ professional platforms (LinkedIn, GitHub, StackOverflow)
- **Reduction**: -10% of current score
- **Reasoning**: Professional presence indicates legitimate user

### Limited Username Presence
- **Trigger**: Only 1 platform
- **Reduction**: -5 points
- **Reasoning**: Low reuse reduces risk

### No Spam Indicators
- **Trigger**: Email present but not suspicious/disposable
- **Reduction**: -5 points
- **Reasoning**: Clean email reduces risk

## Determinism

The module is fully deterministic:
- Given the same input, it always produces the same output
- No random numbers or time-based variations
- Suitable for testing and auditing

## Libraries Used

Only standard Python libraries (as required):
- `math`: Mathematical operations
- `json`: JSON serialization (for demos)
- `logging`: Diagnostic logging
- `typing`: Type hints
- `datetime`: Timestamps

## Testing

See `test_risk_scoring.py` for comprehensive test suite covering:
- Score normalization
- Confidence calculation
- Weight redistribution
- Correlation detection
- Basic and detailed scoring
- High-risk scenarios
- Legitimacy indicators
- Determinism
- Edge cases
- JSON serialization

Run tests:
```bash
python3 test_risk_scoring.py
```

## Demonstration

See `demo_risk_scoring.py` for interactive demonstration of:
- Moderate digital footprint
- High username reuse
- High-risk profile
- Minimal footprint
- Adaptive weight redistribution

Run demonstration:
```bash
python3 demo_risk_scoring.py
```

## Integration with InfinityTrace

The module integrates seamlessly with the existing codebase:

```python
# In infinitytrace.py
from modules.risk_scoring import calculate_risk_score

# ... collect data from modules ...

risk_score, risk_level = calculate_risk_score(results)
```

The function maintains backward compatibility while providing enhanced functionality.

## Ethical Considerations

- All scoring is based on publicly available data only
- No private or restricted information is used
- Scores indicate risk patterns, not identity confirmation
- Results should be interpreted as signals, not absolute truth

## Future Enhancements

Potential improvements:
- Machine learning-based confidence scoring
- Time-based decay for old data
- Platform-specific risk factors
- Customizable weights per use case
- Multi-language reasoning support
