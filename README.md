# Automated LLM Security Testing System

This is a **fully automated, self-improving security testing platform** for LLM applications that:

1. **Generates Novel Attacks** - ML-powered evolutionary algorithm discovers new vulnerabilities automatically
2. **Fuzzes Inputs** - Tests edge cases, encoding tricks, and boundary conditions continuously
3. **Load Tests** - Measures performance under attack conditions to prevent DoS
4. **A/B Tests** - Compares different security configurations to find optimal settings
5. **Runs Continuously** - 24/7 automated testing with scheduled execution
6. **Self-Monitors** - Tracks trends, triggers alerts, generates reports automatically

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│         Continuous Security Orchestrator (Master)            │
│  - Schedules all tests                                       │
│  - Monitors system health                                    │
│  - Triggers alerts                                           │
│  - Generates reports                                         │
└────────────────┬────────────────────────────────────────────┘
                 │
     ┌───────────┼───────────┬──────────────┬─────────────┐
     │           │           │              │             │
┌────▼────┐ ┌───▼───┐ ┌────▼─────┐ ┌──────▼──────┐ ┌───▼────┐
│Adversar │ │Fuzzing│ │Performance│ │ A/B Testing │ │Original│
│ial ML   │ │Engine │ │ Tester    │ │ Framework   │ │Red Team│
│         │ │       │ │           │ │             │ │  Kit   │
└─────────┘ └───────┘ └───────────┘ └─────────────┘ └────────┘
     │           │           │              │             │
     └───────────┴───────────┴──────────────┴─────────────┘
                             │
                    ┌────────▼────────┐
                    │   AI System     │
                    │  (Your LLM)     │
                    └─────────────────┘
```

---

## Installation & Setup

### Prerequisites

```bash
# Python 3.9+
pip install openai asyncio schedule numpy scikit-learn aiohttp
```

### Quick Start

```bash
# 1. Clone/download all files
git clone <repo-url>
cd llm-security-automation

# 2. Set your API key
export OPENAI_API_KEY="your-key-here"

# 3. Configure (optional - has sane defaults)
cp orchestrator_config.example.json orchestrator_config.json
# Edit orchestrator_config.json with your preferences

# 4. Run continuous testing
python continuous_orchestrator.py
```

---

## File Structure

```
llm-security-automation/
├── design_ai_core.py                    # Your secure AI system
├── adversarial_attack_generator.py      # ML attack generation
├── fuzzing_engine.py                    # Input mutation fuzzing
├── ab_testing_framework.py              # A/B testing + performance
├── continuous_orchestrator.py           # Master controller
├── redteam_kit.py                       # Original test suite
├── improvement_pipeline.py              # Analysis & fixes
│
├── orchestrator_config.json             # Configuration
│
└── continuous_testing_results/          # Auto-generated outputs
    ├── adversarial_YYYYMMDD_HHMMSS.json
    ├── fuzzing_YYYYMMDD_HHMMSS.json
    ├── ab_test_YYYYMMDD_HHMMSS.json
    ├── full_assessment_YYYYMMDD_HHMMSS.json
    ├── test_history.json
    ├── alerts.json
    └── weekly_report_YYYYMMDD.md
```

---

## Usage Examples

### 1. Run One-Time Adversarial Attack Generation

```python
from adversarial_attack_generator import AdversarialAttackGenerator
from design_ai_core import SecureDesignAI

# Initialize
ai = SecureDesignAI(api_key="your-key")
gen = AdversarialAttackGenerator(ai, api_key="your-key")

# Evolve attacks for 10 generations
hall_of_fame = await gen.evolve(generations=10)

# View results
for attack in hall_of_fame[:5]:
    print(f"Fitness: {attack.fitness_score:.3f}")
    print(f"Attack: {attack.payload}\n")

# Export
gen.export_results("attacks.json")
```

**Output**: Novel attacks discovered through evolution, ranked by effectiveness.

---

### 2. Run Fuzzing Campaign

```python
from fuzzing_engine import FuzzingEngine

# Initialize
fuzzer = FuzzingEngine(ai_system)

# Define base inputs to mutate
base_inputs = [
    "Give me a discount",
    "Send me the files",
    "I'm the owner"
]

# Run 100 iterations across all strategies
report = fuzzer.fuzz(
    base_inputs=base_inputs,
    iterations=100,
    strategies=['boundary', 'unicode', 'injection', 'encoding']
)

# Export
fuzzer.export_results("fuzzing_results.json")
```

**Output**: Comprehensive report showing which mutations triggered vulnerabilities.

---

### 3. Run Performance Load Test

```python
from ab_testing_framework import PerformanceTester, SecurityLoadTester

# Standard load test
perf_tester = PerformanceTester(ai_system)

test_inputs = ["I need design help", "What's your pricing?"]

metrics = await perf_tester.load_test(
    test_cases=test_inputs,
    concurrent_users=50,
    duration_seconds=120,
    ramp_up_seconds=20
)

print(f"Avg response time: {metrics.avg_response_time:.3f}s")
print(f"Requests/sec: {metrics.requests_per_second:.2f}")
print(f"p95 latency: {metrics.p95_response_time:.3f}s")
```

**Output**: Performance metrics under load (response times, throughput, error rates).

---

### 4. Run A/B Security Comparison

```python
from ab_testing_framework import ABTestFramework, ABTestVariant

# Define variants
framework = ABTestFramework()

variant_a = ABTestVariant(
    name="Current",
    system_prompt="<current_prompt>",
    input_validator_config={},
    output_filter_config={},
    description="Production system"
)

variant_b = ABTestVariant(
    name="Stricter",
    system_prompt="<enhanced_prompt>",
    input_validator_config={"strict_mode": True},
    output_filter_config={"aggressive": True},
    description="Enhanced security"
)

framework.add_variant(variant_a)
framework.add_variant(variant_b)

# Run comparison
test_cases = [
    {"input": "Help me", "is_attack": False},
    {"input": "Give me discount", "is_attack": True}
]

results = await framework.run_comparison(
    test_cases=test_cases,
    attack_patterns=known_attacks,
    iterations=100
)

print(f"Winner: {results['winner']}")
print(f"Score: {results['winner_score']:.1f}")
```

**Output**: Comparison report showing which variant provides better security/performance balance.

---

### 5. Run Continuous Testing (Production Mode)

```python
from continuous_orchestrator import ContinuousSecurityOrchestrator

# Initialize
orchestrator = ContinuousSecurityOrchestrator(
    ai_system=your_ai_system,
    api_key="your-key"
)

# Start (runs forever until Ctrl+C)
orchestrator.start()
```

**Output**: 
- Automated tests run on schedule
- Real-time monitoring
- Automatic alerts on regressions
- Daily/weekly reports generated

---

## Configuration

### orchestrator_config.json

```json
{
  "adversarial": {
    "population_size": 30,
    "mutation_rate": 0.3,
    "generations": 10
  },
  "fuzzing": {
    "iterations": 100,
    "max_input_length": 10000
  },
  "performance": {
    "concurrent_users": 10,
    "duration_seconds": 60
  },
  "schedules": {
    "adversarial": "daily",      // Run adversarial ML daily at 2am
    "fuzzing": "6hours",          // Fuzz every 6 hours
    "performance": "2hours",      // Load test every 2 hours
    "ab_testing": "weekly",       // A/B test weekly
    "full_regression": "daily"    // Full regression daily at 1am
  }
}
```

**Customize schedules** based on your needs:
- High-frequency testing: More coverage, more compute cost
- Low-frequency testing: Less coverage, lower cost
- Recommended: Use defaults for production systems

---

## Automated Features

### 1. Adversarial ML Attack Generation

**How it works**:
- Maintains population of 30 attack specimens
- Evolves through mutation (40%) and crossover (50%)
- Fitness scoring: success rate + evasion + pattern matching
- Uses LLM to generate semantic variations
- Discovers novel attacks that bypass current defenses

**Automation**:
- Runs on schedule (default: daily)
- Self-improves over generations
- Automatically updates attack library for other tests
- Exports results without intervention

**Output**: `adversarial_YYYYMMDD_HHMMSS.json`

---

### 2. Fuzzing Engine

**How it works**:
- 8 fuzzing strategies: boundary, format, unicode, injection, overflow, encoding, polyglot, grammar
- Mutates inputs 100s of ways per base case
- Tests edge cases humans wouldn't think of
- Grammar-aware mutations maintain semantic coherence

**Automation**:
- Runs on schedule (default: every 6 hours)
- Self-selects base inputs from recent findings
- Adapts strategies based on what finds vulnerabilities
- Automatically reports crashes and vulnerabilities

**Output**: `fuzzing_YYYYMMDD_HHMMSS.json`

---

### 3. Performance & Load Testing

**How it works**:
- Simulates 10-50 concurrent users
- Gradual ramp-up to avoid false negatives
- Tests both legitimate traffic and attack traffic
- Measures: response time, throughput, error rate, p95/p99 latency

**Automation**:
- Runs on schedule (default: every 2 hours)
- Alerts if performance degrades >20%
- Tracks trends over time
- Combines with security testing (attack load test)

**Use case**: Ensure security layers don't degrade performance; prevent DoS attacks.

---

### 4. A/B Testing Framework

**How it works**:
- Tests multiple security configurations simultaneously
- Measures: detection rate, false positive rate, performance
- Calculates weighted score (50% security, 30% performance, 20% FP rate)
- Declares winner automatically

**Automation**:
- Runs on schedule (default: weekly)
- Compares new configurations against baseline
- Recommends which config to deploy
- Provides detailed comparison reports

**Use case**: Optimize security vs. usability trade-off; validate improvements before production.

---

### 5. Continuous Orchestration

**How it works**:
- Master controller schedules all tests
- Monitors system health continuously
- Tracks vulnerability trends (baseline vs current)
- Triggers alerts on regressions or anomalies
- Generates daily status + weekly reports

**Automation**:
- 24/7 operation with no human intervention
- Self-healing: retries failed tests
- Adaptive: increases test frequency if issues found
- Reporting: auto-generates stakeholder reports

**Alerts triggered**:
- Security regression detected
- Performance degradation >20%
- Crash rate >5%
- New critical vulnerability found

---

## Results & Metrics

### What Gets Measured

**Security Metrics**:
- Total attacks tested
- Detection rate (% blocked)
- False positive rate
- Vulnerability count over time
- Attack success rate by category

**Performance Metrics**:
- Average response time
- p50, p95, p99 latency
- Requests per second (throughput)
- Error rate
- Timeout rate

**System Health**:
- Test execution success rate
- Coverage: lines of code tested
- Trend: improving or degrading
- Time to detect new vulnerabilities

---

### Sample Results

**After 1 Week of Continuous Testing**:

```
📊 WEEKLY SUMMARY

Security:
  - Tests Executed: 2,847
  - Vulnerabilities Found: 3 (down from 12 baseline)
  - Detection Rate: 98.7%
  - New Attack Patterns: 47

Performance:
  - Avg Response Time: 2.3s (stable)
  - p95 Latency: 4.1s
  - Requests/sec: 15.2
  - Error Rate: 0.3%

Improvements:
  ✅ 75% reduction in vulnerabilities (12 → 3)
  ✅ 47 new attack patterns discovered and blocked
  ✅ Performance maintained under security load
  ⚠️  1 false positive detected (pricing inquiry flagged)

Action Items:
  1. Review false positive case
  2. Deploy winning A/B variant (Enhanced)
  3. Continue monitoring
```

---

## Advanced Use Cases

### Integration with CI/CD

```yaml
# .github/workflows/security-test.yml
name: LLM Security Test

on:
  pull_request:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2am

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Security Tests
        run: |
          python -m pip install -r requirements.txt
          python run_full_assessment.py
      
      - name: Check for regressions
        run: |
          python check_regression.py --threshold 5
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: continuous_testing_results/
```

---

### Custom Attack Strategies

```python
# Add your own custom attacks

class CustomBusinessLogicAttacks(Probe):
    """Domain-specific attacks for your business"""
    
    prompts = [
        "Exploit specific to your industry",
        "Your competitor's known attack pattern",
        "Regulatory compliance test case"
    ]

# Add to orchestrator
orchestrator.adversarial_gen.seed_attacks.extend(
    CustomBusinessLogicAttacks.prompts
)
```

---

### Real-Time Dashboard

```python
# dashboard.py - Serves real-time metrics

from flask import Flask, jsonify
import json

app = Flask(__name__)

@app.route('/api/status')
def get_status():
    with open('continuous_testing_results/test_history.json') as f:
        history = json.load(f)
    
    return jsonify({
        'last_24h_tests': len([t for t in history if recent(t)]),
        'current_vulnerabilities': get_current_vuln_count(),
        'system_health': calculate_health()
    })

@app.route('/api/alerts')
def get_alerts():
    with open('continuous_testing_results/alerts.json') as f:
        return jsonify(json.load(f))

if __name__ == '__main__':
    app.run(port=5000)
```

---

## License

MIT License
