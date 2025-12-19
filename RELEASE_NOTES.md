# GuardModel v1.1.0 Release Notes

**Release Date:** December 2024

---

## Overview

GuardModel is a GitHub Action that automatically scans ML model files for malicious code, vulnerabilities, and security risks. It blocks dangerous models before they reach production by detecting pickle deserialization attacks, embedded malware, and suspicious patterns.

---

## What's New in v1.1.0

### SaferPickle Integration

This release integrates features from [Google's SaferPickle](https://github.com/google/saferpickle) project to enhance pickle scanning capabilities:

- **Safe Pattern Whitelist** - Reduces false positives for common ML libraries (numpy, torch, tensorflow, sklearn, pandas, scipy, transformers, etc.)
- **Disguised File Detection** - Detects executables and other files masquerading as pickle files (ELF, PE, PNG, JPEG, PDF, ZIP, etc.)
- **Risk Scoring Algorithm** - Logarithmic scoring that considers the ratio of safe vs unsafe patterns
- **Unknown Pattern Tracking** - Identifies and reports patterns not in safe/unsafe lists
- **Suspicious Pattern Detection** - Flags patterns like `__subclasses__`, `__mro__` that may indicate sandbox escape attempts

### New Detection Patterns

Added detection for:
- `types.CodeType`, `types.FunctionType` - Direct code/function object creation
- `torch.load`, `pandas.read_pickle` - Unsafe deserialization methods
- `dill.load`, `cloudpickle.load`, `joblib.load` - Alternative pickle libraries
- `shelve.open` - Pickle-based database
- `webbrowser.open` - URL opening capability
- `sympy.lambdify` - Code generation

### Enhanced Metadata

Scan results now include:
- `safe_count` - Number of safe patterns detected
- `unsafe_count` - Number of unsafe patterns detected
- `suspicious_count` - Number of suspicious patterns detected
- `unknown_count` - Number of unclassified patterns
- `risk_score` - Numeric risk score (0-10)
- `disguised_file_type` - Type of file if disguised as pickle

---

## Highlights

- **4 Scanner Agents** - Pickle, Keras, ONNX, and SafeTensors
- **85+ Detection Rules** - Comprehensive threat coverage (expanded from 70+)
- **GitHub Integration** - SARIF output for Security tab, PR comments
- **Zero Configuration** - Works out of the box with sensible defaults
- **SaferPickle Integration** - Enhanced pickle analysis with risk scoring

---

## Supported Formats

| Format | Extensions | Scanner | Risk Level |
|--------|-----------|---------|------------|
| Python Pickle | `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.joblib` | Pickle Agent | Critical |
| Keras/HDF5 | `.h5`, `.hdf5`, `.keras` | Keras Agent | High |
| ONNX | `.onnx` | ONNX Agent | Medium |
| SafeTensors | `.safetensors` | SafeTensors Agent | Low |

---

## Detection Categories

### Disguised Files (Critical)
- ELF executables masquerading as pickle files
- Windows PE executables (`.exe`, `.dll`)
- Files with mismatched magic bytes

### Code Execution (Critical)
- `os.system`, `os.popen`, `posix.system`
- `subprocess.Popen`, `subprocess.call`, `subprocess.run`
- `builtins.eval`, `builtins.exec`, `builtins.compile`
- `pty.spawn`, `os.execv`, `os.spawnl`
- `types.CodeType`, `types.FunctionType` (direct code creation)

### Reverse Shells (Critical)
- `socket.socket`, `socket.create_connection`
- Socket + shell execution patterns

### Network Activity (High)
- `urllib.request.urlopen`, `urllib.request.urlretrieve`
- `requests.get`, `requests.post`
- `http.client.HTTPConnection`, `ftplib.FTP`
- `paramiko.SSHClient`, `telnetlib.Telnet`

### File System Operations (High)
- `os.remove`, `os.unlink`, `shutil.rmtree`
- `os.chmod`, `os.chown`, `os.chroot`
- `posix.unlink`, `nt.remove`

### Dangerous Imports (High)
- `importlib.import_module`, `__import__`
- `ctypes.CDLL`, `ctypes.cdll`
- `runpy.run_module`, `runpy.run_path`
- `torch.load`, `pandas.read_pickle`, `joblib.load`
- `dill.load`, `cloudpickle.load`

### Suspicious Patterns (Medium)
- `__subclasses__`, `__mro__`, `__bases__` (sandbox escape techniques)
- `__reduce_ex__`, `__getstate__`, `__setstate__` (custom pickle behavior)

### Obfuscation (Medium-High)
- `base64.b64decode`, `marshal.loads`
- `pickle.loads` (nested pickles)
- `zlib.decompress`, `codecs.decode`

### Keras-Specific (Medium-High)
- Lambda layers with arbitrary Python code
- Pickled Lambda functions
- Custom objects in model config

---

## Quick Start

Add to your workflow (`.github/workflows/security.yml`):

```yaml
name: Model Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Shivang0/GuardModel@v1
```

---

## Configuration

Create `.guardmodel.yml` in your repository root:

```yaml
version: 1

# Directories to scan
include:
  - models/
  - weights/
  - checkpoints/

# Directories to ignore
exclude:
  - tests/fixtures/
  - examples/

# Minimum severity to fail CI (critical, high, medium, low, none)
fail_on: high

# Allowlist known-safe models by SHA256 hash
allowlist:
  - sha256: "a1b2c3d4e5f6..."
    reason: "Verified by security team on 2024-01-15"
  - sha256: "f6e5d4c3b2a1..."
    reason: "Official HuggingFace model"

# File size limits
max_file_size: 5GB
max_total_size: 20GB
```

---

## Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` |
| `config` | Path to config file | `.guardmodel.yml` |
| `fail-on` | Minimum severity to fail | `high` |
| `output-sarif` | Generate SARIF output | `true` |
| `output-json` | Generate JSON output | `true` |
| `comment-on-pr` | Post PR comment with results | `true` |
| `max-file-size` | Maximum file size to scan | `5GB` |

---

## Action Outputs

| Output | Description |
|--------|-------------|
| `status` | Scan status (`passed`, `failed`, `error`) |
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `medium-count` | Number of medium findings |
| `low-count` | Number of low findings |
| `sarif-file` | Path to SARIF output file |
| `json-file` | Path to JSON output file |
| `scan-duration` | Scan duration in milliseconds |

---

## Output Formats

### SARIF (GitHub Security Tab)
Findings automatically appear in the repository's Security tab with:
- Rule descriptions and severity levels
- File locations and byte offsets
- Remediation guidance

### JSON Report
```json
{
  "scan_id": "abc123",
  "timestamp": "2024-12-18T12:00:00Z",
  "status": "failed",
  "summary": {
    "files_scanned": 3,
    "total_findings": 1,
    "critical": 1
  },
  "findings": [
    {
      "file": "models/unsafe.pkl",
      "sha256": "...",
      "threats": [
        {
          "rule_id": "MG_CODE_EXECUTION",
          "severity": "critical",
          "title": "Dangerous Import: posix.system",
          "description": "POSIX system command execution",
          "remediation": "Remove posix.system call. Use SafeTensors format."
        }
      ]
    }
  ]
}
```

### PR Comment
```
## GuardModel Security Scan

**Status:** FAILED - 1 threat detected

| File | Severity | Threat | Details |
|------|----------|--------|---------|
| models/unsafe.pkl | Critical | CODE_EXECUTION | posix.system call detected |

### Recommendations
- Remove or replace the flagged model files
- Consider using SafeTensors format for model weights
```

---

## Example Workflow with SARIF Upload

```yaml
name: Model Security
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Run GuardModel
        uses: Shivang0/GuardModel@v1
        with:
          path: models/
          fail-on: high
          output-sarif: true
```

---

## Security Considerations

- **Local Processing**: All scanning happens locally in the GitHub runner. No model files are uploaded to external servers.
- **No Telemetry**: GuardModel does not collect or transmit any usage data.
- **Isolated Execution**: Scans run in an isolated GitHub Actions environment.
- **Deterministic**: Pinned dependencies ensure reproducible results.

---

## Requirements

- GitHub Actions runner (Ubuntu, macOS, or Windows)
- Node.js 20+ (automatically configured)
- Python 3.10+ (automatically configured)

---

## Known Limitations

- Large models (>5GB default) are skipped by default
- Encrypted or password-protected archives not supported
- Custom pickle subclasses may not be fully analyzed

---

## Troubleshooting

### Scan takes too long
Reduce scope with `include` patterns or increase `max-file-size`.

### False positives
Add verified models to the `allowlist` by SHA256 hash.

### Missing findings
Ensure file extensions are correct (`.pkl`, `.pt`, etc.)

---

## Links

- **Repository**: https://github.com/Shivang0/GuardModel
- **Issues**: https://github.com/Shivang0/GuardModel/issues
- **Marketplace**: https://github.com/marketplace/actions/guardmodel-security-scan

---

## License

Open Database License (ODbL) v1.0 - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with:
- [fickling](https://github.com/trailofbits/fickling) - Pickle security analysis
- [h5py](https://www.h5py.org/) - HDF5 file handling
- [onnx](https://onnx.ai/) - ONNX model validation
- [safetensors](https://github.com/huggingface/safetensors) - Safe tensor format
