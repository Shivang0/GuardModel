# GuardModel

**Block malicious AI models in your pipeline with one line of YAML.**

GuardModel is a GitHub Action that automatically scans ML model files for malicious code, vulnerabilities, and security risks in CI/CD pipelines. It blocks dangerous models before they reach production by detecting pickle deserialization attacks, embedded malware, and known CVEs.

## Quick Start

Add to your workflow:

```yaml
name: GuardModel Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: guardmodel/scan@v1
```

That's it! GuardModel will scan all model files and fail the check if threats are detected.

## Features

- **Automatic Detection** - Scans all model files on push/PR
- **Multiple Formats** - Supports pickle, PyTorch, Keras, ONNX, SafeTensors
- **70+ Detection Rules** - Code execution, reverse shells, file system access, network activity
- **GitHub Integration** - SARIF output for Security tab, PR comments, JSON reports
- **Configurable** - Allowlists, severity thresholds, custom rules

## Supported Formats

| Extension | Format | Scanner | Risk Level |
|-----------|--------|---------|------------|
| `.pkl`, `.pickle` | Python Pickle | Pickle Agent | Critical |
| `.pt`, `.pth` | PyTorch | Pickle Agent | Critical |
| `.bin` | PyTorch/Transformers | Pickle Agent | Critical |
| `.h5`, `.hdf5` | HDF5/Keras | Keras Agent | High |
| `.keras` | Keras v3 | Keras Agent | High |
| `.onnx` | ONNX | ONNX Agent | Medium |
| `.safetensors` | SafeTensors | SafeTensors Agent | Low |

## Configuration

Create `.guardmodel.yml` in your repository:

```yaml
version: 1

# Directories to scan
include:
  - models/
  - weights/

# Directories to ignore
exclude:
  - tests/fixtures/

# Severity threshold to fail CI
fail_on: high  # critical, high, medium, low, none

# Allowlist known-safe models by SHA256
allowlist:
  - sha256: "abc123..."
    reason: "Verified by security team"

# Maximum file sizes
max_file_size: 5GB
max_total_size: 20GB
```

## Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` |
| `config` | Config file path | `.guardmodel.yml` |
| `fail-on` | Minimum severity to fail | `high` |
| `output-sarif` | Generate SARIF output | `true` |
| `output-json` | Generate JSON output | `true` |
| `comment-on-pr` | Post PR comment | `true` |
| `max-file-size` | Maximum file size | `5GB` |

## Action Outputs

| Output | Description |
|--------|-------------|
| `status` | Scan status (passed, failed, error) |
| `findings-count` | Total findings |
| `critical-count` | Critical severity findings |
| `high-count` | High severity findings |
| `sarif-file` | Path to SARIF output |
| `json-file` | Path to JSON output |
| `scan-duration` | Duration in milliseconds |

## Threat Detection

GuardModel detects:

- **Code Execution** - `os.system`, `subprocess`, `eval`, `exec`
- **Reverse Shells** - Socket connections with shell execution
- **Network Activity** - HTTP requests, downloads, data exfiltration
- **File System** - File deletion, permission changes
- **Dangerous Imports** - `ctypes`, dynamic imports
- **Obfuscation** - Base64, marshal, nested pickles
- **Known Malware** - Hash and signature matching
- **CVE Vulnerabilities** - Known security issues

## Example Output

### PR Comment

> ## GuardModel Security Scan
>
> **Status:** FAILED - 2 threats detected
>
> | File | Severity | Threat | Details |
> |------|----------|--------|---------|
> | `models/model.pkl` | Critical | CODE_EXECUTION | `os.system` call detected |
> | `models/utils.pt` | High | NETWORK | `socket.socket` creation |

### SARIF Integration

Findings appear in the GitHub Security tab with:
- Rule descriptions
- File locations
- Remediation guidance

## Development

```bash
# Install dependencies
npm install
pip install -r requirements.txt

# Build
npm run build

# Test
npm test
pytest tests/

# Package for release
npm run package
```

## Architecture

```
guardmodel/
├── action.yml              # GitHub Action definition
├── src/                    # TypeScript source
│   ├── index.ts           # Entry point
│   ├── orchestrator.ts    # Scan coordination
│   ├── config.ts          # Configuration
│   ├── walker.ts          # File discovery
│   └── reporters/         # Output formatters
├── python/
│   ├── agents/            # Scanner agents
│   │   ├── pickle_agent.py
│   │   ├── keras_agent.py
│   │   ├── onnx_agent.py
│   │   └── safetensors_agent.py
│   └── rules/             # Detection rules
└── tests/                 # Test suite
```

## Security

GuardModel:
- Scans locally - no files uploaded to external servers
- No telemetry without opt-in
- Runs in isolated GitHub runner environment
- Dependencies pinned with hash verification

## License

MIT

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## Links

- [Documentation](https://guardmodel.dev/docs)
- [Rule Reference](https://guardmodel.dev/rules)
- [GitHub Marketplace](https://github.com/marketplace/actions/guardmodel)
