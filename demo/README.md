# GuardModel Demo

This demo project shows how to use GuardModel to scan ML model files for security threats.

## Quick Start

1. **Download demo models:**
   ```bash
   python download_model.py
   ```

2. **Run GuardModel locally:**
   ```bash
   # From the parent directory
   INPUT_PATH="demo/models" node ../dist/index.js
   ```

3. **Or use the GitHub Action:**
   Push to a repo with the workflow in `.github/workflows/scan-models.yml`

## What Gets Scanned

The demo downloads/creates several model files:

| File | Format | Expected Result |
|------|--------|-----------------|
| `pytorch_model.bin` | PyTorch | Clean (safe tensors) |
| `safe_model.pkl` | Pickle | Clean (simple data) |
| `model.safetensors` | SafeTensors | Clean (safe format) |

## GitHub Action Workflow

The workflow (`.github/workflows/scan-models.yml`) demonstrates:

- Automatic scanning on push/PR when models change
- SARIF output for GitHub Security tab integration
- JSON output for programmatic access
- Artifact upload for scan results

## Example Output

```
GuardModel Security Scan

Found 3 model file(s) to scan:
  - pytorch_model.bin (438 MB)
  - safe_model.pkl (256 B)
  - model.safetensors (64 B)

Scanning files for security threats...

Scan complete in 2.34s
  Files scanned: 3
  Total findings: 0

GuardModel: All models passed security scan
```

## Testing Malicious Detection

To test malicious model detection, you can create a pickle with dangerous code:

```python
# WARNING: This creates a malicious file - for testing only!
import pickle
import os

class Malicious:
    def __reduce__(self):
        return (os.system, ('echo pwned',))

with open('models/malicious.pkl', 'wb') as f:
    pickle.dump(Malicious(), f)
```

GuardModel will detect this and report:
```
FAILED - 1 threat detected

| File | Severity | Threat |
|------|----------|--------|
| malicious.pkl | Critical | CODE_EXECUTION |
```
