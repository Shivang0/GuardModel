# ModelGuard Agents.md
## Scanning Agents Architecture & Implementation

**Version:** 1.0.0  
**Build Target:** Weekend MVP

---

## Overview

ModelGuard uses a multi-agent architecture where specialized scanning agents handle different model file formats. Each agent is designed to detect format-specific threats while maintaining a consistent interface for the orchestrator.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Orchestrator                             │
│                    (Coordinates all agents)                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┬───────────────┐
            ▼               ▼               ▼               ▼
    ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
    │  Pickle   │   │   Keras   │   │   ONNX    │   │   Safe    │
    │   Agent   │   │   Agent   │   │   Agent   │   │  Tensors  │
    │           │   │           │   │           │   │   Agent   │
    └───────────┘   └───────────┘   └───────────┘   └───────────┘
         │               │               │               │
    ┌────┴────┐     ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
    │fickling │     │h5py     │     │onnx     │     │safetens │
    │picklescan│    │keras    │     │validator│     │ors      │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

---

## Agent Interface

All agents implement a common interface for consistent orchestration:

```typescript
// src/scanners/base.ts

export interface ScanResult {
  file: string;
  format: string;
  size: number;
  sha256: string;
  scanDuration: number;
  status: 'clean' | 'suspicious' | 'malicious' | 'error';
  findings: Finding[];
  metadata: Record<string, unknown>;
}

export interface Finding {
  ruleId: string;
  category: ThreatCategory;
  severity: Severity;
  title: string;
  description: string;
  pattern?: string;
  location?: string;
  context?: string;
  remediation: string;
  references: string[];
}

export type ThreatCategory =
  | 'CODE_EXECUTION'
  | 'REVERSE_SHELL'
  | 'FILE_SYSTEM'
  | 'NETWORK'
  | 'DANGEROUS_IMPORT'
  | 'OBFUSCATION'
  | 'KNOWN_MALWARE'
  | 'CVE_VULNERABLE'
  | 'SUSPICIOUS_STRUCTURE';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ScannerAgent {
  name: string;
  version: string;
  supportedFormats: string[];
  
  // Check if this agent can handle the file
  canScan(file: FileInfo): boolean;
  
  // Perform the scan
  scan(file: FileInfo, options: ScanOptions): Promise<ScanResult>;
  
  // Get agent status/health
  getStatus(): AgentStatus;
}

export interface FileInfo {
  path: string;
  name: string;
  extension: string;
  size: number;
  magicBytes: Buffer;
}

export interface ScanOptions {
  timeout: number;
  rules: Rule[];
  allowlist: string[];
  maxDepth: number;  // For nested/compressed files
}
```

---

## Agent 1: Pickle Scanner Agent

**Priority: CRITICAL - Build First**

The Pickle Agent is the most important scanner as pickle-based formats represent the highest risk attack surface.

### Supported Formats

| Extension | Format | Risk Level |
|-----------|--------|------------|
| .pkl | Python Pickle | Critical |
| .pickle | Python Pickle | Critical |
| .pt | PyTorch model | Critical |
| .pth | PyTorch checkpoint | Critical |
| .bin | PyTorch/Transformers binary | Critical |
| .joblib | Joblib serialized | Critical |

### Magic Bytes Detection

```python
# python/utils/magic.py

PICKLE_MAGIC = {
    b'\x80\x02': 'pickle_v2',
    b'\x80\x03': 'pickle_v3',
    b'\x80\x04': 'pickle_v4',
    b'\x80\x05': 'pickle_v5',
}

PYTORCH_MAGIC = {
    b'PK\x03\x04': 'pytorch_zip',  # PyTorch uses ZIP format
}

def detect_pickle_format(file_path: str) -> str | None:
    with open(file_path, 'rb') as f:
        header = f.read(8)
        
        # Check ZIP (PyTorch format)
        if header[:4] == b'PK\x03\x04':
            return 'pytorch_zip'
        
        # Check pickle protocol
        if header[:2] in PICKLE_MAGIC:
            return PICKLE_MAGIC[header[:2]]
        
        # Legacy pickle (protocol 0/1)
        if header[0:1] in (b'(', b']', b'}', b'c'):
            return 'pickle_legacy'
    
    return None
```

### Core Implementation

```python
# python/agents/pickle_agent.py

import os
import sys
import json
import hashlib
import tempfile
import zipfile
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict
import pickletools
import fickling.fickle as fickle
from fickling.analysis import check_safety

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    pattern: str = ""
    location: str = ""
    context: str = ""
    remediation: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class ScanResult:
    file: str
    format: str
    size: int
    sha256: str
    scan_duration: float
    status: str
    findings: List[Finding]
    metadata: Dict[str, Any]

class PickleAgent:
    """
    Pickle Scanner Agent
    
    Detects malicious payloads in pickle-based ML model files.
    Uses fickling for AST analysis and custom rules for pattern matching.
    """
    
    NAME = "pickle_agent"
    VERSION = "1.0.0"
    SUPPORTED_FORMATS = ['.pkl', '.pickle', '.pt', '.pth', '.bin', '.joblib']
    
    # Dangerous patterns with severity and context
    DANGEROUS_PATTERNS = {
        # Critical: Direct code execution
        'os.system': ('critical', 'CODE_EXECUTION', 'System command execution'),
        'os.popen': ('critical', 'CODE_EXECUTION', 'Piped command execution'),
        'subprocess.call': ('critical', 'CODE_EXECUTION', 'Subprocess execution'),
        'subprocess.Popen': ('critical', 'CODE_EXECUTION', 'Subprocess execution'),
        'subprocess.run': ('critical', 'CODE_EXECUTION', 'Subprocess execution'),
        'subprocess.check_output': ('critical', 'CODE_EXECUTION', 'Subprocess execution'),
        'builtins.eval': ('critical', 'CODE_EXECUTION', 'Arbitrary code execution via eval()'),
        'builtins.exec': ('critical', 'CODE_EXECUTION', 'Arbitrary code execution via exec()'),
        'builtins.compile': ('critical', 'CODE_EXECUTION', 'Dynamic code compilation'),
        'commands.getoutput': ('critical', 'CODE_EXECUTION', 'Shell command execution'),
        'commands.getstatusoutput': ('critical', 'CODE_EXECUTION', 'Shell command execution'),
        'pty.spawn': ('critical', 'CODE_EXECUTION', 'PTY spawn (potential shell)'),
        
        # Critical: Reverse shells
        'socket.socket': ('critical', 'REVERSE_SHELL', 'Raw socket creation'),
        'socket.create_connection': ('critical', 'REVERSE_SHELL', 'Outbound connection'),
        
        # High: Network operations
        'urllib.request.urlopen': ('high', 'NETWORK', 'URL request capability'),
        'urllib.request.urlretrieve': ('high', 'NETWORK', 'File download capability'),
        'urllib2.urlopen': ('high', 'NETWORK', 'URL request capability'),
        'requests.get': ('high', 'NETWORK', 'HTTP GET request'),
        'requests.post': ('high', 'NETWORK', 'HTTP POST request'),
        'httplib.HTTPConnection': ('high', 'NETWORK', 'HTTP connection'),
        'http.client.HTTPConnection': ('high', 'NETWORK', 'HTTP connection'),
        'ftplib.FTP': ('high', 'NETWORK', 'FTP connection'),
        
        # High: File system operations
        'os.remove': ('high', 'FILE_SYSTEM', 'File deletion'),
        'os.unlink': ('high', 'FILE_SYSTEM', 'File deletion'),
        'os.rmdir': ('high', 'FILE_SYSTEM', 'Directory deletion'),
        'shutil.rmtree': ('high', 'FILE_SYSTEM', 'Recursive directory deletion'),
        'os.rename': ('high', 'FILE_SYSTEM', 'File rename/move'),
        'shutil.move': ('high', 'FILE_SYSTEM', 'File move'),
        'os.chmod': ('high', 'FILE_SYSTEM', 'Permission modification'),
        'os.chown': ('high', 'FILE_SYSTEM', 'Ownership modification'),
        
        # High: Code loading
        'importlib.import_module': ('high', 'DANGEROUS_IMPORT', 'Dynamic module import'),
        '__import__': ('high', 'DANGEROUS_IMPORT', 'Dynamic import'),
        'imp.load_module': ('high', 'DANGEROUS_IMPORT', 'Module loading'),
        'runpy.run_module': ('high', 'DANGEROUS_IMPORT', 'Module execution'),
        'runpy.run_path': ('high', 'DANGEROUS_IMPORT', 'Path execution'),
        
        # High: Obfuscation
        'marshal.loads': ('high', 'OBFUSCATION', 'Marshal deserialization'),
        'base64.b64decode': ('medium', 'OBFUSCATION', 'Base64 decoding'),
        'codecs.decode': ('medium', 'OBFUSCATION', 'Codec decoding'),
        'zlib.decompress': ('medium', 'OBFUSCATION', 'Zlib decompression'),
        
        # Medium: File operations
        'builtins.open': ('medium', 'FILE_SYSTEM', 'File open operation'),
        'io.open': ('medium', 'FILE_SYSTEM', 'File open operation'),
        'pathlib.Path': ('low', 'FILE_SYSTEM', 'Path manipulation'),
        
        # Medium: Dangerous modules
        'ctypes.CDLL': ('high', 'DANGEROUS_IMPORT', 'C library loading'),
        'ctypes.cdll': ('high', 'DANGEROUS_IMPORT', 'C library loading'),
        'ctypes.windll': ('high', 'DANGEROUS_IMPORT', 'Windows DLL loading'),
        
        # Low: Potentially suspicious
        'getattr': ('low', 'SUSPICIOUS_STRUCTURE', 'Dynamic attribute access'),
        'setattr': ('low', 'SUSPICIOUS_STRUCTURE', 'Dynamic attribute setting'),
    }
    
    def __init__(self, rules: List[Dict] = None):
        self.rules = rules or []
        self.custom_patterns = self._load_custom_patterns()
    
    def _load_custom_patterns(self) -> Dict:
        """Load custom patterns from rules config"""
        patterns = {}
        for rule in self.rules:
            if 'pattern' in rule:
                patterns[rule['pattern']] = (
                    rule.get('severity', 'medium'),
                    rule.get('category', 'CUSTOM'),
                    rule.get('message', 'Custom rule match')
                )
        return patterns
    
    def can_scan(self, file_path: str) -> bool:
        """Check if this agent can handle the file"""
        ext = Path(file_path).suffix.lower()
        if ext in self.SUPPORTED_FORMATS:
            return True
        
        # Also check magic bytes for extensionless files
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return header[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05') or \
                       header == b'PK\x03\x04'
        except:
            return False
    
    def scan(self, file_path: str, options: Dict = None) -> ScanResult:
        """
        Perform comprehensive pickle security scan
        
        1. Calculate file hash
        2. Check for PyTorch ZIP format
        3. Extract and analyze pickle content
        4. Run fickling analysis
        5. Pattern match against dangerous functions
        6. Return consolidated findings
        """
        import time
        start_time = time.time()
        
        options = options or {}
        findings = []
        metadata = {}
        
        # Calculate SHA256
        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        # Detect format
        detected_format = self._detect_format(file_path)
        metadata['detected_format'] = detected_format
        
        try:
            # Handle PyTorch ZIP format
            if detected_format == 'pytorch_zip':
                findings.extend(self._scan_pytorch_zip(file_path))
            else:
                findings.extend(self._scan_raw_pickle(file_path))
            
            # Run fickling analysis
            fickling_findings = self._run_fickling(file_path)
            findings.extend(fickling_findings)
            
        except Exception as e:
            findings.append(Finding(
                rule_id='MG_ERROR',
                category='ERROR',
                severity='info',
                title='Scan Error',
                description=f'Error during scan: {str(e)}',
                remediation='Manual review recommended'
            ))
        
        # Determine overall status
        status = self._determine_status(findings)
        
        scan_duration = time.time() - start_time
        
        return ScanResult(
            file=file_path,
            format=detected_format or 'pickle',
            size=file_size,
            sha256=sha256,
            scan_duration=scan_duration,
            status=status,
            findings=[asdict(f) for f in findings],
            metadata=metadata
        )
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _detect_format(self, file_path: str) -> str:
        """Detect pickle format from magic bytes"""
        with open(file_path, 'rb') as f:
            header = f.read(4)
            
            if header == b'PK\x03\x04':
                return 'pytorch_zip'
            elif header[:2] == b'\x80\x05':
                return 'pickle_v5'
            elif header[:2] == b'\x80\x04':
                return 'pickle_v4'
            elif header[:2] == b'\x80\x03':
                return 'pickle_v3'
            elif header[:2] == b'\x80\x02':
                return 'pickle_v2'
            else:
                return 'pickle_legacy'
    
    def _scan_pytorch_zip(self, file_path: str) -> List[Finding]:
        """Scan PyTorch ZIP format (contains pickled data)"""
        findings = []
        
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    # List contents
                    members = zf.namelist()
                    
                    # Look for pickle files inside
                    pickle_members = [m for m in members if 
                                     m.endswith('.pkl') or 
                                     'data.pkl' in m or
                                     m.startswith('archive/data')]
                    
                    for member in pickle_members:
                        extracted_path = zf.extract(member, tmpdir)
                        member_findings = self._scan_raw_pickle(extracted_path)
                        
                        # Update location to show nested path
                        for f in member_findings:
                            f.location = f'{file_path}!{member}'
                        
                        findings.extend(member_findings)
                        
            except zipfile.BadZipFile:
                findings.append(Finding(
                    rule_id='MG_CORRUPT_ZIP',
                    category='SUSPICIOUS_STRUCTURE',
                    severity='medium',
                    title='Corrupt ZIP Structure',
                    description='File appears to be PyTorch format but ZIP is corrupt',
                    remediation='Verify file integrity, re-download from source'
                ))
        
        return findings
    
    def _scan_raw_pickle(self, file_path: str) -> List[Finding]:
        """Scan raw pickle file for dangerous patterns"""
        findings = []
        
        # Disassemble pickle and look for dangerous opcodes
        try:
            with open(file_path, 'rb') as f:
                pickle_data = f.read()
            
            # Analyze with pickletools
            opcodes = list(pickletools.genops(pickle_data))
            
            for opcode, arg, pos in opcodes:
                # Check GLOBAL opcode (imports)
                if opcode.name == 'GLOBAL':
                    module_func = arg if isinstance(arg, str) else f"{arg[0]}.{arg[1]}"
                    
                    if module_func in self.DANGEROUS_PATTERNS:
                        severity, category, desc = self.DANGEROUS_PATTERNS[module_func]
                        findings.append(Finding(
                            rule_id=f'MG_{category}',
                            category=category,
                            severity=severity,
                            title=f'Dangerous Import: {module_func}',
                            description=desc,
                            pattern=module_func,
                            location=f'Byte offset: {pos}',
                            remediation=f'Remove {module_func} call. Use SafeTensors format.',
                            references=['https://blog.trailofbits.com/2021/03/15/never-a-dill-moment-exploiting-machine-learning-pickle-files/']
                        ))
                    
                    # Check custom patterns
                    if module_func in self.custom_patterns:
                        severity, category, desc = self.custom_patterns[module_func]
                        findings.append(Finding(
                            rule_id=f'MG_CUSTOM_{category}',
                            category=category,
                            severity=severity,
                            title=f'Custom Rule Match: {module_func}',
                            description=desc,
                            pattern=module_func,
                            location=f'Byte offset: {pos}',
                            remediation='Review this pattern per custom rule definition'
                        ))
                
                # Check REDUCE opcode (function calls)
                elif opcode.name == 'REDUCE':
                    # REDUCE executes a callable - high risk
                    pass  # Handled by fickling's more sophisticated analysis
                    
        except Exception as e:
            findings.append(Finding(
                rule_id='MG_PARSE_ERROR',
                category='SUSPICIOUS_STRUCTURE',
                severity='medium',
                title='Pickle Parse Error',
                description=f'Could not parse pickle structure: {str(e)}',
                remediation='File may be corrupt or obfuscated'
            ))
        
        return findings
    
    def _run_fickling(self, file_path: str) -> List[Finding]:
        """Run fickling security analysis"""
        findings = []
        
        try:
            # Use fickling to check safety
            result = check_safety(file_path)
            
            if not result.is_likely_safe:
                # Parse fickling warnings
                for warning in result.warnings:
                    severity = 'high'
                    category = 'CODE_EXECUTION'
                    
                    if 'eval' in warning.lower() or 'exec' in warning.lower():
                        severity = 'critical'
                    elif 'import' in warning.lower():
                        severity = 'high'
                        category = 'DANGEROUS_IMPORT'
                    elif 'network' in warning.lower() or 'socket' in warning.lower():
                        severity = 'critical'
                        category = 'REVERSE_SHELL'
                    
                    findings.append(Finding(
                        rule_id='MG_FICKLING',
                        category=category,
                        severity=severity,
                        title='Fickling Security Warning',
                        description=warning,
                        remediation='Do not load this file without manual review',
                        references=['https://github.com/trailofbits/fickling']
                    ))
                    
        except Exception as e:
            # Fickling may fail on some files - that's okay
            pass
        
        return findings
    
    def _determine_status(self, findings: List[Finding]) -> str:
        """Determine overall scan status from findings"""
        if not findings:
            return 'clean'
        
        severities = [f.severity if isinstance(f, Finding) else f.get('severity') for f in findings]
        
        if 'critical' in severities:
            return 'malicious'
        elif 'high' in severities:
            return 'suspicious'
        elif 'medium' in severities:
            return 'suspicious'
        else:
            return 'clean'


# CLI entry point
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Pickle Scanner Agent')
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--output', '-o', default='json', choices=['json', 'text'])
    args = parser.parse_args()
    
    agent = PickleAgent()
    
    if not agent.can_scan(args.file):
        print(f"Error: Cannot scan {args.file} - unsupported format")
        sys.exit(1)
    
    result = agent.scan(args.file)
    
    if args.output == 'json':
        print(json.dumps(asdict(result), indent=2))
    else:
        print(f"File: {result.file}")
        print(f"Status: {result.status}")
        print(f"Findings: {len(result.findings)}")
        for f in result.findings:
            print(f"  [{f['severity'].upper()}] {f['title']}")
    
    sys.exit(0 if result.status == 'clean' else 1)
```

---

## Agent 2: Keras/HDF5 Scanner Agent

**Priority: HIGH**

### Supported Formats

| Extension | Format | Risk Level |
|-----------|--------|------------|
| .h5 | HDF5 (Keras legacy) | High |
| .hdf5 | HDF5 | High |
| .keras | Keras v3 | High |

### Implementation

```python
# python/agents/keras_agent.py

import os
import json
import hashlib
import tempfile
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    pattern: str = ""
    location: str = ""
    remediation: str = ""
    references: List[str] = None

@dataclass
class ScanResult:
    file: str
    format: str
    size: int
    sha256: str
    scan_duration: float
    status: str
    findings: List[Finding]
    metadata: Dict[str, Any]


class KerasAgent:
    """
    Keras/HDF5 Scanner Agent
    
    Detects malicious payloads in Keras model files.
    Keras models can contain Lambda layers with arbitrary code.
    """
    
    NAME = "keras_agent"
    VERSION = "1.0.0"
    SUPPORTED_FORMATS = ['.h5', '.hdf5', '.keras']
    
    # Lambda layer dangerous patterns
    DANGEROUS_LAMBDA_PATTERNS = [
        ('os.system', 'critical', 'System command in Lambda'),
        ('subprocess', 'critical', 'Subprocess in Lambda'),
        ('eval(', 'critical', 'Eval in Lambda'),
        ('exec(', 'critical', 'Exec in Lambda'),
        ('__import__', 'high', 'Dynamic import in Lambda'),
        ('open(', 'medium', 'File operation in Lambda'),
        ('socket', 'critical', 'Network socket in Lambda'),
        ('requests', 'high', 'HTTP request in Lambda'),
        ('urllib', 'high', 'URL operation in Lambda'),
    ]
    
    def can_scan(self, file_path: str) -> bool:
        """Check if this agent can handle the file"""
        ext = Path(file_path).suffix.lower()
        if ext in self.SUPPORTED_FORMATS:
            return True
        
        # Check HDF5 magic bytes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                # HDF5 signature: \x89HDF\r\n\x1a\n
                return header == b'\x89HDF\r\n\x1a\n'
        except:
            return False
    
    def scan(self, file_path: str, options: Dict = None) -> ScanResult:
        """Scan Keras/HDF5 model file"""
        import time
        start_time = time.time()
        
        findings = []
        metadata = {}
        
        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        ext = Path(file_path).suffix.lower()
        
        try:
            if ext == '.keras':
                findings.extend(self._scan_keras_v3(file_path))
            else:
                findings.extend(self._scan_hdf5(file_path))
                
        except Exception as e:
            findings.append(Finding(
                rule_id='MG_KERAS_ERROR',
                category='ERROR',
                severity='info',
                title='Scan Error',
                description=f'Error scanning Keras file: {str(e)}',
                remediation='Manual review recommended'
            ))
        
        status = self._determine_status(findings)
        scan_duration = time.time() - start_time
        
        return ScanResult(
            file=file_path,
            format='keras' if ext == '.keras' else 'hdf5',
            size=file_size,
            sha256=sha256,
            scan_duration=scan_duration,
            status=status,
            findings=[asdict(f) if isinstance(f, Finding) else f for f in findings],
            metadata=metadata
        )
    
    def _calculate_hash(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _scan_keras_v3(self, file_path: str) -> List[Finding]:
        """Scan Keras v3 format (ZIP-based)"""
        import zipfile
        findings = []
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Check for config.json
                if 'config.json' in zf.namelist():
                    config_data = zf.read('config.json').decode('utf-8')
                    findings.extend(self._analyze_keras_config(config_data))
                
                # Check for any pickle files
                for name in zf.namelist():
                    if name.endswith('.pkl') or name.endswith('.pickle'):
                        findings.append(Finding(
                            rule_id='MG_KERAS_PICKLE',
                            category='CODE_EXECUTION',
                            severity='high',
                            title='Pickle file in Keras archive',
                            description=f'Found pickle file: {name}',
                            location=name,
                            remediation='Extract and scan pickle file separately'
                        ))
                        
        except zipfile.BadZipFile:
            # Not a ZIP, try HDF5
            findings.extend(self._scan_hdf5(file_path))
        
        return findings
    
    def _scan_hdf5(self, file_path: str) -> List[Finding]:
        """Scan HDF5 format Keras model"""
        findings = []
        
        try:
            import h5py
            
            with h5py.File(file_path, 'r') as f:
                # Check for model config
                if 'model_config' in f.attrs:
                    config_str = f.attrs['model_config']
                    if isinstance(config_str, bytes):
                        config_str = config_str.decode('utf-8')
                    findings.extend(self._analyze_keras_config(config_str))
                
                # Recursively check groups for suspicious attributes
                def check_group(group, path=''):
                    for key in group.keys():
                        item = group[key]
                        full_path = f'{path}/{key}'
                        
                        if isinstance(item, h5py.Group):
                            # Check for Lambda layers
                            if 'lambda' in key.lower():
                                findings.append(Finding(
                                    rule_id='MG_KERAS_LAMBDA',
                                    category='CODE_EXECUTION',
                                    severity='medium',
                                    title='Lambda layer detected',
                                    description=f'Lambda layer at: {full_path}',
                                    location=full_path,
                                    remediation='Review Lambda layer code manually'
                                ))
                            check_group(item, full_path)
                
                check_group(f)
                
        except ImportError:
            findings.append(Finding(
                rule_id='MG_NO_H5PY',
                category='ERROR',
                severity='info',
                title='h5py not available',
                description='Cannot scan HDF5 without h5py library',
                remediation='Install h5py: pip install h5py'
            ))
        except Exception as e:
            findings.append(Finding(
                rule_id='MG_HDF5_ERROR',
                category='ERROR',
                severity='info',
                title='HDF5 read error',
                description=str(e),
                remediation='File may be corrupt'
            ))
        
        return findings
    
    def _analyze_keras_config(self, config_str: str) -> List[Finding]:
        """Analyze Keras model config for dangerous patterns"""
        findings = []
        
        try:
            config = json.loads(config_str)
        except json.JSONDecodeError:
            return findings
        
        # Look for Lambda layers
        def find_lambdas(obj, path=''):
            if isinstance(obj, dict):
                class_name = obj.get('class_name', '')
                
                if class_name == 'Lambda':
                    # Check the function config
                    func_config = obj.get('config', {}).get('function', '')
                    
                    if func_config:
                        for pattern, severity, desc in self.DANGEROUS_LAMBDA_PATTERNS:
                            if pattern in str(func_config):
                                findings.append(Finding(
                                    rule_id='MG_KERAS_DANGEROUS_LAMBDA',
                                    category='CODE_EXECUTION',
                                    severity=severity,
                                    title=desc,
                                    description=f'Dangerous pattern in Lambda: {pattern}',
                                    pattern=pattern,
                                    location=path,
                                    remediation='Replace Lambda with safe Keras layer'
                                ))
                    else:
                        # Lambda without visible function - could be pickled
                        findings.append(Finding(
                            rule_id='MG_KERAS_OPAQUE_LAMBDA',
                            category='CODE_EXECUTION',
                            severity='high',
                            title='Opaque Lambda layer',
                            description='Lambda layer with serialized/pickled function',
                            location=path,
                            remediation='Review Lambda source code'
                        ))
                
                for key, value in obj.items():
                    find_lambdas(value, f'{path}.{key}')
                    
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_lambdas(item, f'{path}[{i}]')
        
        find_lambdas(config)
        return findings
    
    def _determine_status(self, findings: List[Finding]) -> str:
        if not findings:
            return 'clean'
        
        severities = [f.severity if isinstance(f, Finding) else f.get('severity') for f in findings]
        
        if 'critical' in severities:
            return 'malicious'
        elif 'high' in severities:
            return 'suspicious'
        elif 'medium' in severities:
            return 'suspicious'
        else:
            return 'clean'
```

---

## Agent 3: ONNX Scanner Agent

**Priority: MEDIUM**

### Implementation

```python
# python/agents/onnx_agent.py

import os
import hashlib
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    pattern: str = ""
    location: str = ""
    remediation: str = ""
    references: List[str] = None

@dataclass
class ScanResult:
    file: str
    format: str
    size: int
    sha256: str
    scan_duration: float
    status: str
    findings: List[Finding]
    metadata: Dict[str, Any]


class ONNXAgent:
    """
    ONNX Scanner Agent
    
    ONNX format is generally safer than pickle but can still have issues:
    - Custom operators with arbitrary code
    - External data files that could be malicious
    - Malformed models that exploit parser vulnerabilities
    """
    
    NAME = "onnx_agent"
    VERSION = "1.0.0"
    SUPPORTED_FORMATS = ['.onnx']
    
    # Known dangerous custom op domains
    DANGEROUS_DOMAINS = [
        'com.microsoft.extensions',  # Some MS extensions can execute code
        'ai.onnx.contrib',  # Contrib ops may be unsafe
    ]
    
    def can_scan(self, file_path: str) -> bool:
        ext = Path(file_path).suffix.lower()
        if ext in self.SUPPORTED_FORMATS:
            return True
        
        # Check ONNX magic bytes (protobuf)
        try:
            with open(file_path, 'rb') as f:
                # ONNX starts with protobuf header
                header = f.read(2)
                return header[0:1] == b'\x08'  # Protobuf field 1, wire type 0
        except:
            return False
    
    def scan(self, file_path: str, options: Dict = None) -> ScanResult:
        import time
        start_time = time.time()
        
        findings = []
        metadata = {}
        
        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        try:
            import onnx
            from onnx import checker
            
            # Load and validate
            model = onnx.load(file_path)
            
            # Run ONNX checker
            try:
                checker.check_model(model)
                metadata['valid'] = True
            except Exception as e:
                findings.append(Finding(
                    rule_id='MG_ONNX_INVALID',
                    category='SUSPICIOUS_STRUCTURE',
                    severity='medium',
                    title='Invalid ONNX model',
                    description=f'Model failed validation: {str(e)}',
                    remediation='Re-export model from source framework'
                ))
                metadata['valid'] = False
            
            # Check for custom operators
            graph = model.graph
            for node in graph.node:
                domain = node.domain or 'ai.onnx'
                
                if domain in self.DANGEROUS_DOMAINS:
                    findings.append(Finding(
                        rule_id='MG_ONNX_CUSTOM_OP',
                        category='DANGEROUS_IMPORT',
                        severity='medium',
                        title=f'Custom operator from {domain}',
                        description=f'Op: {node.op_type}, Domain: {domain}',
                        location=node.name,
                        remediation='Review custom operator implementation'
                    ))
                
                # Check for potentially dangerous op types
                if node.op_type in ['Loop', 'If', 'Scan']:
                    # These can contain subgraphs - recursive check
                    for attr in node.attribute:
                        if attr.type == onnx.AttributeProto.GRAPH:
                            findings.append(Finding(
                                rule_id='MG_ONNX_SUBGRAPH',
                                category='SUSPICIOUS_STRUCTURE',
                                severity='low',
                                title='Model contains subgraph',
                                description=f'Subgraph in {node.op_type} node',
                                location=node.name,
                                remediation='Review subgraph for malicious operations'
                            ))
            
            # Check for external data
            if model.HasField('metadata_props'):
                for prop in model.metadata_props:
                    if 'external' in prop.key.lower():
                        findings.append(Finding(
                            rule_id='MG_ONNX_EXTERNAL',
                            category='FILE_SYSTEM',
                            severity='medium',
                            title='External data reference',
                            description=f'Model references external file: {prop.value}',
                            remediation='Verify external data file is safe'
                        ))
            
            metadata['opset_version'] = model.opset_import[0].version if model.opset_import else 'unknown'
            metadata['ir_version'] = model.ir_version
            
        except ImportError:
            findings.append(Finding(
                rule_id='MG_NO_ONNX',
                category='ERROR',
                severity='info',
                title='onnx library not available',
                description='Cannot scan ONNX without onnx library',
                remediation='Install onnx: pip install onnx'
            ))
        except Exception as e:
            findings.append(Finding(
                rule_id='MG_ONNX_ERROR',
                category='ERROR',
                severity='info',
                title='ONNX scan error',
                description=str(e),
                remediation='File may be corrupt'
            ))
        
        status = self._determine_status(findings)
        scan_duration = time.time() - start_time
        
        return ScanResult(
            file=file_path,
            format='onnx',
            size=file_size,
            sha256=sha256,
            scan_duration=scan_duration,
            status=status,
            findings=[asdict(f) if isinstance(f, Finding) else f for f in findings],
            metadata=metadata
        )
    
    def _calculate_hash(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _determine_status(self, findings: List[Finding]) -> str:
        if not findings:
            return 'clean'
        
        severities = [f.severity if isinstance(f, Finding) else f.get('severity') for f in findings]
        
        if 'critical' in severities:
            return 'malicious'
        elif 'high' in severities:
            return 'suspicious'
        elif 'medium' in severities:
            return 'suspicious'
        else:
            return 'clean'
```

---

## Agent 4: SafeTensors Scanner Agent

**Priority: LOW**

SafeTensors is designed to be safe by default - no code execution possible. Scanning is minimal.

```python
# python/agents/safetensors_agent.py

import os
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    remediation: str = ""

@dataclass
class ScanResult:
    file: str
    format: str
    size: int
    sha256: str
    scan_duration: float
    status: str
    findings: List[Finding]
    metadata: Dict[str, Any]


class SafeTensorsAgent:
    """
    SafeTensors Scanner Agent
    
    SafeTensors is designed to be safe - no arbitrary code execution.
    This agent performs minimal checks:
    - Valid SafeTensors format
    - Metadata inspection
    - Size validation
    """
    
    NAME = "safetensors_agent"
    VERSION = "1.0.0"
    SUPPORTED_FORMATS = ['.safetensors']
    
    def can_scan(self, file_path: str) -> bool:
        ext = Path(file_path).suffix.lower()
        return ext in self.SUPPORTED_FORMATS
    
    def scan(self, file_path: str, options: Dict = None) -> ScanResult:
        import time
        import struct
        
        start_time = time.time()
        findings = []
        metadata = {}
        
        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)
        
        try:
            with open(file_path, 'rb') as f:
                # SafeTensors format: 8-byte header size (little endian) + JSON header + tensors
                header_size_bytes = f.read(8)
                if len(header_size_bytes) < 8:
                    findings.append(Finding(
                        rule_id='MG_ST_TRUNCATED',
                        category='SUSPICIOUS_STRUCTURE',
                        severity='medium',
                        title='Truncated SafeTensors file',
                        description='File too small to be valid SafeTensors',
                        remediation='Re-download file'
                    ))
                else:
                    header_size = struct.unpack('<Q', header_size_bytes)[0]
                    
                    # Sanity check header size
                    if header_size > 100 * 1024 * 1024:  # 100MB header is suspicious
                        findings.append(Finding(
                            rule_id='MG_ST_LARGE_HEADER',
                            category='SUSPICIOUS_STRUCTURE',
                            severity='medium',
                            title='Unusually large header',
                            description=f'Header size: {header_size} bytes',
                            remediation='Verify file integrity'
                        ))
                    
                    # Read and parse header
                    header_bytes = f.read(header_size)
                    try:
                        header = json.loads(header_bytes.decode('utf-8'))
                        metadata['tensor_count'] = len([k for k in header.keys() if k != '__metadata__'])
                        
                        # Check for metadata
                        if '__metadata__' in header:
                            meta = header['__metadata__']
                            metadata['file_metadata'] = meta
                            
                            # Check for suspicious metadata keys
                            suspicious_keys = ['eval', 'exec', 'system', 'import']
                            for key in meta.keys():
                                if any(s in key.lower() for s in suspicious_keys):
                                    findings.append(Finding(
                                        rule_id='MG_ST_SUS_META',
                                        category='SUSPICIOUS_STRUCTURE',
                                        severity='low',
                                        title='Suspicious metadata key',
                                        description=f'Key: {key}',
                                        remediation='Review metadata manually'
                                    ))
                                    
                    except json.JSONDecodeError:
                        findings.append(Finding(
                            rule_id='MG_ST_BAD_HEADER',
                            category='SUSPICIOUS_STRUCTURE',
                            severity='medium',
                            title='Invalid JSON header',
                            description='Header is not valid JSON',
                            remediation='File may be corrupt'
                        ))
                        
        except Exception as e:
            findings.append(Finding(
                rule_id='MG_ST_ERROR',
                category='ERROR',
                severity='info',
                title='SafeTensors scan error',
                description=str(e),
                remediation='File may be corrupt'
            ))
        
        status = self._determine_status(findings)
        scan_duration = time.time() - start_time
        
        return ScanResult(
            file=file_path,
            format='safetensors',
            size=file_size,
            sha256=sha256,
            scan_duration=scan_duration,
            status=status,
            findings=[asdict(f) if isinstance(f, Finding) else f for f in findings],
            metadata=metadata
        )
    
    def _calculate_hash(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _determine_status(self, findings: List[Finding]) -> str:
        if not findings:
            return 'clean'
        
        severities = [f.severity if isinstance(f, Finding) else f.get('severity') for f in findings]
        
        if 'critical' in severities:
            return 'malicious'
        elif 'high' in severities:
            return 'suspicious'
        else:
            return 'clean'
```

---

## Agent Orchestrator

The orchestrator coordinates all agents and aggregates results.

```typescript
// src/orchestrator.ts

import * as core from '@actions/core';
import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

interface FileInfo {
  path: string;
  extension: string;
  size: number;
}

interface ScanResult {
  file: string;
  format: string;
  size: number;
  sha256: string;
  scan_duration: number;
  status: 'clean' | 'suspicious' | 'malicious' | 'error';
  findings: Finding[];
  metadata: Record<string, unknown>;
}

interface Finding {
  rule_id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  pattern?: string;
  location?: string;
  remediation?: string;
  references?: string[];
}

interface AggregatedResults {
  total_files: number;
  files_scanned: number;
  files_skipped: number;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  status: 'passed' | 'failed';
  results: ScanResult[];
  duration_ms: number;
}

// Agent routing based on file extension
const AGENT_ROUTING: Record<string, string> = {
  '.pkl': 'pickle_agent.py',
  '.pickle': 'pickle_agent.py',
  '.pt': 'pickle_agent.py',
  '.pth': 'pickle_agent.py',
  '.bin': 'pickle_agent.py',
  '.joblib': 'pickle_agent.py',
  '.h5': 'keras_agent.py',
  '.hdf5': 'keras_agent.py',
  '.keras': 'keras_agent.py',
  '.onnx': 'onnx_agent.py',
  '.safetensors': 'safetensors_agent.py',
};

export class Orchestrator {
  private pythonPath: string;
  private agentsDir: string;
  private config: Config;
  private allowlist: Set<string>;

  constructor(config: Config) {
    this.pythonPath = process.env.PYTHON_PATH || 'python3';
    this.agentsDir = path.join(__dirname, '..', 'python', 'agents');
    this.config = config;
    this.allowlist = new Set(config.allowlist?.map(a => a.sha256) || []);
  }

  async scanFiles(files: FileInfo[]): Promise<AggregatedResults> {
    const startTime = Date.now();
    const results: ScanResult[] = [];
    let skipped = 0;

    // Process files in parallel (with concurrency limit)
    const concurrency = 4;
    const chunks = this.chunk(files, concurrency);

    for (const chunk of chunks) {
      const chunkResults = await Promise.all(
        chunk.map(file => this.scanFile(file))
      );
      
      for (const result of chunkResults) {
        if (result === null) {
          skipped++;
        } else {
          results.push(result);
        }
      }
    }

    // Aggregate results
    const aggregated = this.aggregateResults(results);
    aggregated.files_skipped = skipped;
    aggregated.duration_ms = Date.now() - startTime;

    return aggregated;
  }

  private async scanFile(file: FileInfo): Promise<ScanResult | null> {
    const ext = path.extname(file.path).toLowerCase();
    const agent = AGENT_ROUTING[ext];

    if (!agent) {
      core.debug(`No agent for extension: ${ext}`);
      return null;
    }

    // Check file size limit
    if (file.size > this.config.maxFileSize) {
      core.warning(`Skipping ${file.path}: exceeds size limit`);
      return null;
    }

    // Run the appropriate Python agent
    const agentPath = path.join(this.agentsDir, agent);
    
    try {
      const result = await this.runPythonAgent(agentPath, file.path);
      
      // Check allowlist
      if (this.allowlist.has(result.sha256)) {
        core.info(`Allowlisted: ${file.path} (${result.sha256})`);
        result.status = 'clean';
        result.findings = [];
      }
      
      return result;
    } catch (error) {
      core.error(`Error scanning ${file.path}: ${error}`);
      return {
        file: file.path,
        format: 'unknown',
        size: file.size,
        sha256: '',
        scan_duration: 0,
        status: 'error',
        findings: [{
          rule_id: 'MG_SCAN_ERROR',
          category: 'ERROR',
          severity: 'info',
          title: 'Scan Error',
          description: String(error),
        }],
        metadata: {}
      };
    }
  }

  private runPythonAgent(agentPath: string, filePath: string): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const proc = spawn(this.pythonPath, [agentPath, filePath, '--output', 'json'], {
        timeout: this.config.timeout || 60000,
      });

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        if (code !== 0 && code !== 1) {
          reject(new Error(`Agent exited with code ${code}: ${stderr}`));
          return;
        }

        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (e) {
          reject(new Error(`Failed to parse agent output: ${stdout}`));
        }
      });

      proc.on('error', (err) => {
        reject(err);
      });
    });
  }

  private aggregateResults(results: ScanResult[]): AggregatedResults {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    for (const result of results) {
      for (const finding of result.findings) {
        switch (finding.severity) {
          case 'critical': critical++; break;
          case 'high': high++; break;
          case 'medium': medium++; break;
          case 'low': low++; break;
        }
      }
    }

    // Determine pass/fail based on config threshold
    const failThreshold = this.config.failOn || 'high';
    let status: 'passed' | 'failed' = 'passed';

    switch (failThreshold) {
      case 'critical':
        if (critical > 0) status = 'failed';
        break;
      case 'high':
        if (critical > 0 || high > 0) status = 'failed';
        break;
      case 'medium':
        if (critical > 0 || high > 0 || medium > 0) status = 'failed';
        break;
      case 'low':
        if (critical > 0 || high > 0 || medium > 0 || low > 0) status = 'failed';
        break;
    }

    return {
      total_files: results.length,
      files_scanned: results.length,
      files_skipped: 0,
      total_findings: critical + high + medium + low,
      critical,
      high,
      medium,
      low,
      status,
      results,
      duration_ms: 0
    };
  }

  private chunk<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}
```

---

## Agent Installation & Dependencies

### requirements.txt

```
fickling>=0.1.0
pickletools-extras>=0.1.0
h5py>=3.8.0
onnx>=1.14.0
safetensors>=0.4.0
```

### Setup Script

```bash
#!/bin/bash
# scripts/setup-agents.sh

set -e

echo "Installing Python dependencies..."
pip install --break-system-packages -q fickling h5py onnx safetensors

echo "Verifying installations..."
python3 -c "import fickling; print('fickling:', fickling.__version__)"
python3 -c "import h5py; print('h5py:', h5py.__version__)"
python3 -c "import onnx; print('onnx:', onnx.__version__)"

echo "Agents ready!"
```

---

## Testing Agents

### Unit Test Example

```python
# tests/test_pickle_agent.py

import pytest
import tempfile
import pickle
import os
from python.agents.pickle_agent import PickleAgent

class TestPickleAgent:
    
    def test_clean_pickle(self):
        """Test scanning a clean pickle file"""
        agent = PickleAgent()
        
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create safe pickle
            pickle.dump({'weights': [1, 2, 3]}, f)
            f.flush()
            
            result = agent.scan(f.name)
            assert result.status == 'clean'
            assert len(result.findings) == 0
            
        os.unlink(f.name)
    
    def test_malicious_os_system(self):
        """Test detection of os.system in pickle"""
        agent = PickleAgent()
        
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create malicious pickle
            class Malicious:
                def __reduce__(self):
                    return (os.system, ('echo pwned',))
            
            pickle.dump(Malicious(), f)
            f.flush()
            
            result = agent.scan(f.name)
            assert result.status in ('malicious', 'suspicious')
            assert any(f['category'] == 'CODE_EXECUTION' for f in result.findings)
            
        os.unlink(f.name)
    
    def test_detects_network(self):
        """Test detection of network operations"""
        agent = PickleAgent()
        
        # Would need to craft specific pickle - simplified test
        # In real tests, use pre-crafted malicious samples
        pass
```

---

## Summary

| Agent | Priority | Formats | Key Threats |
|-------|----------|---------|-------------|
| Pickle Agent | CRITICAL | .pkl, .pt, .pth, .bin | Code execution, reverse shells |
| Keras Agent | HIGH | .h5, .keras | Lambda layers with code |
| ONNX Agent | MEDIUM | .onnx | Custom ops, invalid models |
| SafeTensors Agent | LOW | .safetensors | Format validation only |

Build order:
1. **Pickle Agent** - Handles 80%+ of threats
2. **Orchestrator** - Coordinates agents
3. **Keras Agent** - Second most common format
4. **ONNX Agent** - Growing adoption
5. **SafeTensors Agent** - Minimal risk, quick win
