#!/usr/bin/env python3
"""
Keras/HDF5 Scanner Agent for GuardModel

Detects malicious payloads in Keras model files.
Supports: .h5, .hdf5, .keras

Keras models can contain Lambda layers with arbitrary Python code.
"""

import os
import sys
import json
import hashlib
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
import time

# Try to import h5py for HDF5 support
try:
    import h5py
    H5PY_AVAILABLE = True
except ImportError:
    H5PY_AVAILABLE = False


@dataclass
class Finding:
    """Represents a security finding in a scanned file."""
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    pattern: str = ""
    location: str = ""
    context: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    file: str
    format: str
    size: int
    sha256: str
    scan_duration: float
    status: str  # 'clean', 'suspicious', 'malicious', 'error'
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class KerasAgent:
    """
    Keras/HDF5 Scanner Agent

    Detects malicious payloads in Keras model files.
    Keras models can contain Lambda layers with arbitrary code.
    """

    NAME = "keras_agent"
    VERSION = "1.0.0"
    SUPPORTED_EXTENSIONS = ['.h5', '.hdf5', '.keras']

    # Dangerous patterns in Lambda layer code
    DANGEROUS_LAMBDA_PATTERNS: List[Tuple[str, str, str]] = [
        ('os.system', 'critical', 'System command in Lambda'),
        ('os.popen', 'critical', 'Piped command in Lambda'),
        ('subprocess', 'critical', 'Subprocess in Lambda'),
        ('eval(', 'critical', 'Eval in Lambda'),
        ('exec(', 'critical', 'Exec in Lambda'),
        ('compile(', 'critical', 'Compile in Lambda'),
        ('__import__', 'high', 'Dynamic import in Lambda'),
        ('importlib', 'high', 'Import lib in Lambda'),
        ('open(', 'medium', 'File operation in Lambda'),
        ('socket', 'critical', 'Network socket in Lambda'),
        ('requests.', 'high', 'HTTP request in Lambda'),
        ('urllib', 'high', 'URL operation in Lambda'),
        ('pickle', 'high', 'Pickle in Lambda'),
        ('marshal', 'high', 'Marshal in Lambda'),
        ('ctypes', 'high', 'Ctypes in Lambda'),
        ('pty.spawn', 'critical', 'PTY spawn in Lambda'),
        ('shutil.rmtree', 'critical', 'Recursive delete in Lambda'),
        ('os.remove', 'high', 'File deletion in Lambda'),
        ('os.chmod', 'high', 'Permission change in Lambda'),
    ]

    def __init__(self, rules: Optional[List[Dict]] = None):
        """Initialize the Keras Agent with optional custom rules."""
        self.rules = rules or []

    def can_scan(self, file_path: str) -> bool:
        """Check if this agent can handle the file."""
        ext = Path(file_path).suffix.lower()
        if ext in self.SUPPORTED_EXTENSIONS:
            return True

        # Check HDF5 magic bytes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                # HDF5 signature: \x89HDF\r\n\x1a\n
                return header == b'\x89HDF\r\n\x1a\n'
        except (IOError, OSError):
            pass

        return False

    def scan(self, file_path: str, options: Optional[Dict] = None) -> ScanResult:
        """Scan Keras/HDF5 model file."""
        start_time = time.time()
        options = options or {}
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {}

        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)

        ext = Path(file_path).suffix.lower()

        try:
            if ext == '.keras':
                # Keras v3 format (ZIP-based)
                findings.extend(self._scan_keras_v3(file_path))
                detected_format = 'keras_v3'
            else:
                # Try HDF5 first, then Keras v3
                with open(file_path, 'rb') as f:
                    header = f.read(8)

                if header == b'\x89HDF\r\n\x1a\n':
                    findings.extend(self._scan_hdf5(file_path))
                    detected_format = 'hdf5'
                elif header[:4] == b'PK\x03\x04':
                    findings.extend(self._scan_keras_v3(file_path))
                    detected_format = 'keras_v3'
                else:
                    findings.extend(self._scan_hdf5(file_path))
                    detected_format = 'hdf5'

            metadata['detected_format'] = detected_format
            metadata['h5py_available'] = H5PY_AVAILABLE

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
            format=metadata.get('detected_format', 'keras'),
            size=file_size,
            sha256=sha256,
            scan_duration=scan_duration,
            status=status,
            findings=[asdict(f) for f in findings],
            metadata=metadata
        )

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _scan_keras_v3(self, file_path: str) -> List[Finding]:
        """Scan Keras v3 format (ZIP-based)."""
        findings: List[Finding] = []

        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                members = zf.namelist()

                # Check for config.json
                if 'config.json' in members:
                    config_data = zf.read('config.json').decode('utf-8')
                    findings.extend(self._analyze_keras_config(config_data, 'config.json'))

                # Check for any pickle files
                for name in members:
                    if name.endswith('.pkl') or name.endswith('.pickle'):
                        findings.append(Finding(
                            rule_id='MG_KERAS_PICKLE',
                            category='CODE_EXECUTION',
                            severity='high',
                            title='Pickle file in Keras archive',
                            description=f'Found pickle file: {name}',
                            location=name,
                            remediation='Extract and scan pickle file with pickle_agent'
                        ))

                    # Check for Python files
                    if name.endswith('.py'):
                        findings.append(Finding(
                            rule_id='MG_KERAS_PYTHON',
                            category='CODE_EXECUTION',
                            severity='high',
                            title='Python file in Keras archive',
                            description=f'Found Python file: {name}',
                            location=name,
                            remediation='Review Python file for malicious code'
                        ))

                # Check for model.weights.h5 or similar
                for name in members:
                    if name.endswith('.h5') or name.endswith('.hdf5'):
                        # Extract and scan HDF5
                        import tempfile
                        with tempfile.NamedTemporaryFile(suffix='.h5', delete=False) as tmp:
                            tmp.write(zf.read(name))
                            tmp_path = tmp.name

                        try:
                            hdf5_findings = self._scan_hdf5(tmp_path)
                            for f in hdf5_findings:
                                f.location = f'{file_path}!{name}'
                            findings.extend(hdf5_findings)
                        finally:
                            os.unlink(tmp_path)

        except zipfile.BadZipFile:
            # Not a ZIP, try HDF5
            findings.extend(self._scan_hdf5(file_path))

        return findings

    def _scan_hdf5(self, file_path: str) -> List[Finding]:
        """Scan HDF5 format Keras model."""
        findings: List[Finding] = []

        if not H5PY_AVAILABLE:
            findings.append(Finding(
                rule_id='MG_NO_H5PY',
                category='ERROR',
                severity='info',
                title='h5py not available',
                description='Cannot scan HDF5 without h5py library',
                remediation='Install h5py: pip install h5py'
            ))
            return findings

        try:
            with h5py.File(file_path, 'r') as f:
                # Check for model config
                if 'model_config' in f.attrs:
                    config_str = f.attrs['model_config']
                    if isinstance(config_str, bytes):
                        config_str = config_str.decode('utf-8')
                    findings.extend(self._analyze_keras_config(config_str, 'model_config'))

                # Check keras_version attribute
                if 'keras_version' in f.attrs:
                    keras_version = f.attrs['keras_version']
                    if isinstance(keras_version, bytes):
                        keras_version = keras_version.decode('utf-8')

                # Recursively check groups for suspicious attributes
                findings.extend(self._check_hdf5_group(f, '/'))

        except Exception as e:
            findings.append(Finding(
                rule_id='MG_HDF5_ERROR',
                category='ERROR',
                severity='info',
                title='HDF5 read error',
                description=str(e),
                remediation='File may be corrupt or not a valid HDF5'
            ))

        return findings

    def _check_hdf5_group(self, group, path: str) -> List[Finding]:
        """Recursively check HDF5 groups for suspicious content."""
        findings: List[Finding] = []

        try:
            for key in group.keys():
                try:
                    item = group[key]
                    full_path = f'{path}/{key}' if path != '/' else f'/{key}'

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

                        # Check for custom objects
                        if 'custom' in key.lower():
                            findings.append(Finding(
                                rule_id='MG_KERAS_CUSTOM',
                                category='SUSPICIOUS_STRUCTURE',
                                severity='medium',
                                title='Custom object detected',
                                description=f'Custom object at: {full_path}',
                                location=full_path,
                                remediation='Review custom object code'
                            ))

                        # Recurse into group
                        findings.extend(self._check_hdf5_group(item, full_path))

                    elif isinstance(item, h5py.Dataset):
                        # Check dataset attributes
                        pass

                except Exception:
                    continue

            # Check group attributes
            for attr_name in group.attrs.keys():
                try:
                    attr_value = group.attrs[attr_name]
                    if isinstance(attr_value, bytes):
                        attr_value = attr_value.decode('utf-8', errors='replace')
                    elif isinstance(attr_value, str):
                        pass
                    else:
                        continue

                    # Check for suspicious patterns in attributes
                    for pattern, severity, desc in self.DANGEROUS_LAMBDA_PATTERNS:
                        if pattern in str(attr_value):
                            findings.append(Finding(
                                rule_id='MG_KERAS_DANGEROUS_ATTR',
                                category='CODE_EXECUTION',
                                severity=severity,
                                title=f'Dangerous pattern in attribute',
                                description=f'{desc} in {path}@{attr_name}',
                                pattern=pattern,
                                location=f'{path}@{attr_name}',
                                remediation='Review attribute content'
                            ))
                except Exception:
                    continue

        except Exception:
            pass

        return findings

    def _analyze_keras_config(self, config_str: str, location: str) -> List[Finding]:
        """Analyze Keras model config for dangerous patterns."""
        findings: List[Finding] = []

        try:
            config = json.loads(config_str)
        except json.JSONDecodeError:
            findings.append(Finding(
                rule_id='MG_KERAS_INVALID_CONFIG',
                category='SUSPICIOUS_STRUCTURE',
                severity='low',
                title='Invalid model config',
                description='Model config is not valid JSON',
                location=location,
                remediation='Verify model integrity'
            ))
            return findings

        # Look for Lambda layers recursively
        findings.extend(self._find_lambdas(config, location))

        return findings

    def _find_lambdas(self, obj: Any, path: str = '') -> List[Finding]:
        """Find Lambda layers in config object."""
        findings: List[Finding] = []

        if isinstance(obj, dict):
            class_name = obj.get('class_name', '')

            if class_name == 'Lambda':
                # Check the function config
                config = obj.get('config', {})
                func_config = config.get('function', '')
                func_type = config.get('function_type', '')

                if func_config:
                    # Check for dangerous patterns in lambda function
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

                    # Check if function is pickled
                    if func_type == 'serialized':
                        findings.append(Finding(
                            rule_id='MG_KERAS_PICKLED_LAMBDA',
                            category='CODE_EXECUTION',
                            severity='high',
                            title='Pickled Lambda function',
                            description='Lambda layer contains serialized/pickled function',
                            location=path,
                            remediation='Pickled lambdas can execute arbitrary code'
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

            # Check for other potentially dangerous layers
            if class_name in ['TFOpLambda', 'SlicingOpLambda']:
                findings.append(Finding(
                    rule_id='MG_KERAS_TF_LAMBDA',
                    category='CODE_EXECUTION',
                    severity='medium',
                    title=f'{class_name} detected',
                    description=f'TensorFlow operation layer at: {path}',
                    location=path,
                    remediation='Review operation for security implications'
                ))

            # Recurse into nested structures
            for key, value in obj.items():
                findings.extend(self._find_lambdas(value, f'{path}.{key}'))

        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                findings.extend(self._find_lambdas(item, f'{path}[{i}]'))

        return findings

    def _determine_status(self, findings: List[Finding]) -> str:
        """Determine overall scan status from findings."""
        if not findings:
            return 'clean'

        severities = [f.severity for f in findings]

        if 'critical' in severities:
            return 'malicious'
        elif 'high' in severities:
            return 'suspicious'
        elif 'medium' in severities:
            return 'suspicious'
        else:
            return 'clean'


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='GuardModel Keras Scanner Agent')
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--output', '-o', default='json', choices=['json', 'text'],
                       help='Output format')
    args = parser.parse_args()

    agent = KerasAgent()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    if not agent.can_scan(args.file):
        print(f"Error: Cannot scan {args.file} - unsupported format", file=sys.stderr)
        sys.exit(1)

    result = agent.scan(args.file)

    if args.output == 'json':
        print(json.dumps(asdict(result), indent=2))
    else:
        print(f"File: {result.file}")
        print(f"Format: {result.format}")
        print(f"SHA256: {result.sha256}")
        print(f"Status: {result.status}")
        print(f"Scan Duration: {result.scan_duration:.3f}s")
        print(f"Findings: {len(result.findings)}")
        for f in result.findings:
            severity_icon = {'critical': '!!', 'high': '!', 'medium': '~', 'low': '-', 'info': ' '}.get(f['severity'], ' ')
            print(f"  [{severity_icon}] [{f['severity'].upper():8s}] {f['title']}")

    sys.exit(0 if result.status == 'clean' else 1)


if __name__ == '__main__':
    main()
