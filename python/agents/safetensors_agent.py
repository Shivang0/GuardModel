#!/usr/bin/env python3
"""
SafeTensors Scanner Agent for GuardModel

Detects potential issues in SafeTensors model files.
Supports: .safetensors

SafeTensors is designed to be safe - no code execution possible.
This agent performs minimal checks for format validation and metadata inspection.
"""

import os
import sys
import json
import hashlib
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
import time


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
    SUPPORTED_EXTENSIONS = ['.safetensors']

    # Maximum reasonable header size (100MB)
    MAX_HEADER_SIZE = 100 * 1024 * 1024

    # Suspicious metadata keys that might indicate tampering
    SUSPICIOUS_KEYS = [
        'eval', 'exec', 'system', 'import', 'subprocess',
        'socket', 'pickle', 'marshal', 'compile', 'popen',
        '__reduce__', '__import__', 'builtins', 'globals'
    ]

    def __init__(self, rules: Optional[List[Dict]] = None):
        """Initialize the SafeTensors Agent with optional custom rules."""
        self.rules = rules or []

    def can_scan(self, file_path: str) -> bool:
        """Check if this agent can handle the file."""
        ext = Path(file_path).suffix.lower()
        return ext in self.SUPPORTED_EXTENSIONS

    def scan(self, file_path: str, options: Optional[Dict] = None) -> ScanResult:
        """Scan SafeTensors file."""
        start_time = time.time()
        options = options or {}
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {}

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
                        remediation='Re-download file from source'
                    ))
                else:
                    header_size = struct.unpack('<Q', header_size_bytes)[0]
                    metadata['header_size'] = header_size

                    # Sanity check header size
                    if header_size > self.MAX_HEADER_SIZE:
                        findings.append(Finding(
                            rule_id='MG_ST_LARGE_HEADER',
                            category='SUSPICIOUS_STRUCTURE',
                            severity='medium',
                            title='Unusually large header',
                            description=f'Header size: {header_size:,} bytes ({header_size / (1024*1024):.1f} MB)',
                            remediation='Verify file integrity, may be corrupted or malicious'
                        ))
                    elif header_size > file_size:
                        findings.append(Finding(
                            rule_id='MG_ST_INVALID_HEADER_SIZE',
                            category='SUSPICIOUS_STRUCTURE',
                            severity='high',
                            title='Invalid header size',
                            description=f'Header size ({header_size}) exceeds file size ({file_size})',
                            remediation='File is corrupted or maliciously crafted'
                        ))
                    else:
                        # Read and parse header
                        header_bytes = f.read(header_size)

                        if len(header_bytes) < header_size:
                            findings.append(Finding(
                                rule_id='MG_ST_TRUNCATED_HEADER',
                                category='SUSPICIOUS_STRUCTURE',
                                severity='medium',
                                title='Truncated header',
                                description='File ends before header is complete',
                                remediation='Re-download file from source'
                            ))
                        else:
                            try:
                                header = json.loads(header_bytes.decode('utf-8'))
                                metadata['valid_json'] = True

                                # Count tensors (exclude __metadata__)
                                tensor_names = [k for k in header.keys() if k != '__metadata__']
                                metadata['tensor_count'] = len(tensor_names)

                                # Check for __metadata__
                                if '__metadata__' in header:
                                    meta = header['__metadata__']
                                    metadata['file_metadata'] = meta

                                    # Check for suspicious metadata keys
                                    for key in meta.keys():
                                        key_lower = key.lower()
                                        for suspicious in self.SUSPICIOUS_KEYS:
                                            if suspicious in key_lower:
                                                findings.append(Finding(
                                                    rule_id='MG_ST_SUS_META_KEY',
                                                    category='SUSPICIOUS_STRUCTURE',
                                                    severity='low',
                                                    title='Suspicious metadata key',
                                                    description=f'Key "{key}" contains suspicious pattern "{suspicious}"',
                                                    pattern=suspicious,
                                                    location=f'__metadata__.{key}',
                                                    remediation='Review metadata content manually'
                                                ))
                                                break

                                    # Check for suspicious metadata values
                                    for key, value in meta.items():
                                        if isinstance(value, str):
                                            value_lower = value.lower()
                                            for suspicious in self.SUSPICIOUS_KEYS:
                                                if suspicious in value_lower:
                                                    findings.append(Finding(
                                                        rule_id='MG_ST_SUS_META_VALUE',
                                                        category='SUSPICIOUS_STRUCTURE',
                                                        severity='low',
                                                        title='Suspicious metadata value',
                                                        description=f'Value of "{key}" contains suspicious pattern "{suspicious}"',
                                                        pattern=suspicious,
                                                        location=f'__metadata__.{key}',
                                                        remediation='Review metadata content manually'
                                                    ))
                                                    break

                                # Check tensor definitions
                                for tensor_name, tensor_info in header.items():
                                    if tensor_name == '__metadata__':
                                        continue

                                    if not isinstance(tensor_info, dict):
                                        findings.append(Finding(
                                            rule_id='MG_ST_INVALID_TENSOR_DEF',
                                            category='SUSPICIOUS_STRUCTURE',
                                            severity='low',
                                            title='Invalid tensor definition',
                                            description=f'Tensor "{tensor_name}" has invalid definition',
                                            location=tensor_name,
                                            remediation='Verify file integrity'
                                        ))
                                        continue

                                    # Check required fields
                                    if 'dtype' not in tensor_info:
                                        findings.append(Finding(
                                            rule_id='MG_ST_MISSING_DTYPE',
                                            category='SUSPICIOUS_STRUCTURE',
                                            severity='low',
                                            title='Missing dtype',
                                            description=f'Tensor "{tensor_name}" missing dtype field',
                                            location=tensor_name,
                                            remediation='Verify file integrity'
                                        ))

                                    if 'shape' not in tensor_info:
                                        findings.append(Finding(
                                            rule_id='MG_ST_MISSING_SHAPE',
                                            category='SUSPICIOUS_STRUCTURE',
                                            severity='low',
                                            title='Missing shape',
                                            description=f'Tensor "{tensor_name}" missing shape field',
                                            location=tensor_name,
                                            remediation='Verify file integrity'
                                        ))

                                    # Check data offsets
                                    if 'data_offsets' in tensor_info:
                                        offsets = tensor_info['data_offsets']
                                        if isinstance(offsets, list) and len(offsets) == 2:
                                            start, end = offsets
                                            if end < start:
                                                findings.append(Finding(
                                                    rule_id='MG_ST_INVALID_OFFSET',
                                                    category='SUSPICIOUS_STRUCTURE',
                                                    severity='medium',
                                                    title='Invalid data offset',
                                                    description=f'Tensor "{tensor_name}" has end < start offset',
                                                    location=tensor_name,
                                                    remediation='File is corrupted or maliciously crafted'
                                                ))

                            except json.JSONDecodeError as e:
                                findings.append(Finding(
                                    rule_id='MG_ST_BAD_HEADER',
                                    category='SUSPICIOUS_STRUCTURE',
                                    severity='medium',
                                    title='Invalid JSON header',
                                    description=f'Header is not valid JSON: {str(e)[:100]}',
                                    remediation='File may be corrupt or not a valid SafeTensors file'
                                ))
                                metadata['valid_json'] = False

                            except UnicodeDecodeError:
                                findings.append(Finding(
                                    rule_id='MG_ST_BAD_ENCODING',
                                    category='SUSPICIOUS_STRUCTURE',
                                    severity='medium',
                                    title='Invalid header encoding',
                                    description='Header is not valid UTF-8',
                                    remediation='File may be corrupt'
                                ))

        except Exception as e:
            findings.append(Finding(
                rule_id='MG_ST_ERROR',
                category='ERROR',
                severity='info',
                title='SafeTensors scan error',
                description=str(e)[:200],
                remediation='File may be corrupt or inaccessible'
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

    parser = argparse.ArgumentParser(description='GuardModel SafeTensors Scanner Agent')
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--output', '-o', default='json', choices=['json', 'text'],
                       help='Output format')
    args = parser.parse_args()

    agent = SafeTensorsAgent()

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
        if 'tensor_count' in result.metadata:
            print(f"Tensors: {result.metadata['tensor_count']}")
        print(f"Findings: {len(result.findings)}")
        for f in result.findings:
            severity_icon = {'critical': '!!', 'high': '!', 'medium': '~', 'low': '-', 'info': ' '}.get(f['severity'], ' ')
            print(f"  [{severity_icon}] [{f['severity'].upper():8s}] {f['title']}")

    sys.exit(0 if result.status == 'clean' else 1)


if __name__ == '__main__':
    main()
