#!/usr/bin/env python3
"""
ONNX Scanner Agent for GuardModel

Detects potential security issues in ONNX model files.
Supports: .onnx

ONNX is generally safer than pickle but can still have issues:
- Custom operators with arbitrary code
- External data files that could be malicious
- Malformed models that exploit parser vulnerabilities
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict, field
import time

# Try to import onnx
try:
    import onnx
    from onnx import checker
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


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
    SUPPORTED_EXTENSIONS = ['.onnx']

    # Known dangerous custom op domains
    DANGEROUS_DOMAINS = [
        'com.microsoft.extensions',  # Some MS extensions can execute code
        'ai.onnx.contrib',  # Contrib ops may be unsafe
        'com.microsoft.nchwc',
        'com.microsoft.mlfeaturizers',
    ]

    # Potentially dangerous op types
    SUSPICIOUS_OP_TYPES = [
        'Loop',  # Can contain subgraphs with complex logic
        'If',    # Conditional execution
        'Scan',  # Iterative execution
        'SequenceMap',  # Map over sequences
    ]

    def __init__(self, rules: Optional[List[Dict]] = None):
        """Initialize the ONNX Agent with optional custom rules."""
        self.rules = rules or []

    def can_scan(self, file_path: str) -> bool:
        """Check if this agent can handle the file."""
        ext = Path(file_path).suffix.lower()
        if ext in self.SUPPORTED_EXTENSIONS:
            return True

        # Check ONNX magic bytes (protobuf)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(2)
                # ONNX starts with protobuf header
                # Field 1 (ir_version), wire type 0 (varint)
                return header[0:1] == b'\x08'
        except (IOError, OSError):
            pass

        return False

    def scan(self, file_path: str, options: Optional[Dict] = None) -> ScanResult:
        """Scan ONNX model file."""
        start_time = time.time()
        options = options or {}
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {}

        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)

        if not ONNX_AVAILABLE:
            findings.append(Finding(
                rule_id='MG_NO_ONNX',
                category='ERROR',
                severity='info',
                title='onnx library not available',
                description='Cannot scan ONNX without onnx library',
                remediation='Install onnx: pip install onnx'
            ))
            return ScanResult(
                file=file_path,
                format='onnx',
                size=file_size,
                sha256=sha256,
                scan_duration=time.time() - start_time,
                status='error',
                findings=[asdict(f) for f in findings],
                metadata={'onnx_available': False}
            )

        try:
            # Load ONNX model
            model = onnx.load(file_path)

            # Run ONNX checker for validation
            try:
                checker.check_model(model)
                metadata['valid'] = True
            except Exception as e:
                findings.append(Finding(
                    rule_id='MG_ONNX_INVALID',
                    category='SUSPICIOUS_STRUCTURE',
                    severity='medium',
                    title='Invalid ONNX model',
                    description=f'Model failed validation: {str(e)[:200]}',
                    remediation='Re-export model from source framework'
                ))
                metadata['valid'] = False

            # Extract metadata
            if model.opset_import:
                metadata['opset_version'] = model.opset_import[0].version
            metadata['ir_version'] = model.ir_version
            metadata['producer_name'] = model.producer_name
            metadata['producer_version'] = model.producer_version
            metadata['domain'] = model.domain

            # Analyze graph
            graph = model.graph
            metadata['num_nodes'] = len(graph.node)
            metadata['num_inputs'] = len(graph.input)
            metadata['num_outputs'] = len(graph.output)

            # Check for custom operators
            for node in graph.node:
                domain = node.domain or 'ai.onnx'

                if domain in self.DANGEROUS_DOMAINS:
                    findings.append(Finding(
                        rule_id='MG_ONNX_DANGEROUS_DOMAIN',
                        category='DANGEROUS_IMPORT',
                        severity='medium',
                        title=f'Custom operator from {domain}',
                        description=f'Op: {node.op_type}, Domain: {domain}',
                        location=node.name or 'unnamed',
                        remediation='Review custom operator implementation'
                    ))

                # Check for non-standard domains
                if domain not in ['', 'ai.onnx', 'ai.onnx.ml']:
                    findings.append(Finding(
                        rule_id='MG_ONNX_CUSTOM_OP',
                        category='SUSPICIOUS_STRUCTURE',
                        severity='low',
                        title=f'Non-standard operator domain',
                        description=f'Op: {node.op_type}, Domain: {domain}',
                        location=node.name or 'unnamed',
                        remediation='Verify custom operator is from trusted source'
                    ))

                # Check for potentially dangerous op types
                if node.op_type in self.SUSPICIOUS_OP_TYPES:
                    findings.append(Finding(
                        rule_id='MG_ONNX_CONTROL_FLOW',
                        category='SUSPICIOUS_STRUCTURE',
                        severity='low',
                        title=f'Control flow operator: {node.op_type}',
                        description=f'Model uses {node.op_type} which can contain subgraphs',
                        location=node.name or 'unnamed',
                        remediation='Review subgraph for unexpected operations'
                    ))

                    # Check for subgraphs
                    for attr in node.attribute:
                        if attr.type == onnx.AttributeProto.GRAPH:
                            findings.append(Finding(
                                rule_id='MG_ONNX_SUBGRAPH',
                                category='SUSPICIOUS_STRUCTURE',
                                severity='low',
                                title='Model contains subgraph',
                                description=f'Subgraph in {node.op_type} node: {attr.name}',
                                location=node.name or 'unnamed',
                                remediation='Review subgraph for malicious operations'
                            ))

            # Check for external data references
            for initializer in graph.initializer:
                if initializer.HasField('data_location'):
                    if initializer.data_location == onnx.TensorProto.EXTERNAL:
                        findings.append(Finding(
                            rule_id='MG_ONNX_EXTERNAL_DATA',
                            category='FILE_SYSTEM',
                            severity='medium',
                            title='External data reference',
                            description=f'Tensor "{initializer.name}" uses external data',
                            location=initializer.name,
                            remediation='Verify external data file is safe and from trusted source'
                        ))

            # Check metadata props for external references
            for prop in model.metadata_props:
                if 'external' in prop.key.lower() or 'path' in prop.key.lower():
                    findings.append(Finding(
                        rule_id='MG_ONNX_EXTERNAL_REF',
                        category='FILE_SYSTEM',
                        severity='medium',
                        title='External path in metadata',
                        description=f'Metadata key "{prop.key}" may reference external file',
                        location=f'metadata.{prop.key}',
                        remediation='Verify referenced path is safe'
                    ))

            # Check for extremely large models (potential DoS)
            if len(graph.node) > 100000:
                findings.append(Finding(
                    rule_id='MG_ONNX_LARGE_MODEL',
                    category='SUSPICIOUS_STRUCTURE',
                    severity='low',
                    title='Extremely large model',
                    description=f'Model has {len(graph.node)} nodes',
                    remediation='Verify model size is expected'
                ))

            # Check for functions (ONNX 1.11+)
            if hasattr(model, 'functions') and model.functions:
                for func in model.functions:
                    findings.append(Finding(
                        rule_id='MG_ONNX_FUNCTION',
                        category='SUSPICIOUS_STRUCTURE',
                        severity='low',
                        title='ONNX function definition',
                        description=f'Model defines function: {func.name}',
                        location=func.name,
                        remediation='Review function definition'
                    ))

        except Exception as e:
            findings.append(Finding(
                rule_id='MG_ONNX_ERROR',
                category='ERROR',
                severity='info',
                title='ONNX scan error',
                description=str(e)[:200],
                remediation='File may be corrupt or invalid ONNX'
            ))

        status = self._determine_status(findings)
        scan_duration = time.time() - start_time
        metadata['onnx_available'] = True

        return ScanResult(
            file=file_path,
            format='onnx',
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

    parser = argparse.ArgumentParser(description='GuardModel ONNX Scanner Agent')
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--output', '-o', default='json', choices=['json', 'text'],
                       help='Output format')
    args = parser.parse_args()

    agent = ONNXAgent()

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
