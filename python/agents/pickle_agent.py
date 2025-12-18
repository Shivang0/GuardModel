#!/usr/bin/env python3
"""
Pickle Scanner Agent for GuardModel

Detects malicious payloads in pickle-based ML model files.
Supports: .pkl, .pickle, .pt, .pth, .bin, .joblib

This is the CRITICAL scanner - handles 80%+ of ML model security threats.
"""

import os
import sys
import json
import hashlib
import tempfile
import zipfile
import pickletools
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
import time
import struct

# Try to import fickling for advanced analysis
try:
    from fickling.fickle import Pickled
    from fickling.analysis import check_safety
    FICKLING_AVAILABLE = True
except ImportError:
    FICKLING_AVAILABLE = False


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


class PickleAgent:
    """
    Pickle Scanner Agent

    Detects malicious payloads in pickle-based ML model files.
    Uses pickletools for opcode analysis and fickling for AST analysis.
    """

    NAME = "pickle_agent"
    VERSION = "1.0.0"
    SUPPORTED_EXTENSIONS = ['.pkl', '.pickle', '.pt', '.pth', '.bin', '.joblib']

    # Comprehensive dangerous patterns with severity and context
    # Based on skills.md detection rules
    DANGEROUS_PATTERNS: Dict[str, Tuple[str, str, str]] = {
        # Critical: Direct code execution (MG001-MG015)
        'os.system': ('critical', 'CODE_EXECUTION', 'System shell command execution'),
        'os.popen': ('critical', 'CODE_EXECUTION', 'Piped command execution'),
        'os.popen2': ('critical', 'CODE_EXECUTION', 'Piped command execution'),
        'os.popen3': ('critical', 'CODE_EXECUTION', 'Piped command execution'),
        'os.popen4': ('critical', 'CODE_EXECUTION', 'Piped command execution'),
        'posix.system': ('critical', 'CODE_EXECUTION', 'POSIX system command execution'),
        'subprocess.call': ('critical', 'CODE_EXECUTION', 'Subprocess execution'),
        'subprocess.Popen': ('critical', 'CODE_EXECUTION', 'Subprocess with full control'),
        'subprocess.run': ('critical', 'CODE_EXECUTION', 'Modern subprocess execution'),
        'subprocess.check_output': ('critical', 'CODE_EXECUTION', 'Subprocess with output capture'),
        'subprocess.check_call': ('critical', 'CODE_EXECUTION', 'Subprocess execution'),
        'subprocess.getoutput': ('critical', 'CODE_EXECUTION', 'Subprocess output'),
        'subprocess.getstatusoutput': ('critical', 'CODE_EXECUTION', 'Subprocess with status'),
        'builtins.eval': ('critical', 'CODE_EXECUTION', 'Arbitrary Python evaluation'),
        'builtins.exec': ('critical', 'CODE_EXECUTION', 'Arbitrary Python execution'),
        'builtins.compile': ('critical', 'CODE_EXECUTION', 'Dynamic code compilation'),
        '__builtin__.eval': ('critical', 'CODE_EXECUTION', 'Arbitrary Python evaluation'),
        '__builtin__.exec': ('critical', 'CODE_EXECUTION', 'Arbitrary Python execution'),
        'commands.getoutput': ('critical', 'CODE_EXECUTION', 'Legacy shell execution'),
        'commands.getstatusoutput': ('critical', 'CODE_EXECUTION', 'Legacy shell execution'),
        'pty.spawn': ('critical', 'CODE_EXECUTION', 'PTY spawn (interactive shell)'),
        'os.execv': ('critical', 'CODE_EXECUTION', 'Process replacement'),
        'os.execve': ('critical', 'CODE_EXECUTION', 'Process replacement with env'),
        'os.execvp': ('critical', 'CODE_EXECUTION', 'Process replacement with PATH'),
        'os.execl': ('critical', 'CODE_EXECUTION', 'Process replacement'),
        'os.execle': ('critical', 'CODE_EXECUTION', 'Process replacement'),
        'os.execlp': ('critical', 'CODE_EXECUTION', 'Process replacement'),
        'os.spawnl': ('critical', 'CODE_EXECUTION', 'Process spawning'),
        'os.spawnle': ('critical', 'CODE_EXECUTION', 'Process spawning'),
        'os.spawnlp': ('critical', 'CODE_EXECUTION', 'Process spawning'),
        'os.spawnv': ('critical', 'CODE_EXECUTION', 'Process spawning'),
        'os.spawnve': ('critical', 'CODE_EXECUTION', 'Process spawning'),
        'os.spawnvp': ('critical', 'CODE_EXECUTION', 'Process spawning'),

        # Critical: Reverse shells (MG020-MG021)
        'socket.socket': ('critical', 'REVERSE_SHELL', 'Raw socket creation'),
        'socket.create_connection': ('critical', 'REVERSE_SHELL', 'Outbound TCP connection'),
        '_socket.socket': ('critical', 'REVERSE_SHELL', 'Raw socket creation'),

        # High: Network operations (MG022-MG030)
        'urllib.request.urlopen': ('high', 'NETWORK', 'URL request capability'),
        'urllib.request.urlretrieve': ('high', 'NETWORK', 'File download capability'),
        'urllib.urlopen': ('high', 'NETWORK', 'URL request capability'),
        'urllib2.urlopen': ('high', 'NETWORK', 'URL request capability'),
        'requests.get': ('high', 'NETWORK', 'HTTP GET request'),
        'requests.post': ('high', 'NETWORK', 'HTTP POST request'),
        'requests.put': ('high', 'NETWORK', 'HTTP PUT request'),
        'requests.delete': ('high', 'NETWORK', 'HTTP DELETE request'),
        'requests.request': ('high', 'NETWORK', 'HTTP request'),
        'http.client.HTTPConnection': ('high', 'NETWORK', 'HTTP connection'),
        'http.client.HTTPSConnection': ('high', 'NETWORK', 'HTTPS connection'),
        'httplib.HTTPConnection': ('high', 'NETWORK', 'HTTP connection'),
        'httplib.HTTPSConnection': ('high', 'NETWORK', 'HTTPS connection'),
        'ftplib.FTP': ('high', 'NETWORK', 'FTP connection'),
        'smtplib.SMTP': ('high', 'NETWORK', 'Email sending'),
        'telnetlib.Telnet': ('critical', 'NETWORK', 'Telnet connection'),
        'paramiko.SSHClient': ('critical', 'NETWORK', 'SSH connection'),

        # High: File system operations (MG040-MG053)
        'os.remove': ('high', 'FILE_SYSTEM', 'File deletion'),
        'os.unlink': ('high', 'FILE_SYSTEM', 'File deletion'),
        'os.rmdir': ('high', 'FILE_SYSTEM', 'Directory deletion'),
        'shutil.rmtree': ('critical', 'FILE_SYSTEM', 'Recursive directory deletion'),
        'os.rename': ('high', 'FILE_SYSTEM', 'File rename/move'),
        'shutil.move': ('high', 'FILE_SYSTEM', 'File move'),
        'os.chmod': ('high', 'FILE_SYSTEM', 'Permission modification'),
        'os.chown': ('high', 'FILE_SYSTEM', 'Ownership modification'),
        'os.chroot': ('critical', 'FILE_SYSTEM', 'Chroot jail escape'),

        # High: Dangerous imports (MG060-MG069)
        'importlib.import_module': ('high', 'DANGEROUS_IMPORT', 'Dynamic module import'),
        'importlib.__import__': ('high', 'DANGEROUS_IMPORT', 'Dynamic import'),
        '__import__': ('high', 'DANGEROUS_IMPORT', 'Built-in import function'),
        'builtins.__import__': ('high', 'DANGEROUS_IMPORT', 'Built-in import'),
        'imp.load_module': ('high', 'DANGEROUS_IMPORT', 'Legacy module loading'),
        'imp.load_source': ('high', 'DANGEROUS_IMPORT', 'Legacy source loading'),
        'imp.load_compiled': ('high', 'DANGEROUS_IMPORT', 'Legacy compiled loading'),
        'runpy.run_module': ('high', 'DANGEROUS_IMPORT', 'Module execution'),
        'runpy.run_path': ('high', 'DANGEROUS_IMPORT', 'Path execution'),
        'runpy._run_code': ('high', 'DANGEROUS_IMPORT', 'Code execution'),

        # High: Native code loading
        'ctypes.CDLL': ('high', 'DANGEROUS_IMPORT', 'C library loading'),
        'ctypes.cdll': ('high', 'DANGEROUS_IMPORT', 'C library loading'),
        'ctypes.windll': ('high', 'DANGEROUS_IMPORT', 'Windows DLL loading'),
        'ctypes.oledll': ('high', 'DANGEROUS_IMPORT', 'Windows OLE DLL loading'),
        'ctypes.pydll': ('high', 'DANGEROUS_IMPORT', 'Python DLL loading'),
        'ctypes.LibraryLoader': ('high', 'DANGEROUS_IMPORT', 'Library loader'),
        'cffi.FFI': ('high', 'DANGEROUS_IMPORT', 'Foreign function interface'),

        # High: Obfuscation (MG080-MG089)
        'marshal.loads': ('high', 'OBFUSCATION', 'Marshal deserialization (code execution)'),
        'marshal.load': ('high', 'OBFUSCATION', 'Marshal deserialization'),

        # Medium: Potential obfuscation
        'base64.b64decode': ('medium', 'OBFUSCATION', 'Base64 decoding (potential obfuscation)'),
        'base64.decodebytes': ('medium', 'OBFUSCATION', 'Base64 decoding'),
        'codecs.decode': ('medium', 'OBFUSCATION', 'Codec decoding'),
        'zlib.decompress': ('medium', 'OBFUSCATION', 'Zlib decompression'),
        'gzip.decompress': ('medium', 'OBFUSCATION', 'Gzip decompression'),
        'bz2.decompress': ('medium', 'OBFUSCATION', 'Bzip2 decompression'),
        'lzma.decompress': ('medium', 'OBFUSCATION', 'LZMA decompression'),
        'binascii.unhexlify': ('medium', 'OBFUSCATION', 'Hex decoding'),
        'binascii.a2b_hex': ('medium', 'OBFUSCATION', 'Hex decoding'),
        'binascii.a2b_base64': ('medium', 'OBFUSCATION', 'Base64 decoding'),

        # Medium: File operations
        'builtins.open': ('medium', 'FILE_SYSTEM', 'File open operation'),
        'io.open': ('medium', 'FILE_SYSTEM', 'File open operation'),
        'io.FileIO': ('medium', 'FILE_SYSTEM', 'File I/O'),
        'os.open': ('medium', 'FILE_SYSTEM', 'Low-level file open'),
        'os.fdopen': ('medium', 'FILE_SYSTEM', 'File descriptor open'),
        'os.makedirs': ('medium', 'FILE_SYSTEM', 'Directory creation'),
        'os.mkdir': ('medium', 'FILE_SYSTEM', 'Directory creation'),
        'shutil.copy': ('medium', 'FILE_SYSTEM', 'File copy'),
        'shutil.copy2': ('medium', 'FILE_SYSTEM', 'File copy with metadata'),
        'shutil.copytree': ('medium', 'FILE_SYSTEM', 'Directory copy'),
        'pathlib.Path.write_text': ('medium', 'FILE_SYSTEM', 'File write'),
        'pathlib.Path.write_bytes': ('medium', 'FILE_SYSTEM', 'File write'),
        'pathlib.Path.unlink': ('high', 'FILE_SYSTEM', 'File deletion'),

        # Medium: Pickle within pickle
        'pickle.loads': ('high', 'OBFUSCATION', 'Nested pickle (may bypass scanners)'),
        'pickle.load': ('high', 'OBFUSCATION', 'Nested pickle'),
        '_pickle.loads': ('high', 'OBFUSCATION', 'Nested pickle'),
        'cPickle.loads': ('high', 'OBFUSCATION', 'Nested pickle'),

        # Low: Potentially suspicious
        'builtins.getattr': ('low', 'SUSPICIOUS_STRUCTURE', 'Dynamic attribute access'),
        'builtins.setattr': ('low', 'SUSPICIOUS_STRUCTURE', 'Dynamic attribute setting'),
        'builtins.delattr': ('low', 'SUSPICIOUS_STRUCTURE', 'Dynamic attribute deletion'),
        'builtins.globals': ('low', 'SUSPICIOUS_STRUCTURE', 'Globals access'),
        'builtins.locals': ('low', 'SUSPICIOUS_STRUCTURE', 'Locals access'),
        'builtins.vars': ('low', 'SUSPICIOUS_STRUCTURE', 'Vars access'),

        # Info: __reduce__ related (often legitimate but worth noting)
        'copy_reg._reconstructor': ('info', 'SUSPICIOUS_STRUCTURE', 'Object reconstruction'),
        'copyreg._reconstructor': ('info', 'SUSPICIOUS_STRUCTURE', 'Object reconstruction'),
    }

    def __init__(self, rules: Optional[List[Dict]] = None):
        """Initialize the Pickle Agent with optional custom rules."""
        self.rules = rules or []
        self.custom_patterns = self._load_custom_patterns()

    def _load_custom_patterns(self) -> Dict[str, Tuple[str, str, str]]:
        """Load custom patterns from rules config."""
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
        """Check if this agent can handle the file."""
        ext = Path(file_path).suffix.lower()
        if ext in self.SUPPORTED_EXTENSIONS:
            return True

        # Also check magic bytes for extensionless files
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                # Check pickle protocols 2-5
                if header[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'):
                    return True
                # Check PyTorch ZIP format
                if header == b'PK\x03\x04':
                    return True
                # Check legacy pickle (protocol 0/1)
                if header[0:1] in (b'(', b']', b'}', b'c', b'l', b'd'):
                    return True
        except (IOError, OSError):
            pass

        return False

    def scan(self, file_path: str, options: Optional[Dict] = None) -> ScanResult:
        """
        Perform comprehensive pickle security scan.

        1. Calculate file hash
        2. Detect format (raw pickle or PyTorch ZIP)
        3. Extract and analyze pickle content
        4. Run fickling analysis if available
        5. Pattern match against dangerous functions
        6. Return consolidated findings
        """
        start_time = time.time()
        options = options or {}
        findings: List[Finding] = []
        metadata: Dict[str, Any] = {}

        # Calculate SHA256
        sha256 = self._calculate_hash(file_path)
        file_size = os.path.getsize(file_path)

        # Detect format
        detected_format = self._detect_format(file_path)
        metadata['detected_format'] = detected_format
        metadata['fickling_available'] = FICKLING_AVAILABLE

        try:
            # Handle PyTorch ZIP format
            if detected_format == 'pytorch_zip':
                findings.extend(self._scan_pytorch_zip(file_path))
            else:
                findings.extend(self._scan_raw_pickle(file_path))

            # Run fickling analysis if available
            if FICKLING_AVAILABLE:
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

        # Deduplicate findings
        findings = self._deduplicate_findings(findings)

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
        """Calculate SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _detect_format(self, file_path: str) -> str:
        """Detect pickle format from magic bytes."""
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
        """Scan PyTorch ZIP format (contains pickled data)."""
        findings: List[Finding] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    # List contents
                    members = zf.namelist()

                    # Look for pickle files inside
                    pickle_members = [m for m in members if
                                     m.endswith('.pkl') or
                                     m.endswith('.pickle') or
                                     'data.pkl' in m or
                                     m.startswith('archive/data') or
                                     '/data/' in m]

                    if not pickle_members:
                        # Sometimes PyTorch just has data files without .pkl extension
                        pickle_members = [m for m in members if
                                         not m.endswith('/') and
                                         not m.endswith('.py') and
                                         not m.endswith('.json')]

                    for member in pickle_members:
                        try:
                            extracted_path = zf.extract(member, tmpdir)
                            # Check if it's actually a pickle
                            with open(extracted_path, 'rb') as f:
                                header = f.read(2)
                                if header in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05') or \
                                   header[0:1] in (b'(', b']', b'}', b'c'):
                                    member_findings = self._scan_raw_pickle(extracted_path)
                                    # Update location to show nested path
                                    for f in member_findings:
                                        f.location = f'{file_path}!{member}' + (f' ({f.location})' if f.location else '')
                                    findings.extend(member_findings)
                        except Exception as e:
                            # Skip files that can't be extracted
                            continue

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
        """Scan raw pickle file for dangerous patterns."""
        findings: List[Finding] = []

        try:
            with open(file_path, 'rb') as f:
                pickle_data = f.read()

            # Analyze with pickletools
            try:
                opcodes = list(pickletools.genops(pickle_data))
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

            # Track stack for STACK_GLOBAL analysis (Python 3.4+)
            # STACK_GLOBAL pops module and name from stack (pushed by SHORT_BINUNICODE, BINUNICODE, etc.)
            string_stack: List[str] = []
            # Track memo for BINGET/MEMOIZE operations
            memo: Dict[int, str] = {}
            memo_counter = 0

            for opcode, arg, pos in opcodes:
                # Track string values pushed onto the stack
                if opcode.name in ('SHORT_BINUNICODE', 'BINUNICODE', 'UNICODE', 'SHORT_BINSTRING', 'BINSTRING', 'STRING'):
                    if isinstance(arg, bytes):
                        string_stack.append(arg.decode('utf-8', errors='replace'))
                    elif isinstance(arg, str):
                        string_stack.append(arg)

                # Track MEMOIZE - stores top of stack in memo (doesn't pop)
                elif opcode.name == 'MEMOIZE':
                    if string_stack:
                        memo[memo_counter] = string_stack[-1]
                    memo_counter += 1

                # Track PUT/BINPUT - stores top of stack in memo at specified index
                elif opcode.name in ('PUT', 'BINPUT', 'LONG_BINPUT'):
                    if string_stack and arg is not None:
                        memo[int(arg)] = string_stack[-1]

                # Track GET/BINGET - retrieves value from memo and pushes to stack
                elif opcode.name in ('GET', 'BINGET', 'LONG_BINGET'):
                    if arg is not None and int(arg) in memo:
                        string_stack.append(memo[int(arg)])

                # Check GLOBAL opcode (imports) - older pickle protocols
                elif opcode.name == 'GLOBAL':
                    module_func = self._normalize_global(arg)

                    # Check against dangerous patterns
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

                    # Check for partial matches (module-level)
                    findings.extend(self._check_partial_matches(module_func, pos))

                # Check STACK_GLOBAL opcode (Python 3.4+)
                # STACK_GLOBAL pops the top two stack items: module_name, func_name
                elif opcode.name == 'STACK_GLOBAL':
                    module_func = None
                    if len(string_stack) >= 2:
                        # Pop module and function from stack (in order: module, then function)
                        func_name = string_stack.pop()
                        module_name = string_stack.pop()
                        module_func = f'{module_name}.{func_name}'

                        # Check against dangerous patterns
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

                        # Check for partial matches (module-level)
                        findings.extend(self._check_partial_matches(module_func, pos))
                    else:
                        # Could not reconstruct the callable - flag for review
                        findings.append(Finding(
                            rule_id='MG_STACK_GLOBAL',
                            category='SUSPICIOUS_STRUCTURE',
                            severity='medium',
                            title='Dynamic Global Import',
                            description='Uses STACK_GLOBAL opcode but could not reconstruct callable name',
                            location=f'Byte offset: {pos}',
                            remediation='Manual review recommended'
                        ))

                # Clear stack on certain opcodes that consume values
                elif opcode.name in ('REDUCE', 'TUPLE', 'TUPLE1', 'TUPLE2', 'TUPLE3', 'LIST', 'DICT', 'SETITEM', 'APPEND', 'BUILD'):
                    # These opcodes consume stack values - be conservative and clear our tracking
                    # For more precise tracking, would need full pickle VM simulation
                    pass

                # Check for REDUCE with suspicious patterns
                elif opcode.name == 'REDUCE':
                    # REDUCE executes a callable - this is where code runs
                    # The callable should have been loaded via GLOBAL
                    pass

                # Check for BUILD opcode with __setstate__
                elif opcode.name == 'BUILD':
                    # BUILD can trigger __setstate__ which may execute code
                    pass

        except Exception as e:
            findings.append(Finding(
                rule_id='MG_SCAN_ERROR',
                category='ERROR',
                severity='info',
                title='Scan Error',
                description=f'Error during pickle scan: {str(e)}',
                remediation='File may be corrupt'
            ))

        return findings

    def _normalize_global(self, arg: Any) -> str:
        """Normalize GLOBAL opcode argument to module.function format."""
        if isinstance(arg, str):
            # Already in module.function format
            return arg
        elif isinstance(arg, tuple) and len(arg) == 2:
            # (module, function) tuple
            return f"{arg[0]}.{arg[1]}"
        elif isinstance(arg, bytes):
            return arg.decode('utf-8', errors='replace')
        else:
            return str(arg)

    def _check_partial_matches(self, module_func: str, pos: int) -> List[Finding]:
        """Check for partial pattern matches at module level."""
        findings = []

        # Suspicious module prefixes
        suspicious_modules = {
            'os.': ('medium', 'FILE_SYSTEM', 'OS module access'),
            'subprocess.': ('high', 'CODE_EXECUTION', 'Subprocess module'),
            'socket.': ('high', 'NETWORK', 'Socket module'),
            'ctypes.': ('high', 'DANGEROUS_IMPORT', 'Ctypes module'),
            'multiprocessing.': ('medium', 'CODE_EXECUTION', 'Multiprocessing module'),
        }

        for prefix, (severity, category, desc) in suspicious_modules.items():
            if module_func.startswith(prefix) and module_func not in self.DANGEROUS_PATTERNS:
                findings.append(Finding(
                    rule_id=f'MG_{category}_PARTIAL',
                    category=category,
                    severity=severity,
                    title=f'Suspicious Module: {module_func}',
                    description=desc,
                    pattern=module_func,
                    location=f'Byte offset: {pos}',
                    remediation='Review this import manually'
                ))
                break

        return findings

    def _run_fickling(self, file_path: str) -> List[Finding]:
        """Run fickling security analysis."""
        findings: List[Finding] = []

        if not FICKLING_AVAILABLE:
            return findings

        try:
            with open(file_path, 'rb') as f:
                pickle_data = f.read()

            # Use fickling to check safety
            result = check_safety(pickle_data)

            if not result.is_likely_safe:
                for warning in (result.warnings or []):
                    severity = 'high'
                    category = 'CODE_EXECUTION'

                    warning_lower = str(warning).lower()

                    if 'eval' in warning_lower or 'exec' in warning_lower:
                        severity = 'critical'
                    elif 'import' in warning_lower:
                        severity = 'high'
                        category = 'DANGEROUS_IMPORT'
                    elif 'network' in warning_lower or 'socket' in warning_lower:
                        severity = 'critical'
                        category = 'REVERSE_SHELL'
                    elif 'file' in warning_lower or 'open' in warning_lower:
                        severity = 'medium'
                        category = 'FILE_SYSTEM'

                    findings.append(Finding(
                        rule_id='MG_FICKLING',
                        category=category,
                        severity=severity,
                        title='Fickling Security Warning',
                        description=str(warning),
                        remediation='Do not load this file without manual review',
                        references=['https://github.com/trailofbits/fickling']
                    ))

        except Exception as e:
            # Fickling may fail on some files - that's okay
            pass

        return findings

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on rule_id and pattern."""
        seen = set()
        unique = []

        for f in findings:
            key = (f.rule_id, f.pattern, f.location)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

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

    parser = argparse.ArgumentParser(description='GuardModel Pickle Scanner Agent')
    parser.add_argument('file', help='File to scan')
    parser.add_argument('--output', '-o', default='json', choices=['json', 'text'],
                       help='Output format')
    args = parser.parse_args()

    agent = PickleAgent()

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
            if f.get('pattern'):
                print(f"      Pattern: {f['pattern']}")

    sys.exit(0 if result.status == 'clean' else 1)


if __name__ == '__main__':
    main()
