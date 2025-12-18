#!/usr/bin/env python3
"""
Unit tests for Pickle Scanner Agent
"""

import os
import sys
import pickle
import tempfile
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from agents.pickle_agent import PickleAgent, Finding, ScanResult


class TestPickleAgent:
    """Test cases for PickleAgent."""

    def setup_method(self):
        """Set up test fixtures."""
        self.agent = PickleAgent()

    def test_can_scan_pkl(self):
        """Test that agent can scan .pkl files."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            pickle.dump({'test': 'data'}, f)
            f.flush()
            assert self.agent.can_scan(f.name)
            os.unlink(f.name)

    def test_can_scan_pt(self):
        """Test that agent can scan .pt files."""
        with tempfile.NamedTemporaryFile(suffix='.pt', delete=False) as f:
            pickle.dump({'test': 'data'}, f)
            f.flush()
            assert self.agent.can_scan(f.name)
            os.unlink(f.name)

    def test_cannot_scan_txt(self):
        """Test that agent rejects .txt files."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'hello world')
            f.flush()
            assert not self.agent.can_scan(f.name)
            os.unlink(f.name)

    def test_clean_pickle(self):
        """Test scanning a clean pickle file."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create safe pickle with simple data
            data = {
                'weights': [1.0, 2.0, 3.0],
                'bias': 0.5,
                'name': 'test_model',
            }
            pickle.dump(data, f)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status == 'clean'
            assert len(result.findings) == 0
            assert result.sha256  # Should have hash
            assert result.format in ('pickle_v4', 'pickle_v5', 'pickle_v3', 'pickle_v2')

            os.unlink(f.name)

    def test_malicious_os_system(self):
        """Test detection of os.system in pickle."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create malicious pickle with os.system
            class Malicious:
                def __reduce__(self):
                    return (os.system, ('echo pwned',))

            pickle.dump(Malicious(), f)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')
            assert len(result.findings) > 0

            # Check for code execution finding
            categories = [finding['category'] for finding in result.findings]
            assert 'CODE_EXECUTION' in categories

            os.unlink(f.name)

    def test_malicious_eval(self):
        """Test detection of eval in pickle."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create malicious pickle with eval
            class Malicious:
                def __reduce__(self):
                    return (eval, ('print("pwned")',))

            pickle.dump(Malicious(), f)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')
            assert len(result.findings) > 0

            os.unlink(f.name)

    def test_network_socket(self):
        """Test detection of socket creation."""
        import socket as socket_module

        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create pickle with socket
            class Malicious:
                def __reduce__(self):
                    return (socket_module.socket, ())

            pickle.dump(Malicious(), f)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')

            # Check for network or reverse shell category
            categories = [finding['category'] for finding in result.findings]
            assert 'REVERSE_SHELL' in categories or 'NETWORK' in categories

            os.unlink(f.name)

    def test_file_deletion(self):
        """Test detection of os.remove."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create pickle with file deletion
            class Malicious:
                def __reduce__(self):
                    return (os.remove, ('/tmp/test',))

            pickle.dump(Malicious(), f)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')

            categories = [finding['category'] for finding in result.findings]
            assert 'FILE_SYSTEM' in categories

            os.unlink(f.name)

    def test_hash_calculation(self):
        """Test that SHA256 hash is calculated correctly."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            data = {'test': 'data'}
            pickle.dump(data, f)
            f.flush()

            result = self.agent.scan(f.name)

            # Hash should be 64 hex characters
            assert len(result.sha256) == 64
            assert all(c in '0123456789abcdef' for c in result.sha256)

            os.unlink(f.name)

    def test_scan_duration(self):
        """Test that scan duration is recorded."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            pickle.dump({'test': 'data'}, f)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.scan_duration > 0
            assert result.scan_duration < 60  # Should be fast

            os.unlink(f.name)

    def test_corrupt_file(self):
        """Test handling of corrupt pickle file."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Write invalid pickle data
            f.write(b'\x80\x04garbage data that is not valid pickle')
            f.flush()

            result = self.agent.scan(f.name)

            # Should handle gracefully
            assert result.status in ('clean', 'error', 'suspicious')

            os.unlink(f.name)

    def test_empty_file(self):
        """Test handling of empty file."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.flush()  # Empty file

            result = self.agent.scan(f.name)

            # Should handle gracefully
            assert result.status in ('clean', 'error', 'suspicious')

            os.unlink(f.name)


class TestSaferPickleFeatures:
    """Test cases for SaferPickle integration features."""

    def setup_method(self):
        """Set up test fixtures."""
        self.agent = PickleAgent()

    def test_disguised_elf_detection(self):
        """Test detection of ELF executable disguised as pickle."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Write ELF magic bytes
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status == 'malicious'
            assert result.metadata['disguised_file_type'] == 'ELF executable'
            assert len(result.findings) > 0
            assert any(f['rule_id'] == 'MG_DISGUISED_FILE' for f in result.findings)

            os.unlink(f.name)

    def test_disguised_pe_detection(self):
        """Test detection of Windows PE executable disguised as pickle."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Write MZ (PE) magic bytes
            f.write(b'MZ' + b'\x00' * 100)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status == 'malicious'
            assert result.metadata['disguised_file_type'] == 'Windows PE executable'

            os.unlink(f.name)

    def test_disguised_png_detection(self):
        """Test detection of PNG image disguised as pickle."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Write PNG magic bytes
            f.write(b'\x89PNG\r\n\x1a\n' + b'\x00' * 100)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.metadata['disguised_file_type'] == 'PNG image'
            # PNG should be medium severity, not immediately malicious
            assert any(f['severity'] == 'medium' for f in result.findings)

            os.unlink(f.name)

    def test_safe_pattern_numpy(self):
        """Test that numpy patterns are recognized as safe."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create pickle with STACK_GLOBAL for numpy.core.multiarray._reconstruct
            pickle_data = b'\x80\x04'
            pickle_data += b'\x8c\x11numpy.core.multiarray'  # SHORT_BINUNICODE
            pickle_data += b'\x94'  # MEMOIZE
            pickle_data += b'\x8c\x0c_reconstruct'  # SHORT_BINUNICODE
            pickle_data += b'\x94'  # MEMOIZE
            pickle_data += b'\x93'  # STACK_GLOBAL
            pickle_data += b'.'  # STOP
            f.write(pickle_data)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status == 'clean'
            assert result.metadata['safe_count'] >= 1
            assert result.metadata['unsafe_count'] == 0
            assert len(result.findings) == 0

            os.unlink(f.name)

    def test_pattern_counts_metadata(self):
        """Test that pattern counts are tracked in metadata."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create malicious pickle with os.system
            class Malicious:
                def __reduce__(self):
                    return (os.system, ('echo pwned',))

            pickle.dump(Malicious(), f)
            f.flush()

            result = self.agent.scan(f.name)

            # Check metadata includes pattern counts
            assert 'safe_count' in result.metadata
            assert 'unsafe_count' in result.metadata
            assert 'suspicious_count' in result.metadata
            assert 'unknown_count' in result.metadata
            assert result.metadata['unsafe_count'] >= 1

            os.unlink(f.name)

    def test_risk_score_metadata(self):
        """Test that risk score is calculated and included."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            class Malicious:
                def __reduce__(self):
                    return (os.system, ('whoami',))

            pickle.dump(Malicious(), f)
            f.flush()

            result = self.agent.scan(f.name)

            assert 'risk_score' in result.metadata
            assert isinstance(result.metadata['risk_score'], float)
            assert result.metadata['risk_score'] >= 0

            os.unlink(f.name)

    def test_new_pattern_types_codetype(self):
        """Test detection of types.CodeType (from SaferPickle)."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create pickle with STACK_GLOBAL for types.CodeType
            pickle_data = b'\x80\x04'
            pickle_data += b'\x8c\x05types'  # SHORT_BINUNICODE 'types'
            pickle_data += b'\x94'  # MEMOIZE
            pickle_data += b'\x8c\x08CodeType'  # SHORT_BINUNICODE 'CodeType'
            pickle_data += b'\x94'  # MEMOIZE
            pickle_data += b'\x93'  # STACK_GLOBAL
            pickle_data += b'.'  # STOP
            f.write(pickle_data)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')
            assert any('types.CodeType' in f.get('pattern', '') for f in result.findings)

            os.unlink(f.name)

    def test_new_pattern_types_functiontype(self):
        """Test detection of types.FunctionType (from SaferPickle)."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create pickle with STACK_GLOBAL for types.FunctionType
            pickle_data = b'\x80\x04'
            pickle_data += b'\x8c\x05types'  # SHORT_BINUNICODE 'types'
            pickle_data += b'\x94'  # MEMOIZE
            pickle_data += b'\x8c\x0cFunctionType'  # SHORT_BINUNICODE 'FunctionType'
            pickle_data += b'\x94'  # MEMOIZE
            pickle_data += b'\x93'  # STACK_GLOBAL
            pickle_data += b'.'  # STOP
            f.write(pickle_data)
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')
            assert any('types.FunctionType' in f.get('pattern', '') for f in result.findings)

            os.unlink(f.name)

    def test_classify_pattern_method(self):
        """Test the _classify_pattern method."""
        # Test safe pattern
        classification, severity, category, desc = self.agent._classify_pattern('numpy.ndarray')
        assert classification == 'safe'

        # Test unsafe pattern
        classification, severity, category, desc = self.agent._classify_pattern('os.system')
        assert classification == 'unsafe'
        assert severity == 'critical'

        # Test suspicious pattern
        classification, severity, category, desc = self.agent._classify_pattern('__subclasses__')
        assert classification == 'suspicious'

        # Test unknown pattern
        classification, severity, category, desc = self.agent._classify_pattern('some.random.module')
        assert classification == 'unknown'

    def test_calculate_risk_score(self):
        """Test the _calculate_risk_score method."""
        # No patterns - clean
        level, score = self.agent._calculate_risk_score(0, 0, 0, 0)
        assert level == 'clean'

        # Unsafe patterns - malicious
        level, score = self.agent._calculate_risk_score(0, 1, 0, 0)
        assert level == 'malicious'

        # Safe patterns only - clean
        level, score = self.agent._calculate_risk_score(5, 0, 0, 0)
        assert level == 'clean'

        # Suspicious patterns - suspicious
        level, score = self.agent._calculate_risk_score(0, 0, 1, 0)
        assert level == 'suspicious'

        # Many unsafe, some safe - malicious
        level, score = self.agent._calculate_risk_score(2, 5, 0, 0)
        assert level == 'malicious'


class TestPickleAgentCLI:
    """Test CLI interface of PickleAgent."""

    def test_cli_json_output(self):
        """Test JSON output from CLI."""
        import json
        import subprocess

        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            pickle.dump({'test': 'data'}, f)
            f.flush()

            agent_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'python', 'agents', 'pickle_agent.py'
            )

            result = subprocess.run(
                ['python3', agent_path, f.name, '--output', 'json'],
                capture_output=True,
                text=True
            )

            # Should exit with 0 for clean file
            assert result.returncode == 0

            # Output should be valid JSON
            output = json.loads(result.stdout)
            assert 'file' in output
            assert 'status' in output
            assert 'sha256' in output

            os.unlink(f.name)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
