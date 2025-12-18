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
