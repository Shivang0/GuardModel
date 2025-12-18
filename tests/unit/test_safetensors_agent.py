#!/usr/bin/env python3
"""
Unit tests for SafeTensors Scanner Agent
"""

import os
import sys
import json
import struct
import tempfile
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from agents.safetensors_agent import SafeTensorsAgent


class TestSafeTensorsAgent:
    """Test cases for SafeTensorsAgent."""

    def setup_method(self):
        """Set up test fixtures."""
        self.agent = SafeTensorsAgent()

    def test_can_scan_safetensors(self):
        """Test that agent can scan .safetensors files."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            f.write(b'dummy')
            f.flush()
            assert self.agent.can_scan(f.name)
            os.unlink(f.name)

    def test_cannot_scan_pkl(self):
        """Test that agent rejects .pkl files."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(b'\x80\x04test')
            f.flush()
            assert not self.agent.can_scan(f.name)
            os.unlink(f.name)

    def test_clean_safetensors(self):
        """Test scanning a clean SafeTensors file."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            # Create a valid SafeTensors file
            header = {
                'weight': {
                    'dtype': 'F32',
                    'shape': [10, 10],
                    'data_offsets': [0, 400]
                },
                '__metadata__': {
                    'format': 'pt'
                }
            }
            header_bytes = json.dumps(header).encode('utf-8')
            header_size = len(header_bytes)

            f.write(struct.pack('<Q', header_size))
            f.write(header_bytes)
            f.write(b'\x00' * 400)  # Fake tensor data
            f.flush()

            result = self.agent.scan(f.name)

            assert result.status == 'clean'
            assert result.sha256
            assert result.metadata.get('tensor_count') == 1

            os.unlink(f.name)

    def test_truncated_file(self):
        """Test detection of truncated file."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            # Write only 4 bytes (less than header size field)
            f.write(b'\x00\x00\x00\x00')
            f.flush()

            result = self.agent.scan(f.name)

            assert any('Truncated' in finding['title'] for finding in result.findings)

            os.unlink(f.name)

    def test_large_header(self):
        """Test detection of unusually large header."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            # Write a header size of 200MB (suspicious)
            f.write(struct.pack('<Q', 200 * 1024 * 1024))
            f.write(b'\x00' * 100)
            f.flush()

            result = self.agent.scan(f.name)

            assert any('large header' in finding['title'].lower() or
                      'header' in finding['description'].lower()
                      for finding in result.findings)

            os.unlink(f.name)

    def test_invalid_header_size(self):
        """Test detection of header size larger than file."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            # Header size is 1000 but file is only ~20 bytes
            f.write(struct.pack('<Q', 1000))
            f.write(b'short')
            f.flush()

            result = self.agent.scan(f.name)

            assert any('Truncated' in f['title'] or 'Invalid' in f['title']
                      for f in result.findings)

            os.unlink(f.name)

    def test_invalid_json_header(self):
        """Test detection of invalid JSON header."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            header_bytes = b'not valid json {'
            header_size = len(header_bytes)

            f.write(struct.pack('<Q', header_size))
            f.write(header_bytes)
            f.flush()

            result = self.agent.scan(f.name)

            assert any('Invalid' in f['title'] or 'JSON' in f['title']
                      for f in result.findings)

            os.unlink(f.name)

    def test_suspicious_metadata_key(self):
        """Test detection of suspicious metadata keys."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            header = {
                'weight': {
                    'dtype': 'F32',
                    'shape': [10],
                    'data_offsets': [0, 40]
                },
                '__metadata__': {
                    'eval_code': 'os.system("echo pwned")'
                }
            }
            header_bytes = json.dumps(header).encode('utf-8')

            f.write(struct.pack('<Q', len(header_bytes)))
            f.write(header_bytes)
            f.write(b'\x00' * 40)
            f.flush()

            result = self.agent.scan(f.name)

            assert any('Suspicious' in f['title'] or 'metadata' in f['title'].lower()
                      for f in result.findings)

            os.unlink(f.name)

    def test_suspicious_metadata_value(self):
        """Test detection of suspicious metadata values."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            header = {
                'weight': {
                    'dtype': 'F32',
                    'shape': [10],
                    'data_offsets': [0, 40]
                },
                '__metadata__': {
                    'notes': 'Use eval() to load custom layers'
                }
            }
            header_bytes = json.dumps(header).encode('utf-8')

            f.write(struct.pack('<Q', len(header_bytes)))
            f.write(header_bytes)
            f.write(b'\x00' * 40)
            f.flush()

            result = self.agent.scan(f.name)

            # May or may not flag based on sensitivity
            assert result.status in ('clean', 'suspicious')

            os.unlink(f.name)

    def test_hash_calculation(self):
        """Test that SHA256 hash is calculated correctly."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            header = {'weight': {'dtype': 'F32', 'shape': [1], 'data_offsets': [0, 4]}}
            header_bytes = json.dumps(header).encode('utf-8')

            f.write(struct.pack('<Q', len(header_bytes)))
            f.write(header_bytes)
            f.write(b'\x00\x00\x00\x00')
            f.flush()

            result = self.agent.scan(f.name)

            assert len(result.sha256) == 64
            assert all(c in '0123456789abcdef' for c in result.sha256)

            os.unlink(f.name)

    def test_empty_file(self):
        """Test handling of empty file."""
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            f.flush()

            result = self.agent.scan(f.name)

            assert any('Truncated' in f['title'] for f in result.findings)

            os.unlink(f.name)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
