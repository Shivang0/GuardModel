#!/usr/bin/env python3
"""
Unit tests for Keras Scanner Agent
"""

import os
import sys
import json
import tempfile
import zipfile
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from agents.keras_agent import KerasAgent


class TestKerasAgent:
    """Test cases for KerasAgent."""

    def setup_method(self):
        """Set up test fixtures."""
        self.agent = KerasAgent()

    def test_can_scan_h5(self):
        """Test that agent can scan .h5 files."""
        with tempfile.NamedTemporaryFile(suffix='.h5', delete=False) as f:
            f.write(b'\x89HDF\r\n\x1a\n')  # HDF5 magic bytes
            f.flush()
            assert self.agent.can_scan(f.name)
            os.unlink(f.name)

    def test_can_scan_keras(self):
        """Test that agent can scan .keras files."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
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

    def test_clean_keras_v3(self):
        """Test scanning a clean Keras v3 file (ZIP format)."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            # Create a minimal Keras v3 ZIP file
            with zipfile.ZipFile(f.name, 'w') as zf:
                config = {
                    'class_name': 'Sequential',
                    'config': {
                        'name': 'test_model',
                        'layers': [
                            {
                                'class_name': 'Dense',
                                'config': {'units': 10, 'activation': 'relu'}
                            }
                        ]
                    }
                }
                zf.writestr('config.json', json.dumps(config))

            result = self.agent.scan(f.name)

            assert result.status == 'clean'
            assert len(result.findings) == 0
            assert result.sha256

            os.unlink(f.name)

    def test_lambda_detection(self):
        """Test detection of Lambda layers."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            # Create Keras file with Lambda layer
            with zipfile.ZipFile(f.name, 'w') as zf:
                config = {
                    'class_name': 'Sequential',
                    'config': {
                        'name': 'test_model',
                        'layers': [
                            {
                                'class_name': 'Lambda',
                                'config': {
                                    'function': 'lambda x: x * 2',
                                    'function_type': 'lambda'
                                }
                            }
                        ]
                    }
                }
                zf.writestr('config.json', json.dumps(config))

            result = self.agent.scan(f.name)

            # Lambda layers should be flagged
            assert len(result.findings) > 0
            assert any('Lambda' in f['title'] for f in result.findings)

            os.unlink(f.name)

    def test_dangerous_lambda(self):
        """Test detection of dangerous code in Lambda."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            # Create Keras file with dangerous Lambda
            with zipfile.ZipFile(f.name, 'w') as zf:
                config = {
                    'class_name': 'Sequential',
                    'config': {
                        'name': 'malicious_model',
                        'layers': [
                            {
                                'class_name': 'Lambda',
                                'config': {
                                    'function': 'lambda x: os.system("echo pwned")',
                                    'function_type': 'lambda'
                                }
                            }
                        ]
                    }
                }
                zf.writestr('config.json', json.dumps(config))

            result = self.agent.scan(f.name)

            assert result.status in ('malicious', 'suspicious')
            assert any(f['severity'] in ('critical', 'high') for f in result.findings)

            os.unlink(f.name)

    def test_pickle_in_keras(self):
        """Test detection of pickle files inside Keras archive."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            with zipfile.ZipFile(f.name, 'w') as zf:
                config = {
                    'class_name': 'Sequential',
                    'config': {'name': 'test'}
                }
                zf.writestr('config.json', json.dumps(config))
                zf.writestr('weights.pkl', b'\x80\x04data')

            result = self.agent.scan(f.name)

            # Should detect pickle file
            assert any('Pickle' in f['title'] or 'pickle' in f['description'].lower()
                      for f in result.findings)

            os.unlink(f.name)

    def test_hash_calculation(self):
        """Test that SHA256 hash is calculated correctly."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            with zipfile.ZipFile(f.name, 'w') as zf:
                zf.writestr('config.json', '{}')

            result = self.agent.scan(f.name)

            assert len(result.sha256) == 64
            assert all(c in '0123456789abcdef' for c in result.sha256)

            os.unlink(f.name)

    def test_corrupt_zip(self):
        """Test handling of corrupt ZIP file."""
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            f.write(b'not a valid zip file')
            f.flush()

            result = self.agent.scan(f.name)

            # Should handle gracefully (might try HDF5 fallback)
            assert result.status in ('clean', 'error', 'suspicious')

            os.unlink(f.name)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
