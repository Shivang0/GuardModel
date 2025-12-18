#!/usr/bin/env python3
"""
Pytest configuration and fixtures for GuardModel tests.
"""

import os
import sys
import pytest

# Add python directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))


@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for test files."""
    return tmp_path


@pytest.fixture
def clean_pickle_file(tmp_path):
    """Create a clean pickle file for testing."""
    import pickle
    filepath = tmp_path / "clean_model.pkl"
    with open(filepath, 'wb') as f:
        pickle.dump({'weights': [1.0, 2.0, 3.0]}, f)
    return str(filepath)


@pytest.fixture
def malicious_pickle_file(tmp_path):
    """Create a malicious pickle file for testing."""
    import pickle
    import os as os_module

    filepath = tmp_path / "malicious_model.pkl"

    class Malicious:
        def __reduce__(self):
            return (os_module.system, ('echo pwned',))

    with open(filepath, 'wb') as f:
        pickle.dump(Malicious(), f)

    return str(filepath)


@pytest.fixture
def clean_safetensors_file(tmp_path):
    """Create a clean SafeTensors file for testing."""
    import json
    import struct

    filepath = tmp_path / "clean_model.safetensors"

    header = {
        'weight': {
            'dtype': 'F32',
            'shape': [10, 10],
            'data_offsets': [0, 400]
        }
    }
    header_bytes = json.dumps(header).encode('utf-8')

    with open(filepath, 'wb') as f:
        f.write(struct.pack('<Q', len(header_bytes)))
        f.write(header_bytes)
        f.write(b'\x00' * 400)

    return str(filepath)
