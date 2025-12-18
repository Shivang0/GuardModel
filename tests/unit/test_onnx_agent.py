#!/usr/bin/env python3
"""
Unit tests for ONNX Scanner Agent
"""

import os
import sys
import tempfile
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))

from agents.onnx_agent import ONNXAgent

# Check if onnx is available
try:
    import onnx
    from onnx import helper, TensorProto
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False


class TestONNXAgent:
    """Test cases for ONNXAgent."""

    def setup_method(self):
        """Set up test fixtures."""
        self.agent = ONNXAgent()

    def test_can_scan_onnx(self):
        """Test that agent can scan .onnx files."""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            f.write(b'\x08\x00')  # Protobuf start
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

    @pytest.mark.skipif(not ONNX_AVAILABLE, reason="ONNX not installed")
    def test_clean_onnx(self):
        """Test scanning a clean ONNX file."""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            # Create a simple valid ONNX model
            X = helper.make_tensor_value_info('X', TensorProto.FLOAT, [1, 3])
            Y = helper.make_tensor_value_info('Y', TensorProto.FLOAT, [1, 3])

            relu_node = helper.make_node('Relu', ['X'], ['Y'], name='relu')

            graph = helper.make_graph([relu_node], 'test_graph', [X], [Y])
            model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 13)])

            onnx.save(model, f.name)

            result = self.agent.scan(f.name)

            assert result.status == 'clean'
            assert result.sha256
            assert result.metadata.get('valid') == True

            os.unlink(f.name)

    @pytest.mark.skipif(not ONNX_AVAILABLE, reason="ONNX not installed")
    def test_custom_domain_detection(self):
        """Test detection of custom operator domains."""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            X = helper.make_tensor_value_info('X', TensorProto.FLOAT, [1, 3])
            Y = helper.make_tensor_value_info('Y', TensorProto.FLOAT, [1, 3])

            # Create node with custom domain
            custom_node = helper.make_node(
                'CustomOp', ['X'], ['Y'],
                name='custom',
                domain='com.custom.domain'
            )

            graph = helper.make_graph([custom_node], 'test_graph', [X], [Y])
            model = helper.make_model(
                graph,
                opset_imports=[
                    helper.make_opsetid('', 13),
                    helper.make_opsetid('com.custom.domain', 1)
                ]
            )

            onnx.save(model, f.name)

            result = self.agent.scan(f.name)

            # Should detect non-standard domain
            assert any('domain' in f['title'].lower() or 'custom' in f['title'].lower()
                      for f in result.findings)

            os.unlink(f.name)

    @pytest.mark.skipif(not ONNX_AVAILABLE, reason="ONNX not installed")
    def test_control_flow_detection(self):
        """Test detection of control flow operators."""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            # Create a model with If operator
            X = helper.make_tensor_value_info('X', TensorProto.BOOL, [1])
            Y = helper.make_tensor_value_info('Y', TensorProto.FLOAT, [1])

            # Simple then/else branches
            then_out = helper.make_tensor_value_info('then_out', TensorProto.FLOAT, [1])
            then_const = helper.make_node('Constant', [], ['then_out'],
                                          value=helper.make_tensor('const', TensorProto.FLOAT, [1], [1.0]))
            then_graph = helper.make_graph([then_const], 'then_branch', [], [then_out])

            else_out = helper.make_tensor_value_info('else_out', TensorProto.FLOAT, [1])
            else_const = helper.make_node('Constant', [], ['else_out'],
                                          value=helper.make_tensor('const', TensorProto.FLOAT, [1], [0.0]))
            else_graph = helper.make_graph([else_const], 'else_branch', [], [else_out])

            if_node = helper.make_node('If', ['X'], ['Y'],
                                       then_branch=then_graph,
                                       else_branch=else_graph)

            graph = helper.make_graph([if_node], 'test_graph', [X], [Y])
            model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 13)])

            onnx.save(model, f.name)

            result = self.agent.scan(f.name)

            # Should detect control flow
            assert any('control' in f['title'].lower() or 'If' in f['title']
                      for f in result.findings)

            os.unlink(f.name)

    def test_hash_calculation(self):
        """Test that SHA256 hash is calculated correctly."""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            f.write(b'\x08\x00test_data')
            f.flush()

            result = self.agent.scan(f.name)

            assert len(result.sha256) == 64
            assert all(c in '0123456789abcdef' for c in result.sha256)

            os.unlink(f.name)

    def test_corrupt_file(self):
        """Test handling of corrupt ONNX file."""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            f.write(b'not valid protobuf data at all')
            f.flush()

            result = self.agent.scan(f.name)

            # Should handle gracefully
            assert result.status in ('clean', 'error', 'suspicious')

            os.unlink(f.name)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
