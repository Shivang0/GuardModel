#!/usr/bin/env python3
"""
Demo script to download a model from Hugging Face for GuardModel testing.

This downloads a small sentiment analysis model in various formats
to demonstrate GuardModel's scanning capabilities.
"""

import os
import urllib.request
import json

# Create models directory
os.makedirs('models', exist_ok=True)

print("Downloading demo models from Hugging Face...")

# Download a small pickle-based model (scikit-learn sentiment classifier)
# Using a known safe model from Hugging Face Hub
MODEL_URL = "https://huggingface.co/juliensimon/distilbert-amazon-shoe-reviews/resolve/main/pytorch_model.bin"

try:
    print(f"\n1. Downloading PyTorch model...")
    urllib.request.urlretrieve(
        MODEL_URL,
        "models/pytorch_model.bin"
    )
    print("   Downloaded: models/pytorch_model.bin")
except Exception as e:
    print(f"   Skipped (may require auth): {e}")

# Create a simple safe pickle for testing
print("\n2. Creating safe test pickle...")
import pickle
safe_data = {
    'model_name': 'demo_classifier',
    'version': '1.0',
    'weights': [0.1, 0.2, 0.3, 0.4, 0.5],
    'bias': 0.01,
    'classes': ['positive', 'negative'],
}
with open('models/safe_model.pkl', 'wb') as f:
    pickle.dump(safe_data, f)
print("   Created: models/safe_model.pkl")

# Create a safetensors file (just metadata, safe format)
print("\n3. Creating SafeTensors metadata file...")
safetensors_metadata = {
    "__metadata__": {
        "format": "pt",
        "framework": "pytorch"
    }
}
# SafeTensors header format: 8-byte length + JSON header
header_json = json.dumps(safetensors_metadata).encode('utf-8')
header_len = len(header_json)
with open('models/model.safetensors', 'wb') as f:
    f.write(header_len.to_bytes(8, 'little'))
    f.write(header_json)
print("   Created: models/model.safetensors")

print("\n" + "="*50)
print("Demo models ready for scanning!")
print("Run: guardmodel scan models/")
print("="*50)
