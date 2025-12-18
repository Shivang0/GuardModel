/**
 * Unit tests for walker module
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import { walkDirectory, getAgentType, formatSize, FileInfo } from '../../src/walker';
import { Config } from '../../src/config';

describe('walkDirectory', () => {
  let tempDir: string;
  let config: Config;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardmodel-walk-'));
    config = {
      version: 1,
      include: ['.'],
      exclude: ['.git/', 'node_modules/'],
      maxFileSize: 1024 * 1024 * 1024, // 1GB
      maxTotalSize: 10 * 1024 * 1024 * 1024,
      failOn: 'high',
      allowlist: [],
      rules: [],
      output: { sarif: true, json: true, markdown: true },
      timeout: 60000,
    };
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true });
  });

  it('should find pickle files', () => {
    fs.writeFileSync(path.join(tempDir, 'model.pkl'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].extension).toBe('.pkl');
  });

  it('should find PyTorch files', () => {
    fs.writeFileSync(path.join(tempDir, 'model.pt'), 'test');
    fs.writeFileSync(path.join(tempDir, 'checkpoint.pth'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(2);
    expect(files.some(f => f.extension === '.pt')).toBe(true);
    expect(files.some(f => f.extension === '.pth')).toBe(true);
  });

  it('should find Keras files', () => {
    fs.writeFileSync(path.join(tempDir, 'model.h5'), 'test');
    fs.writeFileSync(path.join(tempDir, 'model.keras'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(2);
  });

  it('should find ONNX files', () => {
    fs.writeFileSync(path.join(tempDir, 'model.onnx'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].extension).toBe('.onnx');
  });

  it('should find SafeTensors files', () => {
    fs.writeFileSync(path.join(tempDir, 'model.safetensors'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].extension).toBe('.safetensors');
  });

  it('should ignore non-model files', () => {
    fs.writeFileSync(path.join(tempDir, 'model.pkl'), 'test');
    fs.writeFileSync(path.join(tempDir, 'readme.txt'), 'test');
    fs.writeFileSync(path.join(tempDir, 'script.py'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].extension).toBe('.pkl');
  });

  it('should respect exclude patterns', () => {
    fs.mkdirSync(path.join(tempDir, 'tests'));
    fs.writeFileSync(path.join(tempDir, 'model.pkl'), 'test');
    fs.writeFileSync(path.join(tempDir, 'tests', 'test_model.pkl'), 'test');

    config.exclude.push('tests/');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].name).toBe('model.pkl');
  });

  it('should walk subdirectories', () => {
    fs.mkdirSync(path.join(tempDir, 'models'));
    fs.mkdirSync(path.join(tempDir, 'models', 'v1'));
    fs.writeFileSync(path.join(tempDir, 'models', 'model.pkl'), 'test');
    fs.writeFileSync(path.join(tempDir, 'models', 'v1', 'checkpoint.pth'), 'test');

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(2);
  });

  it('should skip files exceeding max size', () => {
    fs.writeFileSync(path.join(tempDir, 'small.pkl'), 'small');
    fs.writeFileSync(path.join(tempDir, 'large.pkl'), Buffer.alloc(1024));

    config.maxFileSize = 100; // Very small limit

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].name).toBe('small.pkl');
  });

  it('should return correct file info', () => {
    const content = 'test content';
    fs.writeFileSync(path.join(tempDir, 'model.pkl'), content);

    const files = walkDirectory(tempDir, config);
    expect(files.length).toBe(1);
    expect(files[0].name).toBe('model.pkl');
    expect(files[0].extension).toBe('.pkl');
    expect(files[0].size).toBe(content.length);
    expect(files[0].relativePath).toBe('model.pkl');
    expect(path.isAbsolute(files[0].path)).toBe(true);
  });
});

describe('getAgentType', () => {
  it('should return pickle for pickle extensions', () => {
    expect(getAgentType('.pkl')).toBe('pickle');
    expect(getAgentType('.pickle')).toBe('pickle');
    expect(getAgentType('.pt')).toBe('pickle');
    expect(getAgentType('.pth')).toBe('pickle');
    expect(getAgentType('.bin')).toBe('pickle');
    expect(getAgentType('.joblib')).toBe('pickle');
  });

  it('should return keras for keras extensions', () => {
    expect(getAgentType('.h5')).toBe('keras');
    expect(getAgentType('.hdf5')).toBe('keras');
    expect(getAgentType('.keras')).toBe('keras');
  });

  it('should return onnx for onnx extension', () => {
    expect(getAgentType('.onnx')).toBe('onnx');
  });

  it('should return safetensors for safetensors extension', () => {
    expect(getAgentType('.safetensors')).toBe('safetensors');
  });

  it('should handle uppercase extensions', () => {
    expect(getAgentType('.PKL')).toBe('pickle');
    expect(getAgentType('.ONNX')).toBe('onnx');
  });

  it('should return unknown for unsupported extensions', () => {
    expect(getAgentType('.txt')).toBe('unknown');
    expect(getAgentType('.py')).toBe('unknown');
  });
});

describe('formatSize', () => {
  it('should format bytes', () => {
    expect(formatSize(0)).toBe('0 B');
    expect(formatSize(512)).toBe('512 B');
    expect(formatSize(1023)).toBe('1023 B');
  });

  it('should format kilobytes', () => {
    expect(formatSize(1024)).toBe('1.0 KB');
    expect(formatSize(1536)).toBe('1.5 KB');
  });

  it('should format megabytes', () => {
    expect(formatSize(1024 * 1024)).toBe('1.0 MB');
    expect(formatSize(1.5 * 1024 * 1024)).toBe('1.5 MB');
  });

  it('should format gigabytes', () => {
    expect(formatSize(1024 * 1024 * 1024)).toBe('1.0 GB');
  });

  it('should format terabytes', () => {
    expect(formatSize(1024 * 1024 * 1024 * 1024)).toBe('1.0 TB');
  });
});
