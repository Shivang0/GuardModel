/**
 * Unit tests for config module
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

import {
  loadConfig,
  loadConfigFromInputs,
  validateConfig,
  parseSize,
  isAllowlisted,
  getAllowlistReason,
  Config,
} from '../../src/config';

describe('parseSize', () => {
  it('should parse bytes', () => {
    expect(parseSize('1024')).toBe(1024);
    expect(parseSize('1024B')).toBe(1024);
  });

  it('should parse kilobytes', () => {
    expect(parseSize('1KB')).toBe(1024);
    expect(parseSize('10KB')).toBe(10240);
  });

  it('should parse megabytes', () => {
    expect(parseSize('1MB')).toBe(1024 * 1024);
    expect(parseSize('100MB')).toBe(100 * 1024 * 1024);
  });

  it('should parse gigabytes', () => {
    expect(parseSize('1GB')).toBe(1024 * 1024 * 1024);
    expect(parseSize('5GB')).toBe(5 * 1024 * 1024 * 1024);
  });

  it('should parse terabytes', () => {
    expect(parseSize('1TB')).toBe(1024 * 1024 * 1024 * 1024);
  });

  it('should handle decimal values', () => {
    expect(parseSize('1.5GB')).toBe(Math.floor(1.5 * 1024 * 1024 * 1024));
  });

  it('should be case insensitive', () => {
    expect(parseSize('1gb')).toBe(parseSize('1GB'));
    expect(parseSize('1mb')).toBe(parseSize('1MB'));
  });

  it('should throw on invalid format', () => {
    expect(() => parseSize('invalid')).toThrow();
    expect(() => parseSize('GB')).toThrow();
  });
});

describe('loadConfig', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'modelguard-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true });
  });

  it('should return default config when file does not exist', () => {
    const config = loadConfig(path.join(tempDir, 'nonexistent.yml'));
    expect(config.version).toBe(1);
    expect(config.failOn).toBe('high');
  });

  it('should load config from YAML file', () => {
    const configPath = path.join(tempDir, '.guardmodel.yml');
    fs.writeFileSync(configPath, `
version: 1
fail_on: critical
include:
  - models/
exclude:
  - tests/
max_file_size: 10GB
allowlist:
  - sha256: abc123
    reason: Known safe model
`);

    const config = loadConfig(configPath);
    expect(config.failOn).toBe('critical');
    expect(config.include).toContain('models/');
    expect(config.allowlist.length).toBe(1);
    expect(config.allowlist[0].sha256).toBe('abc123');
    expect(config.allowlist[0].reason).toBe('Known safe model');
  });

  it('should merge exclude patterns with defaults', () => {
    const configPath = path.join(tempDir, '.guardmodel.yml');
    fs.writeFileSync(configPath, `
exclude:
  - custom_exclude/
`);

    const config = loadConfig(configPath);
    expect(config.exclude).toContain('.git/');
    expect(config.exclude).toContain('custom_exclude/');
  });
});

describe('loadConfigFromInputs', () => {
  it('should override config with inputs', () => {
    const inputs = {
      path: './my-models',
      'fail-on': 'medium',
      'output-sarif': 'false',
      'max-file-size': '2GB',
    };

    const config = loadConfigFromInputs(inputs);
    // When path is provided, include is set to ['.'] since path is used as root directory
    expect(config.include).toContain('.');
    expect(config.failOn).toBe('medium');
    expect(config.output.sarif).toBe(false);
    expect(config.maxFileSize).toBe(2 * 1024 * 1024 * 1024);
  });
});

describe('validateConfig', () => {
  it('should return empty array for valid config', () => {
    const config: Config = {
      version: 1,
      include: ['.'],
      exclude: [],
      maxFileSize: 1024,
      maxTotalSize: 1024 * 1024,
      failOn: 'high',
      allowlist: [],
      rules: [],
      output: { sarif: true, json: true, markdown: true },
      timeout: 60000,
    };

    const errors = validateConfig(config);
    expect(errors).toHaveLength(0);
  });

  it('should detect invalid severity', () => {
    const config: Config = {
      version: 1,
      include: ['.'],
      exclude: [],
      maxFileSize: 1024,
      maxTotalSize: 1024 * 1024,
      failOn: 'invalid' as any,
      allowlist: [],
      rules: [],
      output: { sarif: true, json: true, markdown: true },
      timeout: 60000,
    };

    const errors = validateConfig(config);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some(e => e.includes('severity'))).toBe(true);
  });
});

describe('isAllowlisted', () => {
  it('should return true for allowlisted hash', () => {
    const config: Config = {
      version: 1,
      include: ['.'],
      exclude: [],
      maxFileSize: 1024,
      maxTotalSize: 1024 * 1024,
      failOn: 'high',
      allowlist: [{ sha256: 'abc123def456' }],
      rules: [],
      output: { sarif: true, json: true, markdown: true },
      timeout: 60000,
    };

    expect(isAllowlisted(config, 'abc123def456')).toBe(true);
    expect(isAllowlisted(config, 'ABC123DEF456')).toBe(true); // Case insensitive
    expect(isAllowlisted(config, 'other')).toBe(false);
  });
});

describe('getAllowlistReason', () => {
  it('should return reason for allowlisted hash', () => {
    const config: Config = {
      version: 1,
      include: ['.'],
      exclude: [],
      maxFileSize: 1024,
      maxTotalSize: 1024 * 1024,
      failOn: 'high',
      allowlist: [{ sha256: 'abc123', reason: 'Known safe' }],
      rules: [],
      output: { sarif: true, json: true, markdown: true },
      timeout: 60000,
    };

    expect(getAllowlistReason(config, 'abc123')).toBe('Known safe');
    expect(getAllowlistReason(config, 'other')).toBeUndefined();
  });
});
