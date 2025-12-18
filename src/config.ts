/**
 * GuardModel Configuration Loader
 *
 * Loads and validates .guardmodel.yml configuration files.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface AllowlistEntry {
  sha256: string;
  reason?: string;
}

export interface RuleOverride {
  id: string;
  enabled?: boolean;
  severity?: Severity;
}

export interface OutputConfig {
  sarif: boolean;
  json: boolean;
  markdown: boolean;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none';

export interface Config {
  version: number;
  include: string[];
  exclude: string[];
  maxFileSize: number;
  maxTotalSize: number;
  failOn: Severity;
  allowlist: AllowlistEntry[];
  rules: RuleOverride[];
  output: OutputConfig;
  timeout: number;
}

const DEFAULT_CONFIG: Config = {
  version: 1,
  include: ['.'],
  exclude: [
    '.git/',
    'node_modules/',
    '__pycache__/',
    '.pytest_cache/',
    'venv/',
    '.venv/',
    'tests/fixtures/',
  ],
  maxFileSize: 5 * 1024 * 1024 * 1024, // 5GB
  maxTotalSize: 20 * 1024 * 1024 * 1024, // 20GB
  failOn: 'high',
  allowlist: [],
  rules: [],
  output: {
    sarif: true,
    json: true,
    markdown: true,
  },
  timeout: 60000, // 60 seconds per file
};

/**
 * Parse size string to bytes (e.g., "5GB" -> 5368709120)
 */
export function parseSize(sizeStr: string): number {
  const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?$/i);
  if (!match) {
    throw new Error(`Invalid size format: ${sizeStr}`);
  }

  const value = parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();

  const multipliers: Record<string, number> = {
    'B': 1,
    'KB': 1024,
    'MB': 1024 * 1024,
    'GB': 1024 * 1024 * 1024,
    'TB': 1024 * 1024 * 1024 * 1024,
  };

  return Math.floor(value * multipliers[unit]);
}

/**
 * Load configuration from file
 */
export function loadConfig(configPath: string): Config {
  const config = { ...DEFAULT_CONFIG };

  if (!fs.existsSync(configPath)) {
    return config;
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const parsed = yaml.load(content) as Record<string, unknown>;

    if (!parsed || typeof parsed !== 'object') {
      return config;
    }

    // Merge include patterns
    if (Array.isArray(parsed.include)) {
      config.include = parsed.include.map(String);
    }

    // Merge exclude patterns
    if (Array.isArray(parsed.exclude)) {
      config.exclude = [...config.exclude, ...parsed.exclude.map(String)];
    }

    // Parse max file size
    if (typeof parsed.max_file_size === 'string') {
      config.maxFileSize = parseSize(parsed.max_file_size);
    } else if (typeof parsed.maxFileSize === 'string') {
      config.maxFileSize = parseSize(parsed.maxFileSize);
    }

    // Parse max total size
    if (typeof parsed.max_total_size === 'string') {
      config.maxTotalSize = parseSize(parsed.max_total_size);
    } else if (typeof parsed.maxTotalSize === 'string') {
      config.maxTotalSize = parseSize(parsed.maxTotalSize);
    }

    // Parse fail_on severity
    if (typeof parsed.fail_on === 'string') {
      config.failOn = parsed.fail_on as Severity;
    } else if (typeof parsed.failOn === 'string') {
      config.failOn = parsed.failOn as Severity;
    }

    // Parse allowlist
    if (Array.isArray(parsed.allowlist)) {
      config.allowlist = parsed.allowlist.map((entry: unknown) => {
        if (typeof entry === 'string') {
          return { sha256: entry };
        }
        if (typeof entry === 'object' && entry !== null) {
          const obj = entry as Record<string, unknown>;
          return {
            sha256: String(obj.sha256 || ''),
            reason: obj.reason ? String(obj.reason) : undefined,
          };
        }
        return { sha256: '' };
      }).filter(e => e.sha256.length > 0);
    }

    // Parse rules
    if (Array.isArray(parsed.rules)) {
      config.rules = parsed.rules.map((rule: unknown) => {
        if (typeof rule === 'object' && rule !== null) {
          const obj = rule as Record<string, unknown>;
          return {
            id: String(obj.id || ''),
            enabled: obj.enabled !== false,
            severity: obj.severity as Severity | undefined,
          };
        }
        return { id: '' };
      }).filter(r => r.id.length > 0);
    }

    // Parse output config
    if (typeof parsed.output === 'object' && parsed.output !== null) {
      const output = parsed.output as Record<string, unknown>;
      config.output = {
        sarif: output.sarif !== false,
        json: output.json !== false,
        markdown: output.markdown !== false,
      };
    }

    // Parse timeout
    if (typeof parsed.timeout === 'number') {
      config.timeout = parsed.timeout * 1000; // Convert to ms
    } else if (typeof parsed.timeout_seconds === 'number') {
      config.timeout = parsed.timeout_seconds * 1000;
    }

  } catch (error) {
    console.error(`Warning: Failed to parse config file: ${error}`);
    return DEFAULT_CONFIG;
  }

  return config;
}

/**
 * Load configuration from action inputs and config file
 */
export function loadConfigFromInputs(inputs: Record<string, string>): Config {
  // Load base config from file
  const configPath = inputs.config || '.guardmodel.yml';
  const config = loadConfig(configPath);

  // Override with action inputs
  // Note: When path is provided, we set include to ['.'] because the path itself
  // will be used as the root directory by the walker
  if (inputs.path) {
    config.include = ['.'];
  }

  if (inputs['fail-on'] || inputs.failOn) {
    config.failOn = (inputs['fail-on'] || inputs.failOn) as Severity;
  }

  if (inputs['output-sarif'] !== undefined) {
    config.output.sarif = inputs['output-sarif'] === 'true';
  }

  if (inputs['output-json'] !== undefined) {
    config.output.json = inputs['output-json'] === 'true';
  }

  if (inputs['comment-on-pr'] !== undefined) {
    config.output.markdown = inputs['comment-on-pr'] === 'true';
  }

  if (inputs['max-file-size'] || inputs.maxFileSize) {
    config.maxFileSize = parseSize(inputs['max-file-size'] || inputs.maxFileSize);
  }

  return config;
}

/**
 * Validate configuration
 */
export function validateConfig(config: Config): string[] {
  const errors: string[] = [];

  if (config.version !== 1) {
    errors.push(`Unsupported config version: ${config.version}`);
  }

  const validSeverities = ['critical', 'high', 'medium', 'low', 'info', 'none'];
  if (!validSeverities.includes(config.failOn)) {
    errors.push(`Invalid fail_on severity: ${config.failOn}`);
  }

  if (config.maxFileSize <= 0) {
    errors.push('max_file_size must be positive');
  }

  if (config.maxTotalSize <= 0) {
    errors.push('max_total_size must be positive');
  }

  if (config.timeout <= 0) {
    errors.push('timeout must be positive');
  }

  return errors;
}

/**
 * Check if a SHA256 hash is in the allowlist
 */
export function isAllowlisted(config: Config, sha256: string): boolean {
  return config.allowlist.some(entry =>
    entry.sha256.toLowerCase() === sha256.toLowerCase()
  );
}

/**
 * Get the reason for an allowlisted hash
 */
export function getAllowlistReason(config: Config, sha256: string): string | undefined {
  const entry = config.allowlist.find(e =>
    e.sha256.toLowerCase() === sha256.toLowerCase()
  );
  return entry?.reason;
}
