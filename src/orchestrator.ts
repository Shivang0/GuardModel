/**
 * GuardModel Orchestrator
 *
 * Coordinates scanning agents and aggregates results.
 */

import { spawn } from 'child_process';
import * as path from 'path';
import type { Config, Severity } from './config';
import { isAllowlisted, getAllowlistReason } from './config';
import type { FileInfo } from './walker';
import { getAgentType } from './walker';

export interface Finding {
  rule_id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  pattern?: string;
  location?: string;
  context?: string;
  remediation?: string;
  references?: string[];
}

export interface ScanResult {
  file: string;
  relativePath: string;
  format: string;
  size: number;
  sha256: string;
  scan_duration: number;
  status: 'clean' | 'suspicious' | 'malicious' | 'error' | 'skipped';
  findings: Finding[];
  metadata: Record<string, unknown>;
  allowlisted?: boolean;
  allowlistReason?: string;
}

export interface AggregatedResults {
  scanId: string;
  timestamp: string;
  totalFiles: number;
  filesScanned: number;
  filesSkipped: number;
  filesAllowlisted: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  status: 'passed' | 'failed' | 'error';
  results: ScanResult[];
  durationMs: number;
}

// Agent routing based on file type
const AGENT_MAPPING: Record<string, string> = {
  'pickle': 'pickle_agent.py',
  'keras': 'keras_agent.py',
  'onnx': 'onnx_agent.py',
  'safetensors': 'safetensors_agent.py',
};

export class Orchestrator {
  private pythonPath: string;
  private agentsDir: string;
  private config: Config;
  private allowlistHashes: Set<string>;

  constructor(config: Config) {
    this.pythonPath = process.env.PYTHON_PATH || 'python3';
    this.agentsDir = path.join(__dirname, '..', 'python', 'agents');
    this.config = config;
    this.allowlistHashes = new Set(
      config.allowlist.map(a => a.sha256.toLowerCase())
    );
  }

  /**
   * Scan all files and aggregate results
   */
  async scanFiles(files: FileInfo[]): Promise<AggregatedResults> {
    const startTime = Date.now();
    const scanId = this.generateScanId();
    const results: ScanResult[] = [];
    let skipped = 0;
    let allowlisted = 0;

    // Process files in parallel (with concurrency limit)
    const concurrency = 4;
    const chunks = this.chunk(files, concurrency);

    for (const chunk of chunks) {
      const chunkResults = await Promise.all(
        chunk.map(file => this.scanFile(file))
      );

      for (const result of chunkResults) {
        if (result.status === 'skipped') {
          skipped++;
        } else if (result.allowlisted) {
          allowlisted++;
        }
        results.push(result);
      }
    }

    // Aggregate results
    const aggregated = this.aggregateResults(scanId, results);
    aggregated.filesSkipped = skipped;
    aggregated.filesAllowlisted = allowlisted;
    aggregated.durationMs = Date.now() - startTime;

    return aggregated;
  }

  /**
   * Scan a single file
   */
  private async scanFile(file: FileInfo): Promise<ScanResult> {
    const agentType = getAgentType(file.extension);
    const agentScript = AGENT_MAPPING[agentType];

    if (!agentScript) {
      // Unsupported format
      return {
        file: file.path,
        relativePath: file.relativePath,
        format: agentType,
        size: file.size,
        sha256: '',
        scan_duration: 0,
        status: 'skipped',
        findings: [],
        metadata: { reason: 'Unsupported format' },
      };
    }

    const agentPath = path.join(this.agentsDir, agentScript);

    try {
      const result = await this.runPythonAgent(agentPath, file.path);

      // Add relative path to result
      result.relativePath = file.relativePath;

      // Check allowlist
      if (result.sha256 && isAllowlisted(this.config, result.sha256)) {
        result.allowlisted = true;
        result.allowlistReason = getAllowlistReason(this.config, result.sha256);
        result.status = 'clean';
        result.findings = [];
      }

      return result;

    } catch (error) {
      return {
        file: file.path,
        relativePath: file.relativePath,
        format: agentType,
        size: file.size,
        sha256: '',
        scan_duration: 0,
        status: 'error',
        findings: [{
          rule_id: 'MG_SCAN_ERROR',
          category: 'ERROR',
          severity: 'info',
          title: 'Scan Error',
          description: String(error),
        }],
        metadata: { error: String(error) },
      };
    }
  }

  /**
   * Run a Python agent and parse its output
   */
  private runPythonAgent(agentPath: string, filePath: string): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const proc = spawn(
        this.pythonPath,
        [agentPath, filePath, '--output', 'json'],
        {
          timeout: this.config.timeout,
          env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
        }
      );

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        // Exit code 0 = clean, 1 = findings, other = error
        if (code !== 0 && code !== 1) {
          reject(new Error(`Agent exited with code ${code}: ${stderr}`));
          return;
        }

        try {
          const result = JSON.parse(stdout) as ScanResult;
          resolve(result);
        } catch (e) {
          reject(new Error(`Failed to parse agent output: ${stdout.slice(0, 200)}`));
        }
      });

      proc.on('error', (err) => {
        reject(err);
      });
    });
  }

  /**
   * Aggregate results from all scans
   */
  private aggregateResults(scanId: string, results: ScanResult[]): AggregatedResults {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let info = 0;

    for (const result of results) {
      for (const finding of result.findings) {
        switch (finding.severity) {
          case 'critical': critical++; break;
          case 'high': high++; break;
          case 'medium': medium++; break;
          case 'low': low++; break;
          case 'info': info++; break;
        }
      }
    }

    // Determine pass/fail based on config threshold
    const status = this.determineStatus(critical, high, medium, low);

    return {
      scanId,
      timestamp: new Date().toISOString(),
      totalFiles: results.length,
      filesScanned: results.filter(r => r.status !== 'skipped').length,
      filesSkipped: 0, // Will be set by caller
      filesAllowlisted: 0, // Will be set by caller
      totalFindings: critical + high + medium + low + info,
      critical,
      high,
      medium,
      low,
      info,
      status,
      results,
      durationMs: 0, // Will be set by caller
    };
  }

  /**
   * Determine overall pass/fail status
   */
  private determineStatus(
    critical: number,
    high: number,
    medium: number,
    low: number
  ): 'passed' | 'failed' | 'error' {
    const failThreshold = this.config.failOn;

    if (failThreshold === 'none') {
      return 'passed';
    }

    switch (failThreshold) {
      case 'critical':
        return critical > 0 ? 'failed' : 'passed';

      case 'high':
        return (critical > 0 || high > 0) ? 'failed' : 'passed';

      case 'medium':
        return (critical > 0 || high > 0 || medium > 0) ? 'failed' : 'passed';

      case 'low':
        return (critical > 0 || high > 0 || medium > 0 || low > 0) ? 'failed' : 'passed';

      case 'info':
        return 'passed'; // Info doesn't fail

      default:
        return 'passed';
    }
  }

  /**
   * Generate a unique scan ID
   */
  private generateScanId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `${timestamp}-${random}`;
  }

  /**
   * Split array into chunks
   */
  private chunk<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}

/**
 * Get severity icon for display
 */
export function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🔵';
    case 'info': return '⚪';
    default: return '⚪';
  }
}

/**
 * Get severity level for comparison
 */
export function getSeverityLevel(severity: Severity): number {
  switch (severity) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    case 'info': return 0;
    default: return -1;
  }
}
