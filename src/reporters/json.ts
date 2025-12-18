/**
 * GuardModel JSON Reporter
 *
 * Generates JSON output for API/programmatic use.
 */

import type { AggregatedResults } from '../orchestrator';

export interface JsonReport {
  scan_id: string;
  timestamp: string;
  duration_ms: number;
  status: 'passed' | 'failed' | 'error';
  summary: {
    files_scanned: number;
    files_skipped: number;
    files_allowlisted: number;
    files_clean: number;
    files_suspicious: number;
    files_malicious: number;
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: Array<{
    file: string;
    relative_path: string;
    format: string;
    size_bytes: number;
    sha256: string;
    threats: Array<{
      rule_id: string;
      category: string;
      severity: string;
      title: string;
      description: string;
      pattern?: string;
      location?: string;
      remediation?: string;
      references?: string[];
    }>;
  }>;
  metadata: {
    version: string;
    rules_version: string;
  };
}

/**
 * Generate JSON report from scan results
 */
export function generateJson(results: AggregatedResults): JsonReport {
  // Count file statuses
  let filesClean = 0;
  let filesSuspicious = 0;
  let filesMalicious = 0;

  for (const result of results.results) {
    switch (result.status) {
      case 'clean':
        filesClean++;
        break;
      case 'suspicious':
        filesSuspicious++;
        break;
      case 'malicious':
        filesMalicious++;
        break;
    }
  }

  // Build findings array (only files with threats)
  const findings = results.results
    .filter(r => r.findings.length > 0 && !r.allowlisted)
    .map(r => ({
      file: r.file,
      relative_path: r.relativePath || r.file,
      format: r.format,
      size_bytes: r.size,
      sha256: r.sha256,
      threats: r.findings.map(f => ({
        rule_id: f.rule_id,
        category: f.category,
        severity: f.severity,
        title: f.title,
        description: f.description,
        pattern: f.pattern,
        location: f.location,
        remediation: f.remediation,
        references: f.references,
      })),
    }));

  return {
    scan_id: results.scanId,
    timestamp: results.timestamp,
    duration_ms: results.durationMs,
    status: results.status,
    summary: {
      files_scanned: results.filesScanned,
      files_skipped: results.filesSkipped,
      files_allowlisted: results.filesAllowlisted,
      files_clean: filesClean,
      files_suspicious: filesSuspicious,
      files_malicious: filesMalicious,
      total_findings: results.totalFindings,
      critical: results.critical,
      high: results.high,
      medium: results.medium,
      low: results.low,
      info: results.info,
    },
    findings,
    metadata: {
      version: '1.0.0',
      rules_version: '1.0.0',
    },
  };
}

/**
 * Generate JSON string
 */
export function generateJsonString(results: AggregatedResults): string {
  const report = generateJson(results);
  return JSON.stringify(report, null, 2);
}

/**
 * Generate compact JSON (no pretty printing)
 */
export function generateCompactJson(results: AggregatedResults): string {
  const report = generateJson(results);
  return JSON.stringify(report);
}
