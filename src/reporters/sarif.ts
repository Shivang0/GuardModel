/**
 * GuardModel SARIF Reporter
 *
 * Generates SARIF 2.1.0 output for GitHub Security tab integration.
 */

import type { AggregatedResults, Finding, ScanResult } from '../orchestrator';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  helpUri: string;
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  fingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    invocations: Array<{
      executionSuccessful: boolean;
      endTimeUtc: string;
    }>;
  }>;
}

// Map severity to SARIF level
function severityToLevel(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'note';
  }
}

// Generate a unique rule ID
function normalizeRuleId(ruleId: string): string {
  // Ensure rule ID is valid for SARIF
  return ruleId.replace(/[^a-zA-Z0-9_-]/g, '_');
}

// Get category display name
function getCategoryName(category: string): string {
  const names: Record<string, string> = {
    'CODE_EXECUTION': 'Code Execution',
    'REVERSE_SHELL': 'Reverse Shell',
    'NETWORK': 'Network Activity',
    'FILE_SYSTEM': 'File System Operation',
    'DANGEROUS_IMPORT': 'Dangerous Import',
    'OBFUSCATION': 'Obfuscation',
    'KNOWN_MALWARE': 'Known Malware',
    'CVE_VULNERABLE': 'CVE Vulnerability',
    'SUSPICIOUS_STRUCTURE': 'Suspicious Structure',
    'ERROR': 'Scan Error',
  };
  return names[category] || category;
}

/**
 * Generate SARIF report from scan results
 */
export function generateSarif(results: AggregatedResults): SarifReport {
  const rules: Map<string, SarifRule> = new Map();
  const sarifResults: SarifResult[] = [];

  // Collect all unique rules and results
  for (const scanResult of results.results) {
    if (scanResult.status === 'skipped' || scanResult.allowlisted) {
      continue;
    }

    for (const finding of scanResult.findings) {
      const ruleId = normalizeRuleId(finding.rule_id);

      // Add rule if not already present
      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: finding.title,
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          defaultConfiguration: { level: severityToLevel(finding.severity) },
          helpUri: `https://guardmodel.dev/rules/${ruleId}`,
          properties: {
            category: finding.category,
            severity: finding.severity,
          },
        });
      }

      // Create result
      const result: SarifResult = {
        ruleId,
        level: severityToLevel(finding.severity),
        message: {
          text: formatMessage(finding, scanResult),
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: scanResult.relativePath || scanResult.file,
            },
            region: {
              startLine: 1, // Model files don't have line numbers
            },
          },
        }],
        fingerprints: {
          'guardmodel/v1': `${scanResult.sha256}:${ruleId}:${finding.pattern || ''}`,
        },
        properties: {
          category: getCategoryName(finding.category),
          severity: finding.severity,
          pattern: finding.pattern,
          remediation: finding.remediation,
        },
      };

      sarifResults.push(result);
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'GuardModel',
          version: '1.0.0',
          informationUri: 'https://guardmodel.dev',
          rules: Array.from(rules.values()),
        },
      },
      results: sarifResults,
      invocations: [{
        executionSuccessful: results.status !== 'error',
        endTimeUtc: results.timestamp,
      }],
    }],
  };
}

/**
 * Format finding message
 */
function formatMessage(finding: Finding, scanResult: ScanResult): string {
  let message = finding.description;

  if (finding.pattern) {
    message += `\n\nPattern: ${finding.pattern}`;
  }

  if (finding.location) {
    message += `\nLocation: ${finding.location}`;
  }

  if (finding.remediation) {
    message += `\n\nRemediation: ${finding.remediation}`;
  }

  return message;
}

/**
 * Generate SARIF JSON string
 */
export function generateSarifString(results: AggregatedResults): string {
  const sarif = generateSarif(results);
  return JSON.stringify(sarif, null, 2);
}
