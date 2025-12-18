/**
 * GuardModel Markdown Reporter
 *
 * Generates Markdown output for PR comments.
 */

import type { AggregatedResults, Finding, ScanResult } from '../orchestrator';
import { getSeverityIcon } from '../orchestrator';
import { formatSize } from '../walker';

/**
 * Generate Markdown report for PR comment
 */
export function generateMarkdown(results: AggregatedResults): string {
  const lines: string[] = [];

  // Header
  lines.push('## 🛡️ GuardModel Security Scan');
  lines.push('');

  // Status badge
  if (results.status === 'passed') {
    lines.push('**Status:** ✅ PASSED');
  } else if (results.status === 'failed') {
    lines.push(`**Status:** ❌ FAILED - ${results.totalFindings} threat${results.totalFindings !== 1 ? 's' : ''} detected`);
  } else {
    lines.push('**Status:** ⚠️ ERROR');
  }
  lines.push('');

  // Summary
  lines.push('### Summary');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Files Scanned | ${results.filesScanned} |`);
  if (results.filesSkipped > 0) {
    lines.push(`| Files Skipped | ${results.filesSkipped} |`);
  }
  if (results.filesAllowlisted > 0) {
    lines.push(`| Files Allowlisted | ${results.filesAllowlisted} |`);
  }
  lines.push(`| Total Findings | ${results.totalFindings} |`);
  if (results.critical > 0) {
    lines.push(`| 🔴 Critical | ${results.critical} |`);
  }
  if (results.high > 0) {
    lines.push(`| 🟠 High | ${results.high} |`);
  }
  if (results.medium > 0) {
    lines.push(`| 🟡 Medium | ${results.medium} |`);
  }
  if (results.low > 0) {
    lines.push(`| 🔵 Low | ${results.low} |`);
  }
  lines.push(`| Scan Duration | ${(results.durationMs / 1000).toFixed(2)}s |`);
  lines.push('');

  // Findings table
  const findingsToShow = getAllFindings(results).slice(0, 50); // Limit to 50

  if (findingsToShow.length > 0) {
    lines.push('### Findings');
    lines.push('');
    lines.push('| File | Severity | Threat | Details |');
    lines.push('|------|----------|--------|---------|');

    for (const { finding, result } of findingsToShow) {
      const icon = getSeverityIcon(finding.severity);
      const file = truncatePath(result.relativePath || result.file, 40);
      const severity = finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1);
      const threat = finding.category.replace(/_/g, ' ');
      const details = truncate(finding.title, 50);

      lines.push(`| \`${file}\` | ${icon} ${severity} | ${threat} | ${details} |`);
    }

    if (results.totalFindings > 50) {
      lines.push('');
      lines.push(`*...and ${results.totalFindings - 50} more findings*`);
    }
    lines.push('');
  }

  // Recommendations for critical/high findings
  const criticalFindings = getAllFindings(results)
    .filter(f => f.finding.severity === 'critical' || f.finding.severity === 'high')
    .slice(0, 5);

  if (criticalFindings.length > 0) {
    lines.push('### Recommendations');
    lines.push('');

    for (let i = 0; i < criticalFindings.length; i++) {
      const { finding, result } = criticalFindings[i];
      lines.push(`${i + 1}. **${result.relativePath || result.file}**: ${finding.remediation || 'Do not load this file without review.'}`);
      if (finding.pattern) {
        lines.push(`   - Pattern: \`${finding.pattern}\``);
      }
    }
    lines.push('');
  }

  // Scanned files (collapsible)
  if (results.filesScanned > 0) {
    lines.push('<details>');
    lines.push('<summary>Scanned Files</summary>');
    lines.push('');

    for (const result of results.results) {
      if (result.status === 'skipped') continue;

      const icon = result.status === 'clean' ? '✅' :
                   result.status === 'malicious' ? '🔴' :
                   result.status === 'suspicious' ? '🟠' : '⚠️';

      const status = result.allowlisted ? '(allowlisted)' :
                     result.status === 'clean' ? '' :
                     `(${result.findings.length} finding${result.findings.length !== 1 ? 's' : ''})`;

      lines.push(`- ${icon} \`${result.relativePath}\` ${status}`);
    }

    lines.push('');
    lines.push('</details>');
    lines.push('');
  }

  // Footer
  lines.push('---');
  lines.push(`*Scanned ${results.filesScanned} file${results.filesScanned !== 1 ? 's' : ''} in ${(results.durationMs / 1000).toFixed(1)}s • [GuardModel](https://modelguard.dev)*`);

  return lines.join('\n');
}

/**
 * Get all findings with their parent scan result
 */
function getAllFindings(results: AggregatedResults): Array<{ finding: Finding; result: ScanResult }> {
  const all: Array<{ finding: Finding; result: ScanResult }> = [];

  for (const result of results.results) {
    if (result.allowlisted) continue;

    for (const finding of result.findings) {
      all.push({ finding, result });
    }
  }

  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = {
    'critical': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
    'info': 4,
  };

  all.sort((a, b) => {
    const aOrder = severityOrder[a.finding.severity] ?? 5;
    const bOrder = severityOrder[b.finding.severity] ?? 5;
    return aOrder - bOrder;
  });

  return all;
}

/**
 * Truncate string with ellipsis
 */
function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * Truncate file path, keeping the end
 */
function truncatePath(path: string, maxLength: number): string {
  if (path.length <= maxLength) return path;
  return '...' + path.slice(-(maxLength - 3));
}

/**
 * Generate a short summary for action output
 */
export function generateSummary(results: AggregatedResults): string {
  if (results.status === 'passed') {
    return `✅ GuardModel: Scanned ${results.filesScanned} files, no threats detected`;
  } else if (results.status === 'failed') {
    const threats = [];
    if (results.critical > 0) threats.push(`${results.critical} critical`);
    if (results.high > 0) threats.push(`${results.high} high`);
    if (results.medium > 0) threats.push(`${results.medium} medium`);
    return `❌ GuardModel: Found ${threats.join(', ')} severity threats in ${results.filesScanned} files`;
  } else {
    return `⚠️ GuardModel: Scan encountered errors`;
  }
}
