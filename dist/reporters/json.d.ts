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
export declare function generateJson(results: AggregatedResults): JsonReport;
/**
 * Generate JSON string
 */
export declare function generateJsonString(results: AggregatedResults): string;
/**
 * Generate compact JSON (no pretty printing)
 */
export declare function generateCompactJson(results: AggregatedResults): string;
//# sourceMappingURL=json.d.ts.map