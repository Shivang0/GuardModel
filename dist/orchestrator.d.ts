/**
 * GuardModel Orchestrator
 *
 * Coordinates scanning agents and aggregates results.
 */
import type { Config, Severity } from './config';
import type { FileInfo } from './walker';
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
export declare class Orchestrator {
    private pythonPath;
    private agentsDir;
    private config;
    private allowlistHashes;
    constructor(config: Config);
    /**
     * Scan all files and aggregate results
     */
    scanFiles(files: FileInfo[]): Promise<AggregatedResults>;
    /**
     * Scan a single file
     */
    private scanFile;
    /**
     * Run a Python agent and parse its output
     */
    private runPythonAgent;
    /**
     * Aggregate results from all scans
     */
    private aggregateResults;
    /**
     * Determine overall pass/fail status
     */
    private determineStatus;
    /**
     * Generate a unique scan ID
     */
    private generateScanId;
    /**
     * Split array into chunks
     */
    private chunk;
}
/**
 * Get severity icon for display
 */
export declare function getSeverityIcon(severity: Severity): string;
/**
 * Get severity level for comparison
 */
export declare function getSeverityLevel(severity: Severity): number;
