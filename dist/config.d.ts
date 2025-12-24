/**
 * GuardModel Configuration Loader
 *
 * Loads and validates .guardmodel.yml configuration files.
 */
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
/**
 * Parse size string to bytes (e.g., "5GB" -> 5368709120)
 */
export declare function parseSize(sizeStr: string): number;
/**
 * Load configuration from file
 */
export declare function loadConfig(configPath: string): Config;
/**
 * Load configuration from action inputs and config file
 */
export declare function loadConfigFromInputs(inputs: Record<string, string>): Config;
/**
 * Validate configuration
 */
export declare function validateConfig(config: Config): string[];
/**
 * Check if a SHA256 hash is in the allowlist
 */
export declare function isAllowlisted(config: Config, sha256: string): boolean;
/**
 * Get the reason for an allowlisted hash
 */
export declare function getAllowlistReason(config: Config, sha256: string): string | undefined;
