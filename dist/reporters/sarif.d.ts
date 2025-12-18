/**
 * GuardModel SARIF Reporter
 *
 * Generates SARIF 2.1.0 output for GitHub Security tab integration.
 */
import type { AggregatedResults } from '../orchestrator';
interface SarifRule {
    id: string;
    name: string;
    shortDescription: {
        text: string;
    };
    fullDescription: {
        text: string;
    };
    defaultConfiguration: {
        level: string;
    };
    helpUri: string;
    properties?: Record<string, unknown>;
}
interface SarifResult {
    ruleId: string;
    level: string;
    message: {
        text: string;
    };
    locations: Array<{
        physicalLocation: {
            artifactLocation: {
                uri: string;
            };
            region?: {
                startLine: number;
            };
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
/**
 * Generate SARIF report from scan results
 */
export declare function generateSarif(results: AggregatedResults): SarifReport;
/**
 * Generate SARIF JSON string
 */
export declare function generateSarifString(results: AggregatedResults): string;
export {};
//# sourceMappingURL=sarif.d.ts.map