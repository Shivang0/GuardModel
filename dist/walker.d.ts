/**
 * GuardModel File Walker
 *
 * Discovers model files in a directory tree.
 */
import type { Config } from './config';
export interface FileInfo {
    path: string;
    name: string;
    extension: string;
    size: number;
    relativePath: string;
}
/**
 * Walk a directory tree and find model files
 */
export declare function walkDirectory(rootDir: string, config: Config): FileInfo[];
/**
 * Get the agent type for a file extension
 */
export declare function getAgentType(extension: string): string;
/**
 * Format file size for display
 */
export declare function formatSize(bytes: number): string;
//# sourceMappingURL=walker.d.ts.map