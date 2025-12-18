"use strict";
/**
 * GuardModel File Walker
 *
 * Discovers model files in a directory tree.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.walkDirectory = walkDirectory;
exports.getAgentType = getAgentType;
exports.formatSize = formatSize;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// Supported model file extensions
const SUPPORTED_EXTENSIONS = new Set([
    '.pkl',
    '.pickle',
    '.pt',
    '.pth',
    '.bin',
    '.joblib',
    '.h5',
    '.hdf5',
    '.keras',
    '.onnx',
    '.safetensors',
    '.gguf',
]);
/**
 * Check if a path matches any of the exclude patterns
 */
function isExcluded(filePath, excludePatterns) {
    const normalizedPath = filePath.replace(/\\/g, '/');
    for (const pattern of excludePatterns) {
        // Simple pattern matching
        const normalizedPattern = pattern.replace(/\\/g, '/');
        // Check if it's a directory pattern (ends with /)
        if (normalizedPattern.endsWith('/')) {
            const dir = normalizedPattern.slice(0, -1);
            if (normalizedPath.includes(`/${dir}/`) || normalizedPath.startsWith(`${dir}/`)) {
                return true;
            }
        }
        // Check exact match or path contains pattern
        if (normalizedPath === normalizedPattern ||
            normalizedPath.includes(`/${normalizedPattern}`) ||
            normalizedPath.endsWith(`/${normalizedPattern}`)) {
            return true;
        }
        // Simple glob pattern (*)
        if (normalizedPattern.includes('*')) {
            const regex = new RegExp('^' + normalizedPattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
            if (regex.test(normalizedPath)) {
                return true;
            }
        }
    }
    return false;
}
/**
 * Check if a file has a supported extension
 */
function isSupportedExtension(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return SUPPORTED_EXTENSIONS.has(ext);
}
/**
 * Walk a directory tree and find model files
 */
function walkDirectory(rootDir, config) {
    const files = [];
    const absoluteRoot = path.resolve(rootDir);
    function walk(dir) {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        }
        catch (error) {
            // Skip directories we can't read
            return;
        }
        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            const relativePath = path.relative(absoluteRoot, fullPath);
            // Check exclusions
            if (isExcluded(relativePath, config.exclude)) {
                continue;
            }
            if (entry.isDirectory()) {
                // Recurse into subdirectories
                walk(fullPath);
            }
            else if (entry.isFile()) {
                // Check if it's a supported model file
                if (isSupportedExtension(fullPath)) {
                    try {
                        const stats = fs.statSync(fullPath);
                        // Check file size limit
                        if (stats.size > config.maxFileSize) {
                            console.warn(`Skipping ${relativePath}: exceeds max file size (${stats.size} > ${config.maxFileSize})`);
                            continue;
                        }
                        files.push({
                            path: fullPath,
                            name: entry.name,
                            extension: path.extname(fullPath).toLowerCase(),
                            size: stats.size,
                            relativePath,
                        });
                    }
                    catch (error) {
                        // Skip files we can't stat
                        continue;
                    }
                }
            }
        }
    }
    // Walk each include pattern
    for (const includePattern of config.include) {
        const includePath = path.isAbsolute(includePattern)
            ? includePattern
            : path.join(absoluteRoot, includePattern);
        if (fs.existsSync(includePath)) {
            const stats = fs.statSync(includePath);
            if (stats.isDirectory()) {
                walk(includePath);
            }
            else if (stats.isFile() && isSupportedExtension(includePath)) {
                // Single file specified
                const relativePath = path.relative(absoluteRoot, includePath);
                if (!isExcluded(relativePath, config.exclude)) {
                    files.push({
                        path: includePath,
                        name: path.basename(includePath),
                        extension: path.extname(includePath).toLowerCase(),
                        size: stats.size,
                        relativePath,
                    });
                }
            }
        }
    }
    // Sort by path for consistent output
    files.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
    // Check total size limit
    const totalSize = files.reduce((sum, f) => sum + f.size, 0);
    if (totalSize > config.maxTotalSize) {
        console.warn(`Warning: Total size (${totalSize}) exceeds max total size (${config.maxTotalSize})`);
    }
    return files;
}
/**
 * Get the agent type for a file extension
 */
function getAgentType(extension) {
    const ext = extension.toLowerCase();
    switch (ext) {
        case '.pkl':
        case '.pickle':
        case '.pt':
        case '.pth':
        case '.bin':
        case '.joblib':
            return 'pickle';
        case '.h5':
        case '.hdf5':
        case '.keras':
            return 'keras';
        case '.onnx':
            return 'onnx';
        case '.safetensors':
            return 'safetensors';
        case '.gguf':
            return 'gguf';
        default:
            return 'unknown';
    }
}
/**
 * Format file size for display
 */
function formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = bytes;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }
    return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}
//# sourceMappingURL=walker.js.map