"use strict";
/**
 * GuardModel GitHub Action Entry Point
 *
 * Scans ML model files for malicious code, vulnerabilities, and security risks.
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
const core = __importStar(require("@actions/core"));
const github = __importStar(require("@actions/github"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const config_1 = require("./config");
const walker_1 = require("./walker");
const orchestrator_1 = require("./orchestrator");
const sarif_1 = require("./reporters/sarif");
const markdown_1 = require("./reporters/markdown");
const json_1 = require("./reporters/json");
async function run() {
    try {
        core.info('🛡️ GuardModel Security Scan');
        core.info('');
        // Get inputs from environment (set by action.yml)
        const inputs = {
            path: process.env.INPUT_PATH || '.',
            config: process.env.INPUT_CONFIG || '.guardmodel.yml',
            'fail-on': process.env.INPUT_FAIL_ON || 'high',
            'output-sarif': process.env.INPUT_OUTPUT_SARIF || 'true',
            'output-json': process.env.INPUT_OUTPUT_JSON || 'true',
            'comment-on-pr': process.env.INPUT_COMMENT_ON_PR || 'true',
            'max-file-size': process.env.INPUT_MAX_FILE_SIZE || '5GB',
        };
        // Load configuration
        core.info('Loading configuration...');
        const config = (0, config_1.loadConfigFromInputs)(inputs);
        // Validate configuration
        const configErrors = (0, config_1.validateConfig)(config);
        if (configErrors.length > 0) {
            for (const error of configErrors) {
                core.error(`Configuration error: ${error}`);
            }
            core.setFailed('Invalid configuration');
            return;
        }
        core.info(`  Fail on: ${config.failOn}`);
        core.info(`  Max file size: ${(0, walker_1.formatSize)(config.maxFileSize)}`);
        core.info(`  Allowlist entries: ${config.allowlist.length}`);
        core.info('');
        // Discover model files
        core.info('Discovering model files...');
        const scanPath = path.resolve(inputs.path);
        const files = (0, walker_1.walkDirectory)(scanPath, config);
        if (files.length === 0) {
            core.info('No model files found to scan.');
            core.setOutput('status', 'passed');
            core.setOutput('findings-count', '0');
            core.setOutput('critical-count', '0');
            core.setOutput('high-count', '0');
            core.setOutput('medium-count', '0');
            core.setOutput('low-count', '0');
            core.setOutput('scan-duration', '0');
            return;
        }
        core.info(`Found ${files.length} model file(s) to scan:`);
        for (const file of files.slice(0, 10)) {
            core.info(`  - ${file.relativePath} (${(0, walker_1.formatSize)(file.size)})`);
        }
        if (files.length > 10) {
            core.info(`  ... and ${files.length - 10} more`);
        }
        core.info('');
        // Run scans
        core.info('Scanning files for security threats...');
        const orchestrator = new orchestrator_1.Orchestrator(config);
        const results = await orchestrator.scanFiles(files);
        core.info('');
        core.info(`Scan complete in ${(results.durationMs / 1000).toFixed(2)}s`);
        core.info(`  Files scanned: ${results.filesScanned}`);
        core.info(`  Files skipped: ${results.filesSkipped}`);
        core.info(`  Files allowlisted: ${results.filesAllowlisted}`);
        core.info(`  Total findings: ${results.totalFindings}`);
        if (results.critical > 0)
            core.info(`    Critical: ${results.critical}`);
        if (results.high > 0)
            core.info(`    High: ${results.high}`);
        if (results.medium > 0)
            core.info(`    Medium: ${results.medium}`);
        if (results.low > 0)
            core.info(`    Low: ${results.low}`);
        core.info('');
        // Generate outputs
        const outputDir = process.env.GITHUB_WORKSPACE || '.';
        // Generate SARIF
        if (config.output.sarif) {
            const sarifPath = path.join(outputDir, 'guardmodel-results.sarif');
            const sarif = (0, sarif_1.generateSarifString)(results);
            fs.writeFileSync(sarifPath, sarif);
            core.info(`SARIF output written to: ${sarifPath}`);
            core.setOutput('sarif-file', sarifPath);
        }
        // Generate JSON
        if (config.output.json) {
            const jsonPath = path.join(outputDir, 'guardmodel-results.json');
            const json = (0, json_1.generateJsonString)(results);
            fs.writeFileSync(jsonPath, json);
            core.info(`JSON output written to: ${jsonPath}`);
            core.setOutput('json-file', jsonPath);
        }
        // Post PR comment
        if (config.output.markdown && github.context.eventName === 'pull_request') {
            try {
                await postPRComment(results);
            }
            catch (error) {
                core.warning(`Failed to post PR comment: ${error}`);
            }
        }
        // Set outputs
        core.setOutput('status', results.status);
        core.setOutput('findings-count', results.totalFindings.toString());
        core.setOutput('critical-count', results.critical.toString());
        core.setOutput('high-count', results.high.toString());
        core.setOutput('medium-count', results.medium.toString());
        core.setOutput('low-count', results.low.toString());
        core.setOutput('scan-duration', results.durationMs.toString());
        // Set summary
        const summary = (0, markdown_1.generateSummary)(results);
        core.info('');
        core.info(summary);
        // Add to job summary (only works in GitHub Actions environment)
        try {
            await core.summary
                .addHeading('GuardModel Security Scan')
                .addRaw((0, markdown_1.generateMarkdown)(results))
                .write();
        }
        catch {
            // Summary not available outside GitHub Actions
        }
        // Set exit status
        if (results.status === 'failed') {
            core.setFailed(`Security scan failed: ${results.totalFindings} threat(s) detected`);
        }
        else if (results.status === 'error') {
            core.setFailed('Security scan encountered errors');
        }
    }
    catch (error) {
        if (error instanceof Error) {
            core.setFailed(error.message);
        }
        else {
            core.setFailed('An unexpected error occurred');
        }
    }
}
/**
 * Post a comment on the PR with scan results
 */
async function postPRComment(results) {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
        core.warning('GITHUB_TOKEN not available, skipping PR comment');
        return;
    }
    const octokit = github.getOctokit(token);
    const context = github.context;
    if (!context.payload.pull_request) {
        return;
    }
    const markdown = (0, markdown_1.generateMarkdown)(results);
    // Check for existing comment
    const { data: comments } = await octokit.rest.issues.listComments({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.payload.pull_request.number,
    });
    const existingComment = comments.find(comment => comment.body?.includes('🛡️ GuardModel Security Scan'));
    if (existingComment) {
        // Update existing comment
        await octokit.rest.issues.updateComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            comment_id: existingComment.id,
            body: markdown,
        });
        core.info('Updated existing PR comment');
    }
    else {
        // Create new comment
        await octokit.rest.issues.createComment({
            owner: context.repo.owner,
            repo: context.repo.repo,
            issue_number: context.payload.pull_request.number,
            body: markdown,
        });
        core.info('Created PR comment');
    }
}
// Run the action
run();
//# sourceMappingURL=index.js.map