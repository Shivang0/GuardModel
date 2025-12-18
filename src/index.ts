/**
 * GuardModel GitHub Action Entry Point
 *
 * Scans ML model files for malicious code, vulnerabilities, and security risks.
 */

import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';

import { loadConfigFromInputs, validateConfig } from './config';
import { walkDirectory, formatSize } from './walker';
import { Orchestrator } from './orchestrator';
import { generateSarifString } from './reporters/sarif';
import { generateMarkdown, generateSummary } from './reporters/markdown';
import { generateJsonString } from './reporters/json';

async function run(): Promise<void> {
  try {
    core.info('🛡️ GuardModel Security Scan');
    core.info('');

    // Get inputs from environment (set by action.yml)
    const inputs: Record<string, string> = {
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
    const config = loadConfigFromInputs(inputs);

    // Validate configuration
    const configErrors = validateConfig(config);
    if (configErrors.length > 0) {
      for (const error of configErrors) {
        core.error(`Configuration error: ${error}`);
      }
      core.setFailed('Invalid configuration');
      return;
    }

    core.info(`  Fail on: ${config.failOn}`);
    core.info(`  Max file size: ${formatSize(config.maxFileSize)}`);
    core.info(`  Allowlist entries: ${config.allowlist.length}`);
    core.info('');

    // Discover model files
    core.info('Discovering model files...');
    const scanPath = path.resolve(inputs.path);
    const files = walkDirectory(scanPath, config);

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
      core.info(`  - ${file.relativePath} (${formatSize(file.size)})`);
    }
    if (files.length > 10) {
      core.info(`  ... and ${files.length - 10} more`);
    }
    core.info('');

    // Run scans
    core.info('Scanning files for security threats...');
    const orchestrator = new Orchestrator(config);
    const results = await orchestrator.scanFiles(files);

    core.info('');
    core.info(`Scan complete in ${(results.durationMs / 1000).toFixed(2)}s`);
    core.info(`  Files scanned: ${results.filesScanned}`);
    core.info(`  Files skipped: ${results.filesSkipped}`);
    core.info(`  Files allowlisted: ${results.filesAllowlisted}`);
    core.info(`  Total findings: ${results.totalFindings}`);
    if (results.critical > 0) core.info(`    Critical: ${results.critical}`);
    if (results.high > 0) core.info(`    High: ${results.high}`);
    if (results.medium > 0) core.info(`    Medium: ${results.medium}`);
    if (results.low > 0) core.info(`    Low: ${results.low}`);
    core.info('');

    // Generate outputs
    const outputDir = process.env.GITHUB_WORKSPACE || '.';

    // Generate SARIF
    if (config.output.sarif) {
      const sarifPath = path.join(outputDir, 'guardmodel-results.sarif');
      const sarif = generateSarifString(results);
      fs.writeFileSync(sarifPath, sarif);
      core.info(`SARIF output written to: ${sarifPath}`);
      core.setOutput('sarif-file', sarifPath);
    }

    // Generate JSON
    if (config.output.json) {
      const jsonPath = path.join(outputDir, 'guardmodel-results.json');
      const json = generateJsonString(results);
      fs.writeFileSync(jsonPath, json);
      core.info(`JSON output written to: ${jsonPath}`);
      core.setOutput('json-file', jsonPath);
    }

    // Post PR comment
    if (config.output.markdown && github.context.eventName === 'pull_request') {
      try {
        await postPRComment(results);
      } catch (error) {
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
    const summary = generateSummary(results);
    core.info('');
    core.info(summary);

    // Add to job summary (only works in GitHub Actions environment)
    try {
      await core.summary
        .addHeading('GuardModel Security Scan')
        .addRaw(generateMarkdown(results))
        .write();
    } catch {
      // Summary not available outside GitHub Actions
    }

    // Set exit status
    if (results.status === 'failed') {
      core.setFailed(`Security scan failed: ${results.totalFindings} threat(s) detected`);
    } else if (results.status === 'error') {
      core.setFailed('Security scan encountered errors');
    }

  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed('An unexpected error occurred');
    }
  }
}

/**
 * Post a comment on the PR with scan results
 */
async function postPRComment(results: import('./orchestrator').AggregatedResults): Promise<void> {
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

  const markdown = generateMarkdown(results);

  // Check for existing comment
  const { data: comments } = await octokit.rest.issues.listComments({
    owner: context.repo.owner,
    repo: context.repo.repo,
    issue_number: context.payload.pull_request.number,
  });

  const existingComment = comments.find(
    comment => comment.body?.includes('🛡️ GuardModel Security Scan')
  );

  if (existingComment) {
    // Update existing comment
    await octokit.rest.issues.updateComment({
      owner: context.repo.owner,
      repo: context.repo.repo,
      comment_id: existingComment.id,
      body: markdown,
    });
    core.info('Updated existing PR comment');
  } else {
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
