#!/usr/bin/env node

/**
 * Snyft CLI
 * Command-line interface for the Snyft code analysis tool
 */

import { Command } from 'commander';
import { Coordinator } from './coordinator.js';
import { Reporter } from './reporter.js';
import { resolve } from 'path';
import { readFile } from 'fs/promises';

const program = new Command();

// Read package.json for version
const packageJson = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf-8')
);

program
  .name('snyft')
  .description('Multi-agent code analysis tool for Java and JavaScript projects')
  .version(packageJson.version);

program
  .command('analyze')
  .description('Analyze a project directory')
  .argument('[path]', 'Project directory to analyze', '.')
  .option('-o, --output <dir>', 'Output directory for reports')
  .option('-f, --format <format>', 'Output format (console, json, markdown, all)', 'console')
  .action(async (path, options) => {
    try {
      const projectRoot = resolve(path);
      console.log(`🔍 Analyzing project at: ${projectRoot}\n`);

      // Run coordinator
      const coordinator = new Coordinator(projectRoot);
      const results = await coordinator.analyze();

      // Generate reports
      const reporter = new Reporter(results);

      if (options.format === 'console' || options.format === 'all') {
        reporter.generateConsoleReport();
      }

      if (options.format === 'json') {
        console.log(reporter.generateJSONReport());
      }

      if (options.format === 'markdown') {
        console.log(reporter.generateMarkdownReport());
      }

      if (options.output) {
        await reporter.saveReports(resolve(options.output));
      }

    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('multiclaude')
  .description('Run analysis using multiclaude multi-agent mode')
  .argument('[path]', 'Project directory to analyze', '.')
  .action(async (path) => {
    console.log('🤖 Multiclaude multi-agent mode');
    console.log('');
    console.log('To run with multiclaude, use:');
    console.log('');
    console.log('  # Start multiclaude daemon');
    console.log('  multiclaude daemon start');
    console.log('');
    console.log('  # Spawn worker agents');
    console.log('  multiclaude worker create "Analyze Java code in project"');
    console.log('  multiclaude worker create "Analyze JavaScript code in project"');
    console.log('  multiclaude worker create "Detect build infrastructure"');
    console.log('');
    console.log('For now, running standard analysis...\n');

    const projectRoot = resolve(path);
    const coordinator = new Coordinator(projectRoot);
    const results = await coordinator.analyze();
    const reporter = new Reporter(results);
    reporter.generateConsoleReport();
  });

program.parse();
