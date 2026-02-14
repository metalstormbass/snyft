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
  .description('Analyze a project directory or specific manifest files')
  .argument('[inputs...]', 'Project directory or manifest files (pom.xml, package.json, build.gradle, etc.)', ['.'])
  .option('-o, --output <dir>', 'Output directory for reports')
  .option('-f, --format <format>', 'Output format (console, json, markdown, all)', 'console')
  .action(async (inputs, options) => {
    try {
      // Determine if inputs are manifest files or a directory
      const manifestFiles = [];
      let projectRoot = null;

      for (const input of inputs) {
        const resolvedPath = resolve(input);
        const inputStat = await import('fs/promises').then(fs => fs.stat(resolvedPath).catch(() => null));

        if (!inputStat) {
          console.error(`❌ Error: Path not found: ${input}`);
          process.exit(1);
        }

        if (inputStat.isDirectory()) {
          projectRoot = resolvedPath;
        } else if (inputStat.isFile()) {
          manifestFiles.push(resolvedPath);
        }
      }

      // If manifest files provided, analyze them directly
      if (manifestFiles.length > 0) {
        console.log(`🔍 Analyzing ${manifestFiles.length} manifest file(s):\n`);
        manifestFiles.forEach(f => console.log(`   - ${f}`));
        console.log('');

        const { ManifestAnalyzer } = await import('./manifest-analyzer.js');
        const analyzer = new ManifestAnalyzer(manifestFiles);
        const results = await analyzer.analyze();

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
      }
      // Otherwise, analyze directory
      else {
        const root = projectRoot || resolve('.');
        console.log(`🔍 Analyzing project at: ${root}\n`);

        // Run coordinator
        const coordinator = new Coordinator(root);
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
