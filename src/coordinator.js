/**
 * Coordinator Agent
 * Orchestrates all analysis agents and aggregates results
 */

import { JavaParser } from './parsers/java-parser.js';
import { JavaScriptParser } from './parsers/js-parser.js';
import { BuildInfrastructureDetector } from './build-detector.js';

export class Coordinator {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
    this.results = {};
  }

  async analyze() {
    console.log('[Coordinator] Starting project analysis...');
    console.log(`[Coordinator] Project root: ${this.projectRoot}`);
    console.log('');

    const startTime = Date.now();

    // Run all agents in parallel for efficiency
    const [javaResults, jsResults, buildResults] = await Promise.all([
      this.runJavaParser(),
      this.runJSParser(),
      this.runBuildDetector(),
    ]);

    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);

    this.results = {
      projectRoot: this.projectRoot,
      analyzedAt: new Date().toISOString(),
      duration: `${duration}s`,
      languages: {
        java: javaResults,
        javascript: jsResults,
      },
      buildInfrastructure: buildResults,
      summary: this.generateSummary(javaResults, jsResults, buildResults),
    };

    console.log('');
    console.log(`[Coordinator] Analysis complete in ${duration}s`);

    return this.results;
  }

  async runJavaParser() {
    try {
      const parser = new JavaParser(this.projectRoot);
      return await parser.analyze();
    } catch (error) {
      console.error('[Coordinator] Java parser failed:', error.message);
      return { error: error.message };
    }
  }

  async runJSParser() {
    try {
      const parser = new JavaScriptParser(this.projectRoot);
      return await parser.analyze();
    } catch (error) {
      console.error('[Coordinator] JavaScript parser failed:', error.message);
      return { error: error.message };
    }
  }

  async runBuildDetector() {
    try {
      const detector = new BuildInfrastructureDetector(this.projectRoot);
      return await detector.analyze();
    } catch (error) {
      console.error('[Coordinator] Build detector failed:', error.message);
      return { error: error.message };
    }
  }

  generateSummary(javaResults, jsResults, buildResults) {
    const languages = [];
    if (javaResults.fileCount > 0) languages.push('Java');
    if (jsResults.fileCount > 0) languages.push('JavaScript/TypeScript');

    return {
      projectType: this.inferProjectType(javaResults, jsResults, buildResults),
      languages: languages,
      totalFiles: (javaResults.fileCount || 0) + (jsResults.fileCount || 0),
      buildTools: buildResults.summary?.packageManagers || [],
      cicd: buildResults.summary?.cicdTools || [],
      frameworks: jsResults.summary?.frameworks || [],
      hasDocker: buildResults.summary?.hasDocker || false,
    };
  }

  inferProjectType(javaResults, jsResults, buildResults) {
    const hasJava = javaResults.fileCount > 0;
    const hasJS = jsResults.fileCount > 0;

    if (hasJava && hasJS) {
      return 'Full-stack (Java + JavaScript)';
    } else if (hasJava) {
      const frameworks = jsResults.summary?.frameworks || [];
      if (frameworks.includes('next.js') || frameworks.includes('react')) {
        return 'Java Backend + React Frontend';
      }
      return 'Java Application';
    } else if (hasJS) {
      const frameworks = jsResults.summary?.frameworks || [];
      if (frameworks.includes('express') || frameworks.includes('nest.js')) {
        return 'Node.js Backend';
      } else if (frameworks.includes('react') || frameworks.includes('vue') || frameworks.includes('angular')) {
        return 'Frontend Application';
      }
      return 'JavaScript Application';
    }

    return 'Unknown';
  }

  getResults() {
    return this.results;
  }
}
