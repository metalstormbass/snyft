/**
 * Manifest Analyzer
 * Analyzes specific manifest files (pom.xml, package.json, build.gradle, etc.)
 */

import { readFile } from 'fs/promises';
import { dirname, basename, resolve } from 'path';

export class ManifestAnalyzer {
  constructor(manifestFiles) {
    this.manifestFiles = manifestFiles;
    this.results = {
      manifestCount: manifestFiles.length,
      manifests: [],
      languages: {
        java: {
          fileCount: 0,
          manifests: [],
          packages: [],
          sourceRoots: [],
          summary: {
            totalPackages: 0,
            totalClasses: 0,
            buildTool: 'Unknown',
          },
        },
        javascript: {
          fileCount: 0,
          manifests: [],
          summary: {
            totalFunctions: 0,
            totalClasses: 0,
            totalModules: 0,
            frameworks: [],
            buildTool: 'Unknown',
          },
        },
      },
      buildInfrastructure: {
        packageManagers: [],
        projectStructure: null,
        summary: {
          packageManagers: [],
        },
      },
      summary: {},
    };
  }

  async analyze() {
    console.log('[Manifest Analyzer] Analyzing manifest files...');
    console.log('');

    const startTime = Date.now();

    for (const manifestPath of this.manifestFiles) {
      await this.analyzeManifest(manifestPath);
    }

    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);

    this.results.analyzedAt = new Date().toISOString();
    this.results.duration = `${duration}s`;
    this.results.summary = this.generateSummary();

    console.log('');
    console.log(`[Manifest Analyzer] Analysis complete in ${duration}s`);

    return this.results;
  }

  async analyzeManifest(manifestPath) {
    const fileName = basename(manifestPath);
    const projectRoot = dirname(manifestPath);

    console.log(`[Manifest Analyzer] Analyzing: ${fileName}`);

    try {
      let manifestData = null;

      // Maven pom.xml
      if (fileName === 'pom.xml') {
        manifestData = await this.parseMavenManifest(manifestPath);
        manifestData.type = 'maven';
        manifestData.language = 'java';
        this.results.languages.java.fileCount++;
        this.results.languages.java.manifests.push(manifestData);

        // Add to package managers
        const existing = this.results.buildInfrastructure.packageManagers.find(
          pm => pm.type === 'maven'
        );
        if (!existing) {
          this.results.buildInfrastructure.packageManagers.push({
            type: 'maven',
            tool: 'Apache Maven',
            files: [manifestPath],
            language: 'java',
            manifests: [manifestData],
          });
        } else {
          existing.files.push(manifestPath);
          existing.manifests.push(manifestData);
        }
      }
      // Gradle build files
      else if (
        fileName === 'build.gradle' ||
        fileName === 'build.gradle.kts' ||
        fileName === 'settings.gradle' ||
        fileName === 'settings.gradle.kts'
      ) {
        manifestData = await this.parseGradleManifest(manifestPath);
        manifestData.type = 'gradle';
        manifestData.language = 'java';
        this.results.languages.java.fileCount++;
        this.results.languages.java.manifests.push(manifestData);

        const existing = this.results.buildInfrastructure.packageManagers.find(
          pm => pm.type === 'gradle'
        );
        if (!existing) {
          this.results.buildInfrastructure.packageManagers.push({
            type: 'gradle',
            tool: 'Gradle',
            files: [manifestPath],
            language: 'java',
            manifests: [manifestData],
          });
        } else {
          existing.files.push(manifestPath);
          existing.manifests.push(manifestData);
        }
      }
      // Ant build.xml
      else if (fileName === 'build.xml') {
        manifestData = await this.parseAntManifest(manifestPath);
        manifestData.type = 'ant';
        manifestData.language = 'java';
        this.results.languages.java.fileCount++;
        this.results.languages.java.manifests.push(manifestData);

        const existing = this.results.buildInfrastructure.packageManagers.find(
          pm => pm.type === 'ant'
        );
        if (!existing) {
          this.results.buildInfrastructure.packageManagers.push({
            type: 'ant',
            tool: 'Apache Ant',
            files: [manifestPath],
            language: 'java',
            manifests: [manifestData],
          });
        } else {
          existing.files.push(manifestPath);
          existing.manifests.push(manifestData);
        }
      }
      // npm/yarn package.json
      else if (fileName === 'package.json') {
        manifestData = await this.parseNpmManifest(manifestPath);
        manifestData.type = 'npm';
        manifestData.language = 'javascript';
        this.results.languages.javascript.fileCount++;
        this.results.languages.javascript.manifests.push(manifestData);

        const existing = this.results.buildInfrastructure.packageManagers.find(
          pm => pm.type === 'npm'
        );
        if (!existing) {
          this.results.buildInfrastructure.packageManagers.push({
            type: 'npm',
            tool: 'npm/yarn',
            files: [manifestPath],
            language: 'javascript',
            manifests: [manifestData],
          });
        } else {
          existing.files.push(manifestPath);
          existing.manifests.push(manifestData);
        }
      }
      // Ivy ivy.xml
      else if (fileName === 'ivy.xml') {
        manifestData = await this.parseIvyManifest(manifestPath);
        manifestData.type = 'ivy';
        manifestData.language = 'java';
        this.results.languages.java.fileCount++;
        this.results.languages.java.manifests.push(manifestData);

        const existing = this.results.buildInfrastructure.packageManagers.find(
          pm => pm.type === 'ivy'
        );
        if (!existing) {
          this.results.buildInfrastructure.packageManagers.push({
            type: 'ivy',
            tool: 'Apache Ivy',
            files: [manifestPath],
            language: 'java',
            manifests: [manifestData],
          });
        } else {
          existing.files.push(manifestPath);
          existing.manifests.push(manifestData);
        }
      } else {
        console.warn(`[Manifest Analyzer] Unknown manifest type: ${fileName}`);
        return;
      }

      manifestData.file = manifestPath;
      manifestData.projectRoot = projectRoot;
      this.results.manifests.push(manifestData);

      console.log(`[Manifest Analyzer] ✓ Parsed ${manifestData.type}: ${manifestData.name || manifestData.artifactId || 'unknown'}`);
    } catch (error) {
      console.error(`[Manifest Analyzer] ✗ Failed to parse ${fileName}: ${error.message}`);
    }
  }

  async parseMavenManifest(filePath) {
    const content = await readFile(filePath, 'utf-8');

    // Extract basic info from pom.xml using regex
    const groupId = content.match(/<groupId>(.*?)<\/groupId>/)?.[1];
    const artifactId = content.match(/<artifactId>(.*?)<\/artifactId>/)?.[1];
    const version = content.match(/<version>(.*?)<\/version>/)?.[1];
    const packaging = content.match(/<packaging>(.*?)<\/packaging>/)?.[1] || 'jar';
    const name = content.match(/<name>(.*?)<\/name>/)?.[1];
    const description = content.match(/<description>(.*?)<\/description>/)?.[1];

    // Extract dependencies
    const dependenciesMatch = content.match(/<dependencies>([\s\S]*?)<\/dependencies>/);
    const dependencyCount = dependenciesMatch
      ? (dependenciesMatch[1].match(/<dependency>/g) || []).length
      : 0;

    // Extract plugins
    const pluginsMatch = content.match(/<plugins>([\s\S]*?)<\/plugins>/);
    const pluginCount = pluginsMatch
      ? (pluginsMatch[1].match(/<plugin>/g) || []).length
      : 0;

    return {
      groupId,
      artifactId,
      version,
      packaging,
      name,
      description,
      dependencyCount,
      pluginCount,
    };
  }

  async parseGradleManifest(filePath) {
    const content = await readFile(filePath, 'utf-8');
    const fileName = basename(filePath);

    // Basic Gradle parsing (this is simplified - full parsing would need a proper parser)
    const hasJava = content.includes('java') || content.includes('java-library');
    const hasSpringBoot = content.includes('org.springframework.boot');
    const hasKotlin = content.includes('kotlin');

    // Try to extract dependencies (simplified)
    const dependenciesMatch = content.match(/dependencies\s*\{([\s\S]*?)\}/);
    const dependencyCount = dependenciesMatch
      ? (dependenciesMatch[1].match(/implementation|api|compile/g) || []).length
      : 0;

    return {
      fileName,
      hasJava,
      hasSpringBoot,
      hasKotlin,
      dependencyCount,
      name: fileName,
    };
  }

  async parseAntManifest(filePath) {
    const content = await readFile(filePath, 'utf-8');

    // Extract project name
    const nameMatch = content.match(/<project[^>]+name="([^"]+)"/);
    const name = nameMatch ? nameMatch[1] : 'unknown';

    // Extract default target
    const defaultMatch = content.match(/<project[^>]+default="([^"]+)"/);
    const defaultTarget = defaultMatch ? defaultMatch[1] : null;

    // Count targets
    const targetCount = (content.match(/<target/g) || []).length;

    return {
      name,
      defaultTarget,
      targetCount,
    };
  }

  async parseNpmManifest(filePath) {
    const content = await readFile(filePath, 'utf-8');
    const pkg = JSON.parse(content);

    return {
      name: pkg.name,
      version: pkg.version,
      description: pkg.description,
      main: pkg.main,
      scripts: pkg.scripts ? Object.keys(pkg.scripts) : [],
      dependencies: pkg.dependencies ? Object.keys(pkg.dependencies) : [],
      devDependencies: pkg.devDependencies ? Object.keys(pkg.devDependencies) : [],
      dependencyCount: pkg.dependencies ? Object.keys(pkg.dependencies).length : 0,
      devDependencyCount: pkg.devDependencies ? Object.keys(pkg.devDependencies).length : 0,
    };
  }

  async parseIvyManifest(filePath) {
    const content = await readFile(filePath, 'utf-8');

    // Extract module info
    const moduleMatch = content.match(/<info[^>]+organisation="([^"]+)"[^>]+module="([^"]+)"/);
    const organisation = moduleMatch ? moduleMatch[1] : null;
    const module = moduleMatch ? moduleMatch[2] : null;

    // Count dependencies
    const dependencyCount = (content.match(/<dependency/g) || []).length;

    return {
      organisation,
      module,
      name: module || 'unknown',
      dependencyCount,
    };
  }

  generateSummary() {
    const languages = [];
    if (this.results.languages.java.fileCount > 0) {
      languages.push('Java');
      // Populate Java summary
      const javaManifests = this.results.languages.java.manifests;
      this.results.languages.java.summary.buildTool = javaManifests[0]?.type || 'Unknown';
      this.results.languages.java.summary.totalPackages = javaManifests.length;
    }
    if (this.results.languages.javascript.fileCount > 0) {
      languages.push('JavaScript/TypeScript');
      // Populate JavaScript summary
      const jsManifests = this.results.languages.javascript.manifests;
      this.results.languages.javascript.summary.buildTool = 'npm';
      this.results.languages.javascript.summary.totalModules = jsManifests.length;

      // Extract frameworks from package.json dependencies
      const frameworks = new Set();
      jsManifests.forEach(manifest => {
        if (manifest.dependencies) {
          manifest.dependencies.forEach(dep => {
            if (dep.includes('react')) frameworks.add('react');
            if (dep.includes('vue')) frameworks.add('vue');
            if (dep.includes('angular')) frameworks.add('angular');
            if (dep.includes('express')) frameworks.add('express');
            if (dep.includes('next')) frameworks.add('next.js');
            if (dep.includes('nest')) frameworks.add('nest.js');
          });
        }
      });
      this.results.languages.javascript.summary.frameworks = Array.from(frameworks);
    }

    return {
      projectType: this.inferProjectType(),
      languages: languages,
      totalFiles: this.results.manifestCount,
      totalManifests: this.results.manifestCount,
      buildTools: this.results.buildInfrastructure.packageManagers.map(pm => pm.tool),
      cicd: [],
      hasDocker: false,
    };
  }

  inferProjectType() {
    const hasJava = this.results.languages.java.fileCount > 0;
    const hasJS = this.results.languages.javascript.fileCount > 0;

    if (hasJava && hasJS) {
      return 'Full-stack (Java + JavaScript)';
    } else if (hasJava) {
      return 'Java Application';
    } else if (hasJS) {
      return 'JavaScript Application';
    }

    return 'Unknown';
  }
}
