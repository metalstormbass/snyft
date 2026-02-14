/**
 * Build Infrastructure Agent
 * Detects build tools, CI/CD, and project structure
 */

import fg from 'fast-glob';
import { readFile } from 'fs/promises';
import { relative } from 'path';

export class BuildInfrastructureDetector {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
    this.results = {
      buildTools: [],
      cicd: [],
      dockerfiles: [],
      packageManagers: [],
      configFiles: [],
      projectStructure: {},
    };
  }

  async analyze() {
    console.log('[Build Detector] Analyzing build infrastructure...');

    await this.detectCICD();
    await this.detectDocker();
    await this.detectPackageManagers();
    await this.detectConfigFiles();
    await this.analyzeProjectStructure();

    return this.getResults();
  }

  async detectCICD() {
    // GitHub Actions
    const ghActions = await fg(['.github/workflows/**/*.yml', '.github/workflows/**/*.yaml'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (ghActions.length > 0) {
      this.results.cicd.push({
        type: 'github-actions',
        tool: 'GitHub Actions',
        files: ghActions,
      });
    }

    // GitLab CI
    const gitlabCI = await fg(['.gitlab-ci.yml'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (gitlabCI.length > 0) {
      this.results.cicd.push({
        type: 'gitlab-ci',
        tool: 'GitLab CI',
        files: gitlabCI,
      });
    }

    // Jenkins
    const jenkinsFiles = await fg(['Jenkinsfile', '**/Jenkinsfile'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (jenkinsFiles.length > 0) {
      this.results.cicd.push({
        type: 'jenkins',
        tool: 'Jenkins',
        files: jenkinsFiles,
      });
    }

    // Travis CI
    const travisCI = await fg(['.travis.yml'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (travisCI.length > 0) {
      this.results.cicd.push({
        type: 'travis-ci',
        tool: 'Travis CI',
        files: travisCI,
      });
    }

    // CircleCI
    const circleCI = await fg(['.circleci/config.yml'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (circleCI.length > 0) {
      this.results.cicd.push({
        type: 'circleci',
        tool: 'CircleCI',
        files: circleCI,
      });
    }

    console.log(`[Build Detector] Found ${this.results.cicd.length} CI/CD configurations`);
  }

  async detectDocker() {
    const dockerfiles = await fg(['**/Dockerfile', '**/Dockerfile.*', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    dockerfiles.forEach(file => {
      this.results.dockerfiles.push({
        file: file,
        type: 'dockerfile',
      });
    });

    const dockerCompose = await fg(['**/docker-compose.yml', '**/docker-compose.yaml'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    dockerCompose.forEach(file => {
      this.results.dockerfiles.push({
        file: file,
        type: 'docker-compose',
      });
    });

    console.log(`[Build Detector] Found ${this.results.dockerfiles.length} Docker files`);
  }

  async detectPackageManagers() {
    // Maven
    const pomFiles = await fg(['**/pom.xml', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (pomFiles.length > 0) {
      const manifestData = await this.parseMavenManifests(pomFiles);
      this.results.packageManagers.push({
        type: 'maven',
        tool: 'Apache Maven',
        files: pomFiles,
        language: 'java',
        manifests: manifestData,
      });
    }

    // Gradle
    const gradleFiles = await fg([
      '**/build.gradle',
      '**/build.gradle.kts',
      '**/settings.gradle',
      '**/settings.gradle.kts',
      '!**/node_modules/**'
    ], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (gradleFiles.length > 0) {
      this.results.packageManagers.push({
        type: 'gradle',
        tool: 'Gradle',
        files: gradleFiles,
        language: 'java',
      });
    }

    // Ant
    const antFiles = await fg(['**/build.xml', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (antFiles.length > 0) {
      this.results.packageManagers.push({
        type: 'ant',
        tool: 'Apache Ant',
        files: antFiles,
        language: 'java',
      });
    }

    // Ivy (often used with Ant)
    const ivyFiles = await fg(['**/ivy.xml', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (ivyFiles.length > 0) {
      this.results.packageManagers.push({
        type: 'ivy',
        tool: 'Apache Ivy',
        files: ivyFiles,
        language: 'java',
      });
    }

    // npm/yarn
    const packageJson = await fg(['**/package.json', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (packageJson.length > 0) {
      const manifestData = await this.parseNpmManifests(packageJson);
      this.results.packageManagers.push({
        type: 'npm',
        tool: 'npm/yarn',
        files: packageJson,
        language: 'javascript',
        manifests: manifestData,
      });
    }

    // yarn lock files
    const yarnLock = await fg(['**/yarn.lock'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (yarnLock.length > 0) {
      const existing = this.results.packageManagers.find(pm => pm.type === 'npm');
      if (existing) {
        existing.tool = 'Yarn';
      }
    }

    // pnpm lock files
    const pnpmLock = await fg(['**/pnpm-lock.yaml'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    if (pnpmLock.length > 0) {
      const existing = this.results.packageManagers.find(pm => pm.type === 'npm');
      if (existing) {
        existing.tool = 'pnpm';
      }
    }

    console.log(`[Build Detector] Found ${this.results.packageManagers.length} package managers`);
  }

  async parseMavenManifests(pomFiles) {
    const manifests = [];

    for (const file of pomFiles) {
      try {
        const content = await readFile(`${this.projectRoot}/${file}`, 'utf-8');

        // Extract basic info from pom.xml using regex (lightweight alternative to XML parser)
        const groupId = content.match(/<groupId>(.*?)<\/groupId>/)?.[1];
        const artifactId = content.match(/<artifactId>(.*?)<\/artifactId>/)?.[1];
        const version = content.match(/<version>(.*?)<\/version>/)?.[1];
        const packaging = content.match(/<packaging>(.*?)<\/packaging>/)?.[1] || 'jar';

        // Extract dependencies
        const dependenciesMatch = content.match(/<dependencies>([\s\S]*?)<\/dependencies>/);
        const dependencyCount = dependenciesMatch
          ? (dependenciesMatch[1].match(/<dependency>/g) || []).length
          : 0;

        manifests.push({
          file,
          groupId,
          artifactId,
          version,
          packaging,
          dependencyCount,
        });

        console.log(`[Build Detector] Parsed Maven manifest: ${file} (${artifactId})`);
      } catch (error) {
        console.warn(`[Build Detector] Failed to parse ${file}: ${error.message}`);
      }
    }

    return manifests;
  }

  async parseNpmManifests(packageJsonFiles) {
    const manifests = [];

    for (const file of packageJsonFiles) {
      try {
        const content = await readFile(`${this.projectRoot}/${file}`, 'utf-8');
        const pkg = JSON.parse(content);

        manifests.push({
          file,
          name: pkg.name,
          version: pkg.version,
          description: pkg.description,
          scripts: pkg.scripts ? Object.keys(pkg.scripts) : [],
          dependencies: pkg.dependencies ? Object.keys(pkg.dependencies).length : 0,
          devDependencies: pkg.devDependencies ? Object.keys(pkg.devDependencies).length : 0,
        });

        console.log(`[Build Detector] Parsed npm manifest: ${file} (${pkg.name})`);
      } catch (error) {
        console.warn(`[Build Detector] Failed to parse ${file}: ${error.message}`);
      }
    }

    return manifests;
  }

  async detectConfigFiles() {
    const configPatterns = [
      '**/.eslintrc*',
      '**/.prettierrc*',
      '**/tsconfig.json',
      '**/jsconfig.json',
      '**/.editorconfig',
      '**/.gitignore',
      '**/.gitattributes',
    ];

    const configFiles = await fg(configPatterns, {
      cwd: this.projectRoot,
      absolute: false,
      ignore: ['**/node_modules/**'],
    });

    this.results.configFiles = configFiles;
    console.log(`[Build Detector] Found ${this.results.configFiles.length} configuration files`);
  }

  async analyzeProjectStructure() {
    const allFiles = await fg(['**/*', '!**/node_modules/**', '!**/.git/**'], {
      cwd: this.projectRoot,
      absolute: false,
      onlyFiles: true,
    });

    // Analyze directory structure
    const directories = new Set();
    allFiles.forEach(file => {
      const parts = file.split('/');
      let currentPath = '';
      for (let i = 0; i < parts.length - 1; i++) {
        currentPath += (currentPath ? '/' : '') + parts[i];
        directories.add(currentPath);
      }
    });

    this.results.projectStructure = {
      totalFiles: allFiles.length,
      totalDirectories: directories.size,
      topLevelDirs: this.getTopLevelDirectories(directories),
      sourceStructure: this.inferSourceStructure(directories),
    };
  }

  getTopLevelDirectories(directories) {
    const topLevel = new Set();
    directories.forEach(dir => {
      const topDir = dir.split('/')[0];
      topLevel.add(topDir);
    });
    return Array.from(topLevel);
  }

  inferSourceStructure(directories) {
    const structure = {
      hasSourceDir: false,
      hasTestDir: false,
      hasBuildDir: false,
      hasDocsDir: false,
    };

    const dirArray = Array.from(directories);

    structure.hasSourceDir = dirArray.some(d =>
      d.includes('src') || d.includes('source') || d.includes('lib')
    );

    structure.hasTestDir = dirArray.some(d =>
      d.includes('test') || d.includes('spec') || d.includes('__tests__')
    );

    structure.hasBuildDir = dirArray.some(d =>
      d.includes('build') || d.includes('dist') || d.includes('target') || d.includes('out')
    );

    structure.hasDocsDir = dirArray.some(d =>
      d.includes('docs') || d.includes('documentation')
    );

    return structure;
  }

  getResults() {
    return {
      buildTools: this.results.buildTools,
      cicd: this.results.cicd,
      dockerfiles: this.results.dockerfiles,
      packageManagers: this.results.packageManagers,
      configFiles: this.results.configFiles,
      projectStructure: this.results.projectStructure,
      summary: {
        hasCICD: this.results.cicd.length > 0,
        hasDocker: this.results.dockerfiles.length > 0,
        packageManagers: this.results.packageManagers.map(pm => pm.tool),
        cicdTools: this.results.cicd.map(ci => ci.tool),
      },
    };
  }
}
