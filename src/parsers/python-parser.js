/**
 * Python Parser Agent
 * Parses Python manifest files to extract dependencies (NOT source code)
 */

import fg from 'fast-glob';
import { readFile } from 'fs/promises';
import { relative } from 'path';

export class PythonParser {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
    this.results = {
      manifestFiles: [],
      dependencies: [],
      buildTools: new Set(),
    };
  }

  async analyze() {
    console.log('[Python Parser] Starting Python manifest analysis...');

    await this.findAndParseManifests();

    return this.getResults();
  }

  async findAndParseManifests() {
    // Find all Python manifest files
    await this.parseRequirementsTxt();
    await this.parseSetupPy();
    await this.parsePyprojectToml();
    await this.parsePipfile();
    await this.parsePipfileLock();
    await this.parseSetupCfg();
    await this.parseToxIni();
    await this.parseCondaEnvironment();

    console.log(`[Python Parser] Found ${this.results.manifestFiles.length} manifest files`);
    console.log(`[Python Parser] Extracted ${this.results.dependencies.length} dependencies`);
  }

  async parseRequirementsTxt() {
    const files = await fg([
      '**/requirements.txt',
      '**/requirements-*.txt',
      '**/requirements/*.txt',
      '!**/node_modules/**',
      '!**/__pycache__/**',
      '!**/venv/**',
      '!**/env/**',
      '!**/.venv/**',
    ], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'requirements.txt',
        path: relativePath,
        tool: 'pip',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractRequirementsTxtDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('pip');
    }
  }

  extractRequirementsTxtDeps(content) {
    const deps = [];
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip comments and empty lines
      if (!trimmed || trimmed.startsWith('#')) continue;

      // Skip options like -e, -r, --index-url, etc.
      if (trimmed.startsWith('-')) continue;

      // Parse package==version, package>=version, etc.
      const match = trimmed.match(/^([a-zA-Z0-9_\-\.]+)([<>=!~]+)?([0-9a-zA-Z\.\-\*]+)?/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[3] || 'not specified',
          operator: match[2] || '==',
        });
      }
    }

    return deps;
  }

  async parseSetupPy() {
    const files = await fg(['**/setup.py', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'setup.py',
        path: relativePath,
        tool: 'setuptools',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractSetupPyDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('setuptools');
    }
  }

  extractSetupPyDeps(content) {
    const deps = [];

    // Look for install_requires array
    const installRequiresMatch = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
    if (installRequiresMatch) {
      const requiresContent = installRequiresMatch[1];
      const packageMatches = requiresContent.matchAll(/['"]([^'"]+)['"]/g);

      for (const match of packageMatches) {
        const depString = match[1];
        const parsed = this.parseDependencyString(depString);
        if (parsed) deps.push(parsed);
      }
    }

    // Also check extras_require
    const extrasRequireMatch = content.match(/extras_require\s*=\s*\{([\s\S]*?)\}/);
    if (extrasRequireMatch) {
      const extrasContent = extrasRequireMatch[1];
      const packageMatches = extrasContent.matchAll(/['"]([a-zA-Z0-9_\-\.]+[<>=!~]+[^'"]*)['"]/g);

      for (const match of packageMatches) {
        const depString = match[1];
        const parsed = this.parseDependencyString(depString);
        if (parsed) deps.push({ ...parsed, optional: true });
      }
    }

    return deps;
  }

  async parsePyprojectToml() {
    const files = await fg(['**/pyproject.toml', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'pyproject.toml',
        path: relativePath,
        tool: 'Poetry/PEP 518',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractPyprojectTomlDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('Poetry');
    }
  }

  extractPyprojectTomlDeps(content) {
    const deps = [];

    // Simple TOML parsing for dependencies section
    // Look for [tool.poetry.dependencies] or [project.dependencies]
    const dependenciesSections = [
      /\[tool\.poetry\.dependencies\]([\s\S]*?)(?=\[|$)/,
      /\[project\.dependencies\]([\s\S]*?)(?=\[|$)/,
    ];

    for (const pattern of dependenciesSections) {
      const match = content.match(pattern);
      if (match) {
        const depsSection = match[1];
        const depMatches = depsSection.matchAll(/^([a-zA-Z0-9_\-\.]+)\s*=\s*['"~^]?([^'"]+)['"]/gm);

        for (const depMatch of depMatches) {
          if (depMatch[1] === 'python') continue; // Skip python version requirement

          deps.push({
            name: depMatch[1],
            version: depMatch[2].replace(/['"]/g, ''),
            operator: '==',
          });
        }
      }
    }

    return deps;
  }

  async parsePipfile() {
    const files = await fg(['**/Pipfile', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'Pipfile',
        path: relativePath,
        tool: 'Pipenv',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractPipfileDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('Pipenv');
    }
  }

  extractPipfileDeps(content) {
    const deps = [];

    // Look for [packages] section
    const packagesMatch = content.match(/\[packages\]([\s\S]*?)(?=\[|$)/);
    if (packagesMatch) {
      const packagesSection = packagesMatch[1];
      const depMatches = packagesSection.matchAll(/^([a-zA-Z0-9_\-\.]+)\s*=\s*['"~]?([^'"]+)?['"]/gm);

      for (const match of depMatches) {
        deps.push({
          name: match[1],
          version: match[2] || '*',
          operator: '==',
        });
      }
    }

    return deps;
  }

  async parsePipfileLock() {
    const files = await fg(['**/Pipfile.lock', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'Pipfile.lock',
        path: relativePath,
        tool: 'Pipenv',
      });

      try {
        const content = await readFile(file, 'utf-8');
        const lockData = JSON.parse(content);

        // Extract dependencies from default and develop sections
        const sections = ['default', 'develop'];
        for (const section of sections) {
          if (lockData[section]) {
            Object.entries(lockData[section]).forEach(([name, info]) => {
              this.results.dependencies.push({
                name: name,
                version: info.version ? info.version.replace(/^==/, '') : 'not specified',
                operator: '==',
                source: relativePath,
                dev: section === 'develop',
              });
            });
          }
        }

        this.results.buildTools.add('Pipenv');
      } catch (error) {
        console.error(`[Python Parser] Failed to parse ${relativePath}: ${error.message}`);
      }
    }
  }

  async parseSetupCfg() {
    const files = await fg(['**/setup.cfg', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'setup.cfg',
        path: relativePath,
        tool: 'setuptools',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractSetupCfgDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('setuptools');
    }
  }

  extractSetupCfgDeps(content) {
    const deps = [];

    // Look for [options] install_requires section
    const installRequiresMatch = content.match(/\[options\][\s\S]*?install_requires\s*=([\s\S]*?)(?=\n\[|\n\w+\s*=|$)/);
    if (installRequiresMatch) {
      const requiresContent = installRequiresMatch[1];
      const lines = requiresContent.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const parsed = this.parseDependencyString(trimmed);
        if (parsed) deps.push(parsed);
      }
    }

    return deps;
  }

  async parseToxIni() {
    const files = await fg(['**/tox.ini', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'tox.ini',
        path: relativePath,
        tool: 'tox',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractToxIniDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('tox');
    }
  }

  extractToxIniDeps(content) {
    const deps = [];

    // Look for deps = section in testenv
    const depsMatch = content.match(/\[testenv\][\s\S]*?deps\s*=([\s\S]*?)(?=\n\[|\n\w+\s*=|$)/);
    if (depsMatch) {
      const depsContent = depsMatch[1];
      const lines = depsContent.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const parsed = this.parseDependencyString(trimmed);
        if (parsed) deps.push(parsed);
      }
    }

    return deps;
  }

  async parseCondaEnvironment() {
    const files = await fg([
      '**/environment.yml',
      '**/environment.yaml',
      '**/conda.yml',
      '**/conda.yaml',
      '!**/node_modules/**',
    ], {
      cwd: this.projectRoot,
      absolute: true,
    });

    for (const file of files) {
      const relativePath = relative(this.projectRoot, file);
      this.results.manifestFiles.push({
        type: 'environment.yml',
        path: relativePath,
        tool: 'Conda',
      });

      const content = await readFile(file, 'utf-8');
      const deps = this.extractCondaDeps(content);
      deps.forEach(dep => {
        this.results.dependencies.push({
          ...dep,
          source: relativePath,
        });
      });

      this.results.buildTools.add('Conda');
    }
  }

  extractCondaDeps(content) {
    const deps = [];

    // Simple YAML parsing for dependencies
    const depsMatch = content.match(/dependencies:\s*\n((?:\s+-\s+.+\n?)*)/);
    if (depsMatch) {
      const depsContent = depsMatch[1];
      const lines = depsContent.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('-')) continue;

        const depString = trimmed.substring(1).trim();
        const parsed = this.parseDependencyString(depString);
        if (parsed) deps.push(parsed);
      }
    }

    return deps;
  }

  parseDependencyString(depString) {
    // Parse formats like: package==1.0.0, package>=1.0.0, package~=1.0.0, etc.
    const match = depString.match(/^([a-zA-Z0-9_\-\.]+)([<>=!~]+)?([0-9a-zA-Z\.\-\*]+)?/);
    if (match && match[1]) {
      return {
        name: match[1],
        version: match[3] || 'not specified',
        operator: match[2] || '==',
      };
    }
    return null;
  }

  getResults() {
    // Deduplicate dependencies by name (keep first occurrence)
    const uniqueDeps = [];
    const seenDeps = new Set();

    for (const dep of this.results.dependencies) {
      const key = `${dep.name}@${dep.version}`;
      if (!seenDeps.has(key)) {
        seenDeps.add(key);
        uniqueDeps.push(dep);
      }
    }

    return {
      language: 'python',
      manifestFileCount: this.results.manifestFiles.length,
      manifestFiles: this.results.manifestFiles,
      dependencies: uniqueDeps,
      dependencyCount: uniqueDeps.length,
      buildTools: Array.from(this.results.buildTools),
      summary: {
        totalManifestFiles: this.results.manifestFiles.length,
        totalDependencies: uniqueDeps.length,
        buildTools: Array.from(this.results.buildTools),
        buildTool: this.determineBuildTool(),
      },
    };
  }

  determineBuildTool() {
    const tools = Array.from(this.results.buildTools);

    if (tools.length === 0) return 'none detected';
    if (tools.length === 1) return tools[0];
    return `multiple (${tools.join(', ')})`;
  }
}
