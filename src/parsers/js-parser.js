/**
 * JavaScript Parser Agent
 * Analyzes JavaScript/TypeScript source code and identifies structure
 */

import fg from 'fast-glob';
import { readFile } from 'fs/promises';
import { relative } from 'path';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

export class JavaScriptParser {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
    this.results = {
      files: [],
      modules: [],
      functions: [],
      classes: [],
      imports: new Set(),
      frameworks: new Set(),
      buildFiles: [],
    };
  }

  async analyze() {
    console.log('[JS Parser] Starting JavaScript/TypeScript code analysis...');

    await this.findJSFiles();
    await this.findBuildFiles();
    await this.detectFrameworks();

    return this.getResults();
  }

  async findJSFiles() {
    const jsFiles = await fg([
      '**/*.js',
      '**/*.jsx',
      '**/*.ts',
      '**/*.tsx',
      '**/*.mjs',
      '!**/node_modules/**',
      '!**/dist/**',
      '!**/build/**',
      '!**/.next/**',
      '!**/coverage/**',
    ], {
      cwd: this.projectRoot,
      absolute: true,
    });

    console.log(`[JS Parser] Found ${jsFiles.length} JavaScript/TypeScript files`);

    for (const file of jsFiles) {
      const relativePath = relative(this.projectRoot, file);
      this.results.files.push(relativePath);

      try {
        const content = await readFile(file, 'utf-8');
        await this.parseJSFile(file, content);
      } catch (error) {
        console.warn(`[JS Parser] Failed to parse ${relativePath}: ${error.message}`);
      }
    }
  }

  async parseJSFile(filePath, content) {
    const relativePath = relative(this.projectRoot, filePath);

    try {
      // Parse with acorn (JavaScript parser)
      const ast = acorn.parse(content, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        locations: true,
      });

      const fileAnalysis = {
        file: relativePath,
        functions: [],
        classes: [],
        imports: [],
      };

      walk.simple(ast, {
        FunctionDeclaration(node) {
          fileAnalysis.functions.push({
            name: node.id?.name || 'anonymous',
            line: node.loc.start.line,
          });
        },

        ClassDeclaration(node) {
          fileAnalysis.classes.push({
            name: node.id.name,
            line: node.loc.start.line,
          });
        },

        ImportDeclaration(node) {
          const importPath = node.source.value;
          fileAnalysis.imports.push(importPath);
          this.results.imports.add(importPath);

          // Detect framework imports
          this.detectFrameworkImport(importPath);
        },
      });

      this.results.modules.push(fileAnalysis);
      this.results.functions.push(...fileAnalysis.functions.map(f => ({
        ...f,
        file: relativePath,
      })));
      this.results.classes.push(...fileAnalysis.classes.map(c => ({
        ...c,
        file: relativePath,
      })));

    } catch (error) {
      // If acorn fails (e.g., TypeScript syntax), do basic pattern matching
      this.parseJSFileBasic(relativePath, content);
    }
  }

  parseJSFileBasic(relativePath, content) {
    // Basic pattern matching for TypeScript and complex JS
    const functionMatches = content.matchAll(/(?:function|const|let|var)\s+(\w+)\s*(?:=\s*)?(?:\([^)]*\)|async)/g);
    for (const match of functionMatches) {
      this.results.functions.push({
        name: match[1],
        file: relativePath,
      });
    }

    const classMatches = content.matchAll(/class\s+(\w+)/g);
    for (const match of classMatches) {
      this.results.classes.push({
        name: match[1],
        file: relativePath,
      });
    }

    const importMatches = content.matchAll(/import\s+.*?from\s+['"]([^'"]+)['"]/g);
    for (const match of importMatches) {
      this.results.imports.add(match[1]);
      this.detectFrameworkImport(match[1]);
    }
  }

  detectFrameworkImport(importPath) {
    const frameworks = {
      'react': /^react$/,
      'vue': /^vue$/,
      'angular': /^@angular/,
      'svelte': /^svelte/,
      'next.js': /^next/,
      'express': /^express$/,
      'nest.js': /^@nestjs/,
    };

    for (const [framework, pattern] of Object.entries(frameworks)) {
      if (pattern.test(importPath)) {
        this.results.frameworks.add(framework);
      }
    }
  }

  async findBuildFiles() {
    // npm/yarn
    const packageFiles = await fg(['**/package.json', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    for (const file of packageFiles) {
      const content = await readFile(`${this.projectRoot}/${file}`, 'utf-8');
      const pkg = JSON.parse(content);

      this.results.buildFiles.push({
        type: 'npm',
        file: file,
        tool: 'npm/yarn',
        scripts: pkg.scripts ? Object.keys(pkg.scripts) : [],
        dependencies: pkg.dependencies ? Object.keys(pkg.dependencies) : [],
      });
    }

    // Webpack
    const webpackFiles = await fg(['**/webpack.config.js', '**/webpack.config.ts', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    webpackFiles.forEach(file => {
      this.results.buildFiles.push({
        type: 'webpack',
        file: file,
        tool: 'Webpack',
      });
    });

    // Vite
    const viteFiles = await fg(['**/vite.config.js', '**/vite.config.ts', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    viteFiles.forEach(file => {
      this.results.buildFiles.push({
        type: 'vite',
        file: file,
        tool: 'Vite',
      });
    });

    // Rollup
    const rollupFiles = await fg(['**/rollup.config.js', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    rollupFiles.forEach(file => {
      this.results.buildFiles.push({
        type: 'rollup',
        file: file,
        tool: 'Rollup',
      });
    });

    console.log(`[JS Parser] Found ${this.results.buildFiles.length} build files`);
  }

  async detectFrameworks() {
    // Check package.json dependencies for frameworks
    const packageFiles = this.results.buildFiles.filter(f => f.type === 'npm');

    for (const buildFile of packageFiles) {
      if (buildFile.dependencies) {
        buildFile.dependencies.forEach(dep => {
          this.detectFrameworkImport(dep);
        });
      }
    }

    console.log(`[JS Parser] Detected frameworks: ${Array.from(this.results.frameworks).join(', ')}`);
  }

  getResults() {
    return {
      language: 'javascript',
      fileCount: this.results.files.length,
      files: this.results.files,
      modules: this.results.modules,
      functions: this.results.functions,
      classes: this.results.classes,
      frameworks: Array.from(this.results.frameworks),
      buildFiles: this.results.buildFiles,
      summary: {
        totalFunctions: this.results.functions.length,
        totalClasses: this.results.classes.length,
        totalModules: this.results.modules.length,
        frameworks: Array.from(this.results.frameworks),
        buildTool: this.determineBuildTool(),
      },
    };
  }

  determineBuildTool() {
    const tools = new Set(this.results.buildFiles.map(f => f.tool));
    const toolList = Array.from(tools);

    if (toolList.length === 0) return 'none detected';
    if (toolList.length === 1) return toolList[0];
    return toolList.join(', ');
  }
}
