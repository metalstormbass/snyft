/**
 * Java Parser Agent
 * Analyzes Java source code and identifies structure
 */

import fg from 'fast-glob';
import { readFile } from 'fs/promises';
import { join, relative } from 'path';

export class JavaParser {
  constructor(projectRoot) {
    this.projectRoot = projectRoot;
    this.results = {
      files: [],
      packages: new Set(),
      classes: [],
      buildFiles: [],
      sourceRoots: new Set(),
    };
  }

  async analyze() {
    console.log('[Java Parser] Starting Java code analysis...');

    await this.findJavaFiles();
    await this.findBuildFiles();
    await this.analyzeSourceStructure();

    return this.getResults();
  }

  async findJavaFiles() {
    const javaFiles = await fg(['**/*.java', '!**/node_modules/**', '!**/target/**', '!**/build/**'], {
      cwd: this.projectRoot,
      absolute: true,
    });

    console.log(`[Java Parser] Found ${javaFiles.length} Java files`);

    for (const file of javaFiles) {
      const relativePath = relative(this.projectRoot, file);
      this.results.files.push(relativePath);

      const content = await readFile(file, 'utf-8');
      await this.parseJavaFile(file, content);
    }
  }

  async parseJavaFile(filePath, content) {
    const relativePath = relative(this.projectRoot, filePath);

    // Extract package declaration
    const packageMatch = content.match(/package\s+([\w.]+);/);
    if (packageMatch) {
      const packageName = packageMatch[1];
      this.results.packages.add(packageName);

      // Infer source root from package and file path
      const expectedPath = packageName.replace(/\./g, '/');
      const sourceRoot = relativePath.replace(new RegExp(`${expectedPath}/[^/]+\\.java$`), '');
      if (sourceRoot) {
        this.results.sourceRoots.add(sourceRoot);
      }
    }

    // Extract class declarations
    const classMatches = content.matchAll(/(?:public\s+)?(?:abstract\s+)?(?:final\s+)?(?:class|interface|enum)\s+(\w+)/g);
    for (const match of classMatches) {
      this.results.classes.push({
        name: match[1],
        file: relativePath,
        package: packageMatch ? packageMatch[1] : null,
        type: this.getClassType(content, match[0]),
      });
    }
  }

  getClassType(content, declaration) {
    if (declaration.includes('interface')) return 'interface';
    if (declaration.includes('enum')) return 'enum';
    if (declaration.includes('abstract')) return 'abstract_class';
    return 'class';
  }

  async findBuildFiles() {
    // Maven
    const pomFiles = await fg(['**/pom.xml', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    pomFiles.forEach(file => {
      this.results.buildFiles.push({
        type: 'maven',
        file: file,
        tool: 'Apache Maven',
      });
    });

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

    gradleFiles.forEach(file => {
      this.results.buildFiles.push({
        type: 'gradle',
        file: file,
        tool: 'Gradle',
      });
    });

    // Ant
    const antFiles = await fg(['**/build.xml', '!**/node_modules/**'], {
      cwd: this.projectRoot,
      absolute: false,
    });

    antFiles.forEach(file => {
      this.results.buildFiles.push({
        type: 'ant',
        file: file,
        tool: 'Apache Ant',
      });
    });

    console.log(`[Java Parser] Found ${this.results.buildFiles.length} build files`);
  }

  async analyzeSourceStructure() {
    const sourceRoots = Array.from(this.results.sourceRoots);

    // Identify common Java source structures
    const commonPatterns = ['src/main/java', 'src/test/java', 'src', 'java'];
    const detectedRoots = sourceRoots.filter(root =>
      commonPatterns.some(pattern => root.includes(pattern))
    );

    console.log(`[Java Parser] Detected source roots: ${detectedRoots.join(', ')}`);
  }

  getResults() {
    return {
      language: 'java',
      fileCount: this.results.files.length,
      files: this.results.files,
      packages: Array.from(this.results.packages),
      classes: this.results.classes,
      buildFiles: this.results.buildFiles,
      sourceRoots: Array.from(this.results.sourceRoots),
      summary: {
        totalClasses: this.results.classes.length,
        totalPackages: this.results.packages.size,
        buildTool: this.determineBuildTool(),
      },
    };
  }

  determineBuildTool() {
    const maven = this.results.buildFiles.find(f => f.type === 'maven');
    const gradle = this.results.buildFiles.find(f => f.type === 'gradle');
    const ant = this.results.buildFiles.find(f => f.type === 'ant');

    const tools = [];
    if (maven) tools.push('Maven');
    if (gradle) tools.push('Gradle');
    if (ant) tools.push('Ant');

    if (tools.length === 0) return 'none detected';
    if (tools.length === 1) return tools[0];
    return `mixed (${tools.join(' & ')})`;
  }
}
