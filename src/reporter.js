/**
 * Reporter Agent
 * Generates reports from analysis results
 */

import { writeFile } from 'fs/promises';
import { join } from 'path';

export class Reporter {
  constructor(results) {
    this.results = results;
  }

  generateConsoleReport() {
    const { summary, languages, buildInfrastructure } = this.results;

    console.log('\n' + '='.repeat(60));
    console.log('📊 SNYFT PROJECT ANALYSIS REPORT');
    console.log('='.repeat(60));
    console.log('');

    // Project Overview
    console.log('📁 PROJECT OVERVIEW');
    console.log(`   Type: ${summary.projectType}`);
    console.log(`   Languages: ${summary.languages.join(', ')}`);
    console.log(`   Total Files: ${summary.totalFiles}`);
    console.log('');

    // Java Analysis
    if (languages.java && languages.java.fileCount > 0) {
      console.log('☕ JAVA ANALYSIS');
      console.log(`   Files: ${languages.java.fileCount}`);
      console.log(`   Packages: ${languages.java.summary.totalPackages}`);
      console.log(`   Classes: ${languages.java.summary.totalClasses}`);
      console.log(`   Build Tool: ${languages.java.summary.buildTool}`);
      if (languages.java.sourceRoots.length > 0) {
        console.log(`   Source Roots: ${languages.java.sourceRoots.join(', ')}`);
      }
      console.log('');
    }

    // JavaScript Analysis
    if (languages.javascript && languages.javascript.fileCount > 0) {
      console.log('🟨 JAVASCRIPT/TYPESCRIPT ANALYSIS');
      console.log(`   Files: ${languages.javascript.fileCount}`);
      console.log(`   Functions: ${languages.javascript.summary.totalFunctions}`);
      console.log(`   Classes: ${languages.javascript.summary.totalClasses}`);
      console.log(`   Modules: ${languages.javascript.summary.totalModules}`);
      if (languages.javascript.summary.frameworks.length > 0) {
        console.log(`   Frameworks: ${languages.javascript.summary.frameworks.join(', ')}`);
      }
      console.log(`   Build Tool: ${languages.javascript.summary.buildTool}`);
      console.log('');
    }

    // Build Infrastructure
    console.log('🏗️  BUILD INFRASTRUCTURE');
    if (summary.buildTools.length > 0) {
      console.log(`   Package Managers: ${summary.buildTools.join(', ')}`);
    }
    if (summary.cicd.length > 0) {
      console.log(`   CI/CD: ${summary.cicd.join(', ')}`);
    }
    console.log(`   Docker: ${summary.hasDocker ? 'Yes' : 'No'}`);
    console.log('');

    // Project Structure
    if (buildInfrastructure.projectStructure) {
      console.log('📂 PROJECT STRUCTURE');
      const struct = buildInfrastructure.projectStructure;
      console.log(`   Total Directories: ${struct.totalDirectories}`);
      console.log(`   Source Directory: ${struct.sourceStructure.hasSourceDir ? 'Yes' : 'No'}`);
      console.log(`   Test Directory: ${struct.sourceStructure.hasTestDir ? 'Yes' : 'No'}`);
      console.log(`   Build Directory: ${struct.sourceStructure.hasBuildDir ? 'Yes' : 'No'}`);
      console.log('');
    }

    console.log('='.repeat(60));
    console.log(`✅ Analysis completed in ${this.results.duration}`);
    console.log('='.repeat(60));
    console.log('');
  }

  generateJSONReport() {
    return JSON.stringify(this.results, null, 2);
  }

  generateMarkdownReport() {
    const { summary, languages, buildInfrastructure } = this.results;

    let md = '# Snyft Project Analysis Report\n\n';
    md += `**Analyzed:** ${this.results.analyzedAt}\n\n`;
    md += `**Duration:** ${this.results.duration}\n\n`;

    // Project Overview
    md += '## 📁 Project Overview\n\n';
    md += `- **Type:** ${summary.projectType}\n`;
    md += `- **Languages:** ${summary.languages.join(', ')}\n`;
    md += `- **Total Files:** ${summary.totalFiles}\n\n`;

    // Java Analysis
    if (languages.java && languages.java.fileCount > 0) {
      md += '## ☕ Java Analysis\n\n';
      md += `- **Files:** ${languages.java.fileCount}\n`;
      md += `- **Packages:** ${languages.java.summary.totalPackages}\n`;
      md += `- **Classes:** ${languages.java.summary.totalClasses}\n`;
      md += `- **Build Tool:** ${languages.java.summary.buildTool}\n\n`;

      if (languages.java.packages.length > 0) {
        md += '### Packages\n\n';
        languages.java.packages.slice(0, 20).forEach(pkg => {
          md += `- \`${pkg}\`\n`;
        });
        if (languages.java.packages.length > 20) {
          md += `- ... and ${languages.java.packages.length - 20} more\n`;
        }
        md += '\n';
      }
    }

    // JavaScript Analysis
    if (languages.javascript && languages.javascript.fileCount > 0) {
      md += '## 🟨 JavaScript/TypeScript Analysis\n\n';
      md += `- **Files:** ${languages.javascript.fileCount}\n`;
      md += `- **Functions:** ${languages.javascript.summary.totalFunctions}\n`;
      md += `- **Classes:** ${languages.javascript.summary.totalClasses}\n`;
      md += `- **Modules:** ${languages.javascript.summary.totalModules}\n`;
      if (languages.javascript.summary.frameworks.length > 0) {
        md += `- **Frameworks:** ${languages.javascript.summary.frameworks.join(', ')}\n`;
      }
      md += `- **Build Tool:** ${languages.javascript.summary.buildTool}\n\n`;
    }

    // Build Infrastructure
    md += '## 🏗️ Build Infrastructure\n\n';
    if (summary.buildTools.length > 0) {
      md += `- **Package Managers:** ${summary.buildTools.join(', ')}\n`;
    }
    if (summary.cicd.length > 0) {
      md += `- **CI/CD:** ${summary.cicd.join(', ')}\n`;
    }
    md += `- **Docker:** ${summary.hasDocker ? 'Yes' : 'No'}\n\n`;

    // Configuration Files
    if (buildInfrastructure.configFiles && buildInfrastructure.configFiles.length > 0) {
      md += '### Configuration Files\n\n';
      buildInfrastructure.configFiles.slice(0, 10).forEach(file => {
        md += `- \`${file}\`\n`;
      });
      if (buildInfrastructure.configFiles.length > 10) {
        md += `- ... and ${buildInfrastructure.configFiles.length - 10} more\n`;
      }
      md += '\n';
    }

    return md;
  }

  async saveReports(outputDir) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

    // Save JSON report
    const jsonPath = join(outputDir, `snyft-report-${timestamp}.json`);
    await writeFile(jsonPath, this.generateJSONReport());
    console.log(`📄 JSON report saved: ${jsonPath}`);

    // Save Markdown report
    const mdPath = join(outputDir, `snyft-report-${timestamp}.md`);
    await writeFile(mdPath, this.generateMarkdownReport());
    console.log(`📄 Markdown report saved: ${mdPath}`);

    return { jsonPath, mdPath };
  }
}
