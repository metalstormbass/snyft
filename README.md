# Snyft

**S**ource code a**n**alyzer **y**ielding **f**ull **t**axonomy

A multi-agent code analysis tool that parses Java and JavaScript projects to locate source code and build infrastructure.

## Features

- 🔍 **Multi-Language Parsing**: Analyzes Java and JavaScript/TypeScript codebases
- 🏗️ **Build Infrastructure Detection**: Identifies Maven, Gradle, npm, webpack, and more
- 🤖 **Multi-Agent Architecture**: Uses multiclaude for distributed, parallel analysis
- 📊 **Comprehensive Reports**: Generates JSON, Markdown, and console reports
- ⚡ **Fast & Efficient**: Parallel processing with specialized agents
- 🐳 **CI/CD Detection**: Finds GitHub Actions, GitLab CI, Jenkins configurations

## Architecture

Snyft uses a multi-agent approach with specialized agents:

1. **Java Parser Agent** - Scans and parses Java source code
2. **JavaScript Parser Agent** - Analyzes JavaScript/TypeScript files
3. **Build Infrastructure Agent** - Detects build tools and CI/CD
4. **Coordinator Agent** - Orchestrates the analysis workflow
5. **Reporter Agent** - Generates formatted reports

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed design.

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd snyft

# Install dependencies
npm install

# Make CLI executable
chmod +x src/cli.js

# Optional: Link for global use
npm link
```

## Usage

### Basic Analysis

```bash
# Analyze current directory
snyft analyze

# Analyze specific directory
snyft analyze /path/to/project

# Save reports to file
snyft analyze /path/to/project --output ./reports

# Output as JSON
snyft analyze --format json

# Output as Markdown
snyft analyze --format markdown
```

### Multi-Agent Mode with Multiclaude

For large projects, use multiclaude's multi-agent system for parallel analysis:

```bash
# Start multiclaude daemon
multiclaude daemon start

# Spawn worker agents
multiclaude worker create "Analyze Java code in project"
multiclaude worker create "Analyze JavaScript code in project"
multiclaude worker create "Detect build infrastructure"

# Check worker status
multiclaude worker list

# View logs
multiclaude logs <agent-name> -f
```

See [multiclaude-agents.md](./multiclaude-agents.md) for detailed multi-agent setup.

## What It Detects

### Java Analysis
- ☕ Source files (`.java`)
- 📦 Package structure
- 🏛️ Classes, interfaces, enums
- 🔨 Build tools (Maven, Gradle)
- 📂 Source directory structure

### JavaScript/TypeScript Analysis
- 🟨 Source files (`.js`, `.jsx`, `.ts`, `.tsx`)
- 📦 Modules and imports
- ⚡ Functions and classes
- 🎨 Frameworks (React, Vue, Angular, Next.js, Express, Nest.js)
- 🔧 Build tools (npm, yarn, pnpm, webpack, vite, rollup)

### Build Infrastructure
- 🏗️ Package managers (Maven, Gradle, npm, yarn, pnpm)
- 🔄 CI/CD (GitHub Actions, GitLab CI, Jenkins, Travis CI, CircleCI)
- 🐳 Docker (Dockerfile, docker-compose)
- ⚙️ Configuration files (ESLint, Prettier, TypeScript config)

## Example Output

```
============================================================
📊 SNYFT PROJECT ANALYSIS REPORT
============================================================

📁 PROJECT OVERVIEW
   Type: Full-stack (Java + JavaScript)
   Languages: Java, JavaScript/TypeScript
   Total Files: 247

☕ JAVA ANALYSIS
   Files: 89
   Packages: 23
   Classes: 102
   Build Tool: Maven
   Source Roots: src/main/java, src/test/java

🟨 JAVASCRIPT/TYPESCRIPT ANALYSIS
   Files: 158
   Functions: 342
   Classes: 67
   Modules: 158
   Frameworks: react, express
   Build Tool: npm

🏗️ BUILD INFRASTRUCTURE
   Package Managers: Maven, npm
   CI/CD: GitHub Actions
   Docker: Yes

============================================================
✅ Analysis completed in 2.34s
============================================================
```

## API Usage

You can also use Snyft programmatically:

```javascript
import { Coordinator } from './src/coordinator.js';
import { Reporter } from './src/reporter.js';

// Analyze a project
const coordinator = new Coordinator('/path/to/project');
const results = await coordinator.analyze();

// Generate reports
const reporter = new Reporter(results);
reporter.generateConsoleReport();

// Get JSON data
const jsonReport = reporter.generateJSONReport();
console.log(jsonReport);
```

## Development

```bash
# Run analysis in development
npm start

# Run tests
npm test

# Lint code
npm run lint
```

### Regular Commits & Pushes

This repository uses automated tools to ensure work is committed and pushed regularly:

```bash
# Auto-commit and push current work
./scripts/auto-commit.sh

# Check for uncommitted/unpushed changes
./scripts/commit-check.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:
- Commit frequently (after each logical change)
- Push regularly (at least every hour of active work)
- Create PRs when tasks are complete

## Use Cases

- 📋 **Project Discovery**: Understand the structure of unfamiliar codebases
- 🔄 **Migration Planning**: Identify dependencies before migrating projects
- 📊 **Code Metrics**: Generate statistics about codebase composition
- 🔍 **Build Tool Detection**: Automatically detect build infrastructure
- 🤖 **CI/CD Inventory**: Find all CI/CD configurations across repositories
- 📚 **Documentation**: Generate reports about project structure

## Multiclaude Integration

Snyft is designed to work seamlessly with multiclaude's multi-agent system. Each analysis component (Java parser, JS parser, build detector) can run as an independent agent, enabling:

- **Parallel processing** of large codebases
- **Distributed analysis** across multiple machines
- **Fault tolerance** - if one agent fails, others continue
- **Scalability** - easy to add new language parsers

## Contributing

Contributions welcome! To add a new language parser:

1. Create a parser in `src/parsers/your-language-parser.js`
2. Implement the `analyze()` method
3. Add it to the coordinator in `src/coordinator.js`
4. Create an agent definition in `multiclaude-agents.md`

## License

MIT

## Credits

Built with:
- [Acorn](https://github.com/acornjs/acorn) - JavaScript parser
- [fast-glob](https://github.com/mrmlnc/fast-glob) - File pattern matching
- [Commander.js](https://github.com/tj/commander.js) - CLI framework
- [Multiclaude](https://github.com/anthropics/multiclaude) - Multi-agent orchestration
