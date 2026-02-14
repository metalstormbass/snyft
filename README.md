# Snyft

**S**ource code a**n**alyzer **y**ielding **f**ull **t**axonomy

Multi-agent code analysis tool for Java and JavaScript projects.

## Features

- Multi-language parsing (Java, JavaScript/TypeScript)
- Build infrastructure detection (Maven, Gradle, npm, webpack)
- Multi-agent architecture via multiclaude
- Reports in JSON, Markdown, and console formats
- CI/CD detection (GitHub Actions, GitLab CI, Jenkins)

## Installation

```bash
git clone <repo-url> && cd snyft
npm install
chmod +x src/cli.js
npm link  # optional for global use
```

## Usage

```bash
snyft analyze [path]              # analyze directory
snyft analyze --format json       # JSON output
snyft analyze --output ./reports  # save to file
```

### Multi-Agent Mode

```bash
multiclaude daemon start
multiclaude worker create "Analyze Java code in project"
multiclaude worker create "Analyze JavaScript code"
multiclaude worker list  # check status
```

See [multiclaude-agents.md](./multiclaude-agents.md) for details.

## What It Detects

**Java:** `.java` files, packages, classes, Maven/Gradle

**JavaScript:** `.js/.ts` files, modules, React/Vue/Angular, npm/webpack

**Build:** package managers, CI/CD configs, Docker, linters

## API

```javascript
import { Coordinator, Reporter } from './src/coordinator.js';

const coordinator = new Coordinator('/path/to/project');
const results = await coordinator.analyze();
const reporter = new Reporter(results);
reporter.generateConsoleReport();
```

## Development

```bash
npm start  # run analysis
npm test   # run tests
```

### Commits

Use automated scripts to commit/push regularly:

```bash
./scripts/auto-commit.sh     # auto-commit and push
./scripts/commit-check.sh    # check for uncommitted work
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow details.

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for multi-agent design.

## Contributing

To add a language parser:
1. Create parser in `src/parsers/`
2. Implement `analyze()` method
3. Add to `src/coordinator.js`

## License

MIT
