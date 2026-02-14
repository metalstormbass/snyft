# Snyft Project Instructions

## What is Snyft?

Snyft is a **dependency supply chain security analysis tool** that parses dependency manifest files across multiple languages (Java, JavaScript/TypeScript, Python) to identify and analyze project dependencies.

**Important:** Snyft focuses on dependency analysis from manifest files, NOT:
- CVE (Common Vulnerabilities and Exposures) scanning
- Source code vulnerability detection
- Runtime security analysis

## Supported Manifest Files

### Java
- `pom.xml` - Maven dependencies
- `build.gradle` / `build.gradle.kts` - Gradle dependencies
- `build.xml` - Ant build files
- `ivy.xml` - Apache Ivy dependencies

### JavaScript/TypeScript
- `package.json` - npm/yarn/pnpm dependencies
- `yarn.lock` - Yarn lock files
- `pnpm-lock.yaml` - pnpm lock files

### Python
- `requirements.txt` - pip dependencies
- `setup.py` - setuptools configuration
- `pyproject.toml` - Poetry/PEP 518 dependencies
- `Pipfile` / `Pipfile.lock` - Pipenv dependencies
- `setup.cfg` - setuptools configuration
- `tox.ini` - tox testing dependencies
- `environment.yml` / `conda.yml` - Conda environment files

## Architecture

Snyft uses a multi-agent architecture with:
- **Coordinator**: Orchestrates analysis agents
- **Language Parsers**: Extract dependencies from manifest files
  - JavaParser (for manifest files, not source)
  - JavaScriptParser (for manifest files, not source)
  - PythonParser (for manifest files only)
- **Build Infrastructure Detector**: Identifies build tools, CI/CD, Docker configs
- **Reporter**: Generates reports in JSON, Markdown, and console formats

## Key Principles

1. **Manifest-focused**: Parse dependency manifest files, not source code
2. **Supply chain security**: Analyze dependency chains and build infrastructure
3. **Multi-language**: Support Java, JavaScript/TypeScript, and Python ecosystems
4. **No CVE scanning**: Does not check for known vulnerabilities (CVEs)
5. **Multi-agent**: Designed to work with multiclaude for parallel analysis

## Development Guidelines

- Keep parsers focused on manifest file parsing only
- Extract dependency names, versions, and operators
- Don't add CVE or vulnerability scanning features
- Maintain lightweight parsing (regex/simple text parsing preferred over heavy XML/TOML parsers)
- Support multi-agent workflow for large projects

## Output

Snyft generates reports showing:
- Detected dependencies with versions
- Build tools and package managers
- CI/CD configurations
- Project structure and infrastructure
- Dependency counts and summaries

It does NOT report on:
- Security vulnerabilities (CVEs)
- Code quality issues
- Runtime security concerns
