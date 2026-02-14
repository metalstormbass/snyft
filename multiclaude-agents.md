# Multiclaude Agent Definitions for Snyft

This document describes the multiclaude agent setup for distributed code analysis.

## Agent Architecture

### 1. Java Parser Agent

**Task:** "Analyze Java source code and identify structure"

**Responsibilities:**
- Scan for `.java` files
- Extract package declarations
- Identify classes, interfaces, enums
- Detect Maven/Gradle build files
- Map source directory structure

**Tools Used:**
- File system scanning (fast-glob)
- Regex pattern matching for Java syntax
- Package/class extraction

**Output:** JSON report with Java analysis results

---

### 2. JavaScript Parser Agent

**Task:** "Analyze JavaScript/TypeScript source code and identify structure"

**Responsibilities:**
- Scan for `.js`, `.jsx`, `.ts`, `.tsx` files
- Parse AST with Acorn
- Extract functions, classes, modules
- Detect framework usage (React, Vue, Angular, etc.)
- Identify build tools (webpack, vite, rollup)

**Tools Used:**
- Acorn JavaScript parser
- AST walking
- Pattern matching for framework detection

**Output:** JSON report with JavaScript analysis results

---

### 3. Build Infrastructure Agent

**Task:** "Detect build tools, CI/CD, and project structure"

**Responsibilities:**
- Detect CI/CD configurations (GitHub Actions, GitLab CI, Jenkins)
- Find Docker files and docker-compose
- Identify package managers (Maven, Gradle, npm, yarn, pnpm)
- Scan configuration files
- Analyze project directory structure

**Tools Used:**
- File pattern matching
- Configuration file parsing
- Directory structure analysis

**Output:** JSON report with build infrastructure details

---

### 4. Coordinator Agent

**Task:** "Orchestrate analysis workflow and aggregate results"

**Responsibilities:**
- Spawn and manage worker agents
- Collect results from all agents
- Generate unified analysis report
- Handle errors and retries

**Output:** Comprehensive project analysis report

---

### 5. Reporter Agent

**Task:** "Generate reports from analysis results"

**Responsibilities:**
- Format results for console output
- Generate JSON reports
- Generate Markdown reports
- Save reports to files

**Output:** Formatted reports in multiple formats

---

## Running with Multiclaude

### Setup

1. Initialize the repository with multiclaude:
```bash
multiclaude repo init <github-url> snyft
```

2. Install dependencies:
```bash
cd /path/to/snyft/worktree
npm install
```

### Spawn Agents

```bash
# Start the daemon
multiclaude daemon start

# Create worker agents for parallel analysis
multiclaude worker create "Run Java parser on target project" --repo snyft
multiclaude worker create "Run JavaScript parser on target project" --repo snyft
multiclaude worker create "Run build infrastructure detector on target project" --repo snyft
```

### Agent Communication

Agents communicate via multiclaude's message system:

```bash
# List messages
multiclaude message list

# Read a message
multiclaude message read <message-id>

# Send a message to another agent
multiclaude message send <agent-name> "Analysis complete for Java files"
```

### Workflow

1. **Coordinator** spawns worker agents
2. Each worker agent runs its specialized parser
3. Workers send results back to coordinator via messages
4. **Coordinator** aggregates results
5. **Reporter** generates final output

### Example Multi-Agent Workflow

```bash
# Terminal 1: Coordinator
multiclaude worker create "Coordinate code analysis workflow" --repo snyft

# Terminal 2: Java Parser
multiclaude worker create "Parse all Java files in project" --repo snyft

# Terminal 3: JS Parser
multiclaude worker create "Parse all JavaScript files in project" --repo snyft

# Terminal 4: Build Detector
multiclaude worker create "Detect build infrastructure" --repo snyft

# Check status
multiclaude worker list --repo snyft

# View agent output
multiclaude logs <agent-name> -f
```

## Integration with External Projects

To analyze external projects with multiclaude:

```bash
# Analyze a project
cd /path/to/external/project
snyft analyze

# Or use multiclaude workers
multiclaude worker create "Analyze Java code in /path/to/external/project"
multiclaude worker create "Analyze JavaScript code in /path/to/external/project"
```

## Benefits of Multi-Agent Approach

1. **Parallel Processing**: Java and JavaScript analysis run simultaneously
2. **Specialization**: Each agent focuses on one language or aspect
3. **Scalability**: Easy to add new language parsers or analyzers
4. **Resilience**: If one agent fails, others continue
5. **Modularity**: Agents can be developed and tested independently
