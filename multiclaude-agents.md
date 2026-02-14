# Multiclaude Agent Setup

Distributed code analysis using multiclaude's multi-agent system.

## Agents

**Java Parser** - Scans `.java` files, extracts packages/classes, detects Maven/Gradle

**JavaScript Parser** - Parses `.js/.ts` files with Acorn, detects frameworks/build tools

**Build Detector** - Finds CI/CD configs, Docker, package managers

**Coordinator** - Spawns workers, aggregates results, generates reports

**Reporter** - Formats output (JSON, Markdown, console)

## Setup

```bash
multiclaude repo init <github-url> snyft
cd /path/to/snyft/worktree
npm install
```

## Usage

```bash
# Start daemon
multiclaude daemon start

# Spawn workers for parallel analysis
multiclaude worker create "Run Java parser on project" --repo snyft
multiclaude worker create "Run JS parser on project" --repo snyft
multiclaude worker create "Run build detector on project" --repo snyft

# Check status
multiclaude worker list --repo snyft
multiclaude logs <agent-name> -f
```

## Agent Communication

```bash
multiclaude message list                           # list messages
multiclaude message read <id>                      # read message
multiclaude message send <agent> "message text"    # send message
```

## Workflow

1. Coordinator spawns workers
2. Workers run specialized parsers
3. Workers send results via messages
4. Coordinator aggregates results
5. Reporter generates output

## Analyzing External Projects

```bash
cd /path/to/external/project
snyft analyze

# Or use multiclaude
multiclaude worker create "Analyze Java in /path/to/project"
multiclaude worker create "Analyze JavaScript in /path/to/project"
```

## Benefits

- Parallel processing (Java and JS analysis run simultaneously)
- Specialized agents (each focuses on one language/aspect)
- Scalable (easy to add new parsers)
- Resilient (failures isolated to individual agents)
