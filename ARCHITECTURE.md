# Snyft Architecture

## Overview
Snyft is a code analysis tool that uses multiclaude's multi-agent approach to parse Java and JavaScript codebases and identify source code structure and build infrastructure.

## Multi-Agent Design

### Agent Roles

1. **Coordinator Agent** (`coordinator`)
   - Orchestrates the analysis workflow
   - Delegates tasks to specialized agents
   - Aggregates results
   - Generates final report

2. **Java Parser Agent** (`java-parser`)
   - Scans for Java source files
   - Parses Java code structure (classes, packages, methods)
   - Identifies Java-specific patterns
   - Detects Java build files (Maven, Gradle)

3. **JavaScript Parser Agent** (`js-parser`)
   - Scans for JavaScript/TypeScript files
   - Parses JS/TS code structure (modules, functions, classes)
   - Identifies framework usage (React, Vue, Angular, etc.)
   - Detects JS build files (package.json, webpack, etc.)

4. **Build Infrastructure Agent** (`build-detector`)
   - Identifies build tools and configurations
   - Maps dependencies
   - Detects CI/CD configurations
   - Analyzes project structure

5. **Reporter Agent** (`reporter`)
   - Aggregates findings from all agents
   - Generates structured reports (JSON, Markdown, HTML)
   - Creates visualizations
   - Provides actionable insights

## Communication Flow

```
User -> Coordinator
         |
         ├─> Java Parser ──┐
         ├─> JS Parser ────┤
         ├─> Build Detector┤
         |                 |
         |                 v
         └──────────> Reporter -> Final Report
```

## Data Model

### Project Analysis Result
```json
{
  "project_root": "/path/to/project",
  "analyzed_at": "2026-02-13T...",
  "languages": {
    "java": { ... },
    "javascript": { ... }
  },
  "build_infrastructure": { ... },
  "summary": { ... }
}
```

## Implementation Phases

1. **Phase 1**: Core parsing engines (Java & JavaScript)
2. **Phase 2**: Build infrastructure detection
3. **Phase 3**: Multi-agent orchestration with multiclaude
4. **Phase 4**: Reporting and visualization
