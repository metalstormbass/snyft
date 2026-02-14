# Snyft Architecture

Multi-agent code analysis using specialized parsers.

## Agent Roles

**Coordinator** - Orchestrates workflow, aggregates results, generates reports

**Java Parser** - Scans Java files, parses classes/packages, detects Maven/Gradle

**JavaScript Parser** - Parses JS/TS files, identifies frameworks, detects build tools

**Build Detector** - Finds CI/CD configs, Docker files, package managers

**Reporter** - Formats output (JSON, Markdown, console)

## Flow

```
User -> Coordinator
         ├─> Java Parser ──┐
         ├─> JS Parser ────┤
         ├─> Build Detector┤
         └─────────────────> Reporter -> Output
```

## Data Model

```json
{
  "project_root": "/path",
  "analyzed_at": "timestamp",
  "languages": { "java": {...}, "javascript": {...} },
  "build_infrastructure": {...},
  "summary": {...}
}
```
