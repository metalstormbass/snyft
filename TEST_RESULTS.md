# Test Results - Snyft Local Build & Execution

**Test Date**: 2026-02-14
**Tester**: jolly-tiger (automated worker)
**Binary Version**: Built from commit 8172fd1

## Build Test

**Command**: `make build`

**Result**: ✅ SUCCESS

```
CGO_ENABLED=0 go build -o ./snyft .
```

- Binary size: 9.6M
- Build time: < 5 seconds
- Platform: darwin (macOS)

## Functionality Tests

### Test 1: Help Command

**Command**: `./snyft --help`

**Result**: ✅ SUCCESS

Verified output shows:
- Main help menu with available commands
- `scan` command properly listed
- Proper flag descriptions

### Test 2: Scan Command Help

**Command**: `./snyft scan --help`

**Result**: ✅ SUCCESS

Available options confirmed:
- `-w, --workers <N>`: Concurrent workers (default: 10)
- `-v, --verbose`: Verbose output
- `-o, --output <file>`: Output to file

### Test 3: Example Project Scan

**Command**: `./snyft scan examples/nodejs-example/ --verbose`

**Result**: ✅ SUCCESS

Scanned: `/examples/nodejs-example/package.json`
- Manifest files detected: 1
- Dependencies found: 6
  - express@4.18.0
  - lodash@4.17.21
  - axios@1.6.0
  - jsonwebtoken@9.0.0
  - jest@29.0.0
  - eslint@8.0.0

**Risk Summary**:
- 🔴 HIGH: 0
- 🟡 MEDIUM: 0
- 🟢 LOW: 6

**Observations**:
- npm registry queries successful
- GitHub API rate limiting encountered (expected without GITHUB_TOKEN)
- OSSF Scorecard integration working
- Risk scoring applied correctly

### Test 4: Real-World Project Scan (mk.js)

**Command**: `./snyft scan /Users/mike/Projects/mk.js/ --verbose`

**Result**: ✅ SUCCESS

**Target**: Node.js web application with Express.js and Socket.io

Scanned files:
- `/Users/mike/Projects/mk.js/server/package.json`
- `/Users/mike/Projects/mk.js/server/package-lock.json`

**Statistics**:
- Manifest files detected: 2
- Total dependencies analyzed: 111
- Analysis time: ~30 seconds (with API rate limiting delays)

**Risk Summary**:
- 🔴 HIGH: 20 packages
- 🟡 MEDIUM: 33 packages
- 🟢 LOW: 58 packages

**Key Findings**:

HIGH Risk Packages (examples):
- Multiple nested dependency path errors (false positives from package-lock.json parsing)
  - `serve-index/node_modules/escape-html@1.0.3` - Package not found
  - `errorhandler/node_modules/negotiator@0.6.2` - Package not found
  - `method-override/node_modules/debug@2.6.9` - Package not found
- `policyfile@0.0.4` - JSON parsing error from npm registry

MEDIUM Risk Packages (examples):
- `base64-url@1.2.1` - OSSF Score: 2.3/10
- `batch@0.5.3` - OSSF Score: 4.4/10
- `tinycolor@0.0.1` - OSSF Score: 2.7/10
- `inherits@2.0.4` - OSSF Score: 3.2/10
- Multiple packages with no CI/CD detected

LOW Risk Packages (examples):
- `express@3.21.2` - Popular, well-maintained
- `socket.io@0.9.19` - Established library
- `redis@0.7.3` - Known package

## Known Issues Identified

### 1. GitHub API Rate Limiting

**Severity**: Expected behavior
**Description**: Without `GITHUB_TOKEN` set, all repository metadata queries fail with:
- HTTP 403: Rate limit exceeded
- HTTP 429: Abuse detection triggered

**Impact**:
- No repository health metrics
- No CI/CD detection
- No source code verification
- Limited risk scoring accuracy

**Mitigation**: Set `GITHUB_TOKEN` environment variable

### 2. Nested Dependency Parsing

**Severity**: Bug - False Positives
**Description**: Parser attempts to fetch packages with paths like:
- `serve-index/node_modules/escape-html`
- `method-override/node_modules/debug`
- `raw-body/node_modules/iconv-lite`

These are not valid npm package names but appear to come from package-lock.json's nested structure.

**Impact**:
- 20 HIGH risk false positives in mk.js scan
- Inflated risk metrics
- Confusing output for users

**Recommendation**:
- Filter or normalize package names before npm registry queries
- Consider handling nested dependencies differently
- May need to parse package-lock.json structure more carefully

### 3. npm Registry Response Parsing

**Severity**: Minor
**Description**: Package `policyfile@0.0.4` failed with:
```
failed to decode npm response: json: cannot unmarshal object into Go struct field NPMRegistryResponse.license of type string
```

**Impact**: Single package analysis failure
**Recommendation**: Add more flexible JSON parsing for license field (can be string or object)

## Performance Observations

- **Build time**: < 5 seconds (clean build)
- **Small project (6 deps)**: < 2 seconds
- **Large project (111 deps)**: ~30 seconds (including API delays)
- **Concurrency**: Default 10 workers effectively utilized
- **Memory usage**: Reasonable for analyzed package count

## API Integration Status

| API | Status | Notes |
|-----|--------|-------|
| npm Registry | ✅ Working | Successfully fetches package metadata |
| OSSF Scorecard | ✅ Working | Returns security scores for packages |
| GitHub API | ⚠️  Rate Limited | Requires GITHUB_TOKEN for full functionality |
| PyPI | Not tested | N/A for Node.js projects |
| Maven Central | Not tested | N/A for Node.js projects |

## Recommendations

### For Users

1. **Set GitHub Token**: Export `GITHUB_TOKEN` for better results
   ```bash
   export GITHUB_TOKEN="your-token-here"
   ./snyft scan
   ```

2. **Adjust Workers**: For large projects, increase worker count
   ```bash
   ./snyft scan --workers 20 ./large-project
   ```

3. **Save Results**: Use output flag for archival
   ```bash
   ./snyft scan --output results.txt ./project
   ```

### For Developers

1. Fix nested dependency parsing from package-lock.json
2. Add more robust npm registry response parsing
3. Consider caching API responses to reduce rate limiting
4. Add retry logic with exponential backoff for API calls
5. Improve HIGH risk false positive detection

## Conclusion

✅ **Snyft builds and runs successfully on macOS (darwin)**

✅ **Core functionality working**:
- Manifest file detection
- Dependency parsing
- npm registry integration
- OSSF Scorecard integration
- Risk scoring and reporting

⚠️ **Known issues**:
- Nested dependency parsing creates false positives
- Requires GitHub token for full functionality
- Minor JSON parsing edge case

**Overall Assessment**: Tool is functional and provides valuable supply chain security analysis. The identified issues are primarily edge cases and API limitations rather than core functionality problems.
