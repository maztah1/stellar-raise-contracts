# Security Validation Script

## Overview

The `security_validation.sh` script provides automated security validation for the CI/CD pipeline. It performs comprehensive security checks including dependency scanning, secret detection, code quality analysis, and compliance verification.

## Features

- **Dependency Vulnerability Scanning**: NPM and Cargo audit checks
- **Secret Detection**: Scans for exposed API keys, tokens, and credentials
- **Rust Security Linting**: Clippy checks for unsafe code patterns
- **TypeScript Type Checking**: Ensures type safety across the codebase
- **WASM Binary Validation**: Verifies WASM binary integrity
- **File Permissions**: Detects world-writable files
- **Git Configuration**: Validates git setup
- **License Compliance**: Checks for LICENSE and CONTRIBUTING files
- **Code Quality**: Identifies TODO/FIXME comments
- **Test Coverage**: Verifies test infrastructure

## Usage

### Basic Usage

```bash
./scripts/security_validation.sh
```

### Strict Mode

Fails on any warnings or issues:

```bash
./scripts/security_validation.sh --strict
```

### Generate Report

Creates a security validation report:

```bash
./scripts/security_validation.sh --report
```

### Combined Options

```bash
./scripts/security_validation.sh --strict --report
```

## Security Checks

### 1. Dependency Vulnerability Scanning

Checks NPM and Cargo dependencies for known vulnerabilities:

```bash
npm audit --audit-level=moderate
cargo audit --deny warnings
```

**Exit Code**: 1 if vulnerabilities found (in strict mode)

### 2. Secret Detection

Scans for common secret patterns:

- `private_key`
- `secret_key`
- `api_key`
- `password`
- `token`

**Excludes**: Test files, examples, node_modules, target directory

### 3. Rust Security Linting

Runs Clippy with strict warnings:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

**Checks**: Unsafe code, performance issues, style violations

### 4. TypeScript Type Checking

Validates TypeScript type safety:

```bash
tsc --noEmit
```

**Ensures**: No implicit any, proper type annotations

### 5. WASM Binary Validation

Verifies WASM binary format:

```bash
file <wasm_file> | grep "WebAssembly"
```

**Validates**: Binary integrity, correct format

### 6. File Permissions

Detects world-writable files:

```bash
find . -type f -perm -002
```

**Security**: Prevents accidental permission escalation

### 7. Git Configuration

Checks git user setup:

```bash
git config --get user.name
```

**Ensures**: Proper commit attribution

### 8. License Compliance

Verifies presence of:

- `LICENSE` file
- `CONTRIBUTING.md` file

**Ensures**: Legal compliance and contribution guidelines

### 9. Code Quality

Identifies TODO/FIXME comments:

```bash
grep -r "TODO\|FIXME"
```

**Tracks**: Technical debt and pending work

### 10. Test Coverage

Verifies test infrastructure:

- Jest configuration
- Cargo configuration

**Ensures**: Testing framework setup

## Output Format

### Success Output

```
[INFO] Starting security validation...
[✓] NPM dependencies are secure
[✓] No obvious secrets detected
[✓] Rust clippy checks passed
[✓] TypeScript type checking passed
[✓] Valid WASM binary: crowdfund.wasm
[✓] No world-writable files detected
[✓] Git user configured
[✓] LICENSE file present
[✓] CONTRIBUTING.md present
[✓] No TODO/FIXME comments found
[✓] Jest configuration found

[INFO] Security validation complete
  Passed: 11
  Warned: 0
  Failed: 0
```

### Warning Output

```
[⚠] Cargo audit found advisories
[⚠] Potential secret pattern found: token
[⚠] World-writable files detected
```

### Error Output

```
[✗] NPM audit found vulnerabilities
[✗] Invalid WASM binary: contract.wasm
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All security checks passed |
| 1 | Security vulnerabilities detected |
| 2 | Configuration error |

## Report Generation

When using `--report` flag, generates `security_validation_report.txt`:

```
Security Validation Report
Generated: 2026-03-29 04:18:27
Project: /workspaces/stellar-raise-contracts

Summary:
  Passed: 11
  Warned: 0
  Failed: 0

Status: PASSED
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Validation
  run: ./scripts/security_validation.sh --strict --report

- name: Upload Report
  if: always()
  uses: actions/upload-artifact@v2
  with:
    name: security-report
    path: security_validation_report.txt
```

### GitLab CI

```yaml
security_validation:
  script:
    - ./scripts/security_validation.sh --strict --report
  artifacts:
    paths:
      - security_validation_report.txt
    when: always
```

## Configuration

### Environment Variables

- `SCRIPT_DIR`: Directory containing the script
- `PROJECT_ROOT`: Root project directory
- `STRICT_MODE`: Enable strict mode (--strict)
- `GENERATE_REPORT`: Generate report (--report)

### Customization

Edit the script to:

1. Add custom security checks
2. Modify audit levels
3. Change secret patterns
4. Adjust file permission checks

## Security Assumptions

- Script runs with appropriate permissions
- Dependencies are installed and available
- Git repository is properly initialized
- WASM binaries are in expected locations

## Best Practices

1. **Run Before Commits**: Use pre-commit hooks
2. **Run in CI/CD**: Automate security checks
3. **Review Reports**: Analyze security validation reports
4. **Fix Issues Promptly**: Address vulnerabilities immediately
5. **Update Dependencies**: Keep dependencies current
6. **Monitor Advisories**: Track security advisories

## Troubleshooting

### Script Not Executable

```bash
chmod +x ./scripts/security_validation.sh
```

### Command Not Found

Ensure required tools are installed:

```bash
npm install -g npm-audit
cargo install cargo-audit
```

### Permission Denied

Run with appropriate permissions:

```bash
sudo ./scripts/security_validation.sh
```

### False Positives

Review and adjust patterns in the script:

```bash
# Edit secret patterns
# Edit file permission checks
# Edit code quality patterns
```

## Testing

Run the test suite:

```bash
bash ./scripts/security_validation.test.sh
```

Test coverage includes:

- Script syntax validation
- Function existence checks
- Error handling verification
- Integration tests
- Output format validation

## Related Scripts

- `security_compliance_validation.sh` - Compliance checks
- `security_compliance_automation.sh` - Automated compliance
- `security_compliance_reporting.sh` - Compliance reporting

## Support

For issues or questions:

1. Check the troubleshooting section
2. Review the test output
3. Consult the documentation
4. Open an issue on GitHub

## License

This script is part of the Stellar Raise Contracts project and is licensed under the MIT License.
