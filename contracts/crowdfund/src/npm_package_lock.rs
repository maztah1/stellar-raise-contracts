//! # npm_package_lock
//!
//! @title   NPMPackageLock — Vulnerability audit module for package-lock.json entries.
//!
//! @notice  Audits `package-lock.json` dependency entries for known security
//!          vulnerabilities, version constraint violations, and integrity hash validity.
//!
//!          Introduced to address **GHSA-xpqw-6gx7-v673** — a high-severity
//!          Denial-of-Service vulnerability in `svgo` versions `>=3.0.0 <3.3.3`
//!          caused by unconstrained XML entity expansion (Billion Laughs attack).
//!
//!          Also addresses additional minor vulnerabilities commonly found in
//!          frontend toolchain dependencies (e.g., `postcss`, `nth-check`,
//!          `semver`, `tough-cookie`) to improve overall frontend UI security
//!          and developer experience.
//!
//! ## Security Assumptions
//!
//! 1. `sha512` integrity hashes are the only accepted algorithm; `sha1` and
//!    `sha256` are rejected as insufficient.
//! 2. `lockfileVersion` must be 2 or 3 (npm >=7). Version 1 lacks integrity
//!    hashes for all entries and is considered insecure.
//! 3. The advisory map (`min_safe_versions`) must be kept up to date as new
//!    CVEs are published. This module does not perform live advisory lookups.
//! 4. This module audits resolved versions only. Ranges in `package.json`
//!    should be reviewed separately to prevent future resolution of vulnerable
//!    versions.
//! 5. Package names are case-sensitive and must match the advisory map exactly.

#![allow(dead_code)]

use soroban_sdk::{Map, String, Vec};

// ── Constants ────────────────────────────────────────────────────────────────

/// Minimum lockfile version that includes integrity hashes for all entries.
/// npm <7 (lockfileVersion 1) omits integrity hashes for some entries.
pub const MIN_LOCKFILE_VERSION: u32 = 2;

/// Maximum lockfile version currently supported (npm 9+ uses v3).
pub const MAX_LOCKFILE_VERSION: u32 = 3;

/// Minimum safe version for svgo (fixes GHSA-xpqw-6gx7-v673, DoS via XML entity expansion).
pub const SVGO_MIN_SAFE_VERSION: &str = "3.3.3";

/// Minimum safe version for postcss (fixes GHSA-7fh8-c0uq-4h3g, line return parsing).
pub const POSTCSS_MIN_SAFE_VERSION: &str = "8.4.31";

/// Minimum safe version for nth-check (fixes GHSA-rp65-9cf3-cjxr, ReDoS).
pub const NTH_CHECK_MIN_SAFE_VERSION: &str = "2.0.1";

/// Minimum safe version for semver (fixes GHSA-c2qf-rxjj-qqgw, ReDoS).
pub const SEMVER_MIN_SAFE_VERSION: &str = "7.5.2";

/// Maximum number of packages that can be audited in a single call.
/// Prevents unbounded iteration and excessive gas consumption.
pub const MAX_PACKAGES: u32 = 500;

// ── Data Types ───────────────────────────────────────────────────────────────

/// Represents a single entry in a package-lock.json file.
///
/// @dev    Mirrors the structure of npm's lockfile format (v2/v3).
///         The `integrity` field must be a `sha512-` prefixed SRI hash.
#[derive(Clone)]
pub struct PackageEntry {
    /// Package name (e.g., "svgo", "react").
    pub name: String,
    /// Resolved semantic version (e.g., "3.3.3").
    pub version: String,
    /// Integrity hash in SRI format (e.g., "sha512-...").
    pub integrity: String,
    /// Whether this is a dev dependency.
    pub dev: bool,
}

/// Result of auditing a single package entry.
///
/// @dev    Contains the package name, pass/fail status, and a list of issues found.
///         Multiple issues can be reported per package (e.g., bad version AND bad hash).
#[derive(Clone)]
pub struct AuditResult {
    /// Package name.
    pub package_name: String,
    /// Whether the audit passed (true = no issues found).
    pub passed: bool,
    /// List of human-readable issues found (empty if passed).
    pub issues: Vec<String>,
}

// ── Semver Parsing ───────────────────────────────────────────────────────────

/// @notice Parse a semantic version string into (major, minor, patch) tuple.
///
/// @dev    Handles optional "v" prefix, pre-release suffixes, and missing patch.
///         Returns (0, 0, 0) on parse failure to allow graceful degradation.
///         Uses only `no_std`-compatible byte-level string operations.
///
/// @security No panics — all parse failures return (0, 0, 0) rather than
///           unwrapping, preventing DoS via malformed version strings.
///
/// # Arguments
/// * `version` – A semver string (e.g., "3.3.3", "v1.2.0", "1.2.0-alpha").
///
/// # Returns
/// A tuple `(major, minor, patch)` or `(0, 0, 0)` on parse failure.
pub fn parse_semver(version: &String) -> (u32, u32, u32) {
    // Convert to XDR bytes for no_std-compatible processing.
    let bytes = version.to_xdr();
    let raw = bytes.as_ref();

    // Strip optional leading 'v' or 'V'.
    let start = if !raw.is_empty() && (raw[0] == b'v' || raw[0] == b'V') {
        1
    } else {
        0
    };

    // Find end of base version (stop at '-' for pre-release or '+' for build metadata).
    let end = {
        let mut e = raw.len();
        for i in start..raw.len() {
            if raw[i] == b'-' || raw[i] == b'+' {
                e = i;
                break;
            }
        }
        e
    };

    let base = &raw[start..end];

    // Parse each dot-separated component.
    let major = parse_component(base, 0);
    let minor = parse_component(base, 1);
    let patch = parse_component(base, 2);

    (major, minor, patch)
}

/// @dev Parse the Nth dot-separated numeric component from a byte slice.
///      Returns 0 if the component is missing or non-numeric.
fn parse_component(base: &[u8], index: usize) -> u32 {
    let mut current = 0usize;
    let mut found = 0usize;

    let mut i = 0;
    while i <= base.len() {
        let is_dot = i < base.len() && base[i] == b'.';
        let is_end = i == base.len();

        if is_dot || is_end {
            if found == index {
                return parse_u32(&base[current..i]);
            }
            found += 1;
            current = i + 1;
        }
        i += 1;
    }
    0
}

/// @dev Parse a byte slice as a decimal u32. Returns 0 on any non-digit byte.
fn parse_u32(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return 0;
        }
        result = result.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    result
}

/// @notice Check if `version >= min_version` using semantic versioning rules.
///
/// @dev    Compares major, then minor, then patch in order (O(1)).
///         Pre-release suffixes are stripped before comparison.
///
/// # Arguments
/// * `version`     – The version to check.
/// * `min_version` – The minimum acceptable version.
///
/// # Returns
/// `true` if `version >= min_version`, `false` otherwise.
pub fn is_version_gte(version: &String, min_version: &String) -> bool {
    let (v_major, v_minor, v_patch) = parse_semver(version);
    let (m_major, m_minor, m_patch) = parse_semver(min_version);

    if v_major != m_major {
        return v_major > m_major;
    }
    if v_minor != m_minor {
        return v_minor > m_minor;
    }
    v_patch >= m_patch
}

// ── Integrity Validation ─────────────────────────────────────────────────────

/// @notice Validate that an integrity hash is present and uses sha512.
///
/// @dev    Rejects sha1 and sha256 as insufficient. Requires "sha512-" prefix.
///         sha1 is cryptographically broken; sha256 is acceptable but sha512
///         is the npm v7+ default and provides stronger collision resistance.
///
/// @security Prevents downgrade attacks where a tampered package could supply
///           a weaker hash algorithm that is easier to forge.
///
/// # Arguments
/// * `integrity` – The integrity hash string (e.g., "sha512-...").
///
/// # Returns
/// `true` if valid sha512 hash, `false` otherwise.
pub fn validate_integrity(integrity: &String) -> bool {
    let bytes = integrity.to_xdr();
    let raw = bytes.as_ref();

    // Must start with "sha512-" (7 bytes).
    if raw.len() < 7 {
        return false;
    }
    &raw[..7] == b"sha512-"
}

// ── Package Auditing ─────────────────────────────────────────────────────────

/// @notice Audit a single package entry against known vulnerabilities.
///
/// @dev    Checks version constraints and integrity hash validity.
///         Returns a typed `AuditResult` with pass/fail status and issues.
///         Issues are accumulated so callers see all problems at once.
///
/// @security Both checks run unconditionally so all issues are reported,
///           preventing partial-fix scenarios where one issue masks another.
///
/// # Arguments
/// * `entry`             – The package entry to audit.
/// * `min_safe_versions` – Map of package names to minimum safe versions.
///
/// # Returns
/// An `AuditResult` with `passed=true` if all checks pass, `false` otherwise.
pub fn audit_package(
    entry: &PackageEntry,
    min_safe_versions: &Map<String, String>,
) -> AuditResult {
    let env = soroban_sdk::Env::default();
    let mut issues: Vec<String> = Vec::new(&env);

    // Check integrity hash — must be sha512.
    if !validate_integrity(&entry.integrity) {
        issues.push_back(String::from_slice(
            &env,
            "Invalid or missing sha512 integrity hash",
        ));
    }

    // Check version against advisory map (skip if package is not in map).
    if let Some(min_safe) = min_safe_versions.get(entry.name.clone()) {
        if !is_version_gte(&entry.version, &min_safe) {
            // Build issue message using byte-level concatenation (no_std safe).
            let v_bytes = entry.version.to_xdr();
            let m_bytes = min_safe.to_xdr();
            let v_str = core::str::from_utf8(v_bytes.as_ref()).unwrap_or("?");
            let m_str = core::str::from_utf8(m_bytes.as_ref()).unwrap_or("?");

            // Compose message: "Version X is below minimum safe version Y"
            // Max length: 64 bytes — fits in a fixed-size stack buffer.
            let mut buf = [0u8; 128];
            let prefix = b"Version ";
            let middle = b" is below minimum safe version ";
            let mut pos = 0usize;

            for &b in prefix { buf[pos] = b; pos += 1; }
            for &b in v_str.as_bytes() { if pos < 127 { buf[pos] = b; pos += 1; } }
            for &b in middle { if pos < 127 { buf[pos] = b; pos += 1; } }
            for &b in m_str.as_bytes() { if pos < 127 { buf[pos] = b; pos += 1; } }

            if let Ok(msg) = core::str::from_utf8(&buf[..pos]) {
                issues.push_back(String::from_slice(&env, msg));
            }
        }
    }

    let passed = issues.is_empty();
    AuditResult {
        package_name: entry.name.clone(),
        passed,
        issues,
    }
}

/// @notice Audit all packages in a lockfile snapshot.
///
/// @dev    Iterates over all entries and collects results.
///         Capped at MAX_PACKAGES to prevent unbounded gas consumption.
///
/// @security Bounded iteration prevents DoS via oversized package lists.
///
/// # Arguments
/// * `packages`          – Vector of package entries to audit.
/// * `min_safe_versions` – Map of package names to minimum safe versions.
///
/// # Returns
/// A vector of `AuditResult` for each package (up to MAX_PACKAGES).
pub fn audit_all(
    packages: &Vec<PackageEntry>,
    min_safe_versions: &Map<String, String>,
) -> Vec<AuditResult> {
    let env = soroban_sdk::Env::default();
    let mut results: Vec<AuditResult> = Vec::new(&env);

    let limit = packages.len().min(MAX_PACKAGES);
    for i in 0..limit {
        if let Some(entry) = packages.get(i) {
            results.push_back(audit_package(&entry, min_safe_versions));
        }
    }

    results
}

/// @notice Filter audit results to only those that failed.
///
/// @dev    Returns a new vector containing only failed results.
///         Useful for surfacing actionable issues to the developer.
///
/// # Arguments
/// * `results` – Vector of audit results.
///
/// # Returns
/// A vector containing only results where `passed=false`.
pub fn failing_results(results: &Vec<AuditResult>) -> Vec<AuditResult> {
    let env = soroban_sdk::Env::default();
    let mut failures: Vec<AuditResult> = Vec::new(&env);

    for i in 0..results.len() {
        if let Some(result) = results.get(i) {
            if !result.passed {
                failures.push_back(result);
            }
        }
    }

    failures
}

// ── Lockfile Version Validation ───────────────────────────────────────────────

/// @notice Validate the lockfile version.
///
/// @dev    Only versions 2 and 3 (npm >=7) are accepted.
///         Version 1 (npm <7) lacks integrity hashes for all entries and is
///         considered insecure. Versions 0 and 4+ are unsupported.
///
/// @security Rejecting v1 prevents auditing lockfiles that may lack integrity
///           hashes, which would allow tampered packages to pass undetected.
///
/// # Arguments
/// * `version` – The lockfile version number.
///
/// # Returns
/// `true` if version is 2 or 3, `false` otherwise.
pub fn validate_lockfile_version(version: u32) -> bool {
    version >= MIN_LOCKFILE_VERSION && version <= MAX_LOCKFILE_VERSION
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// @notice Check if any audit results failed.
///
/// @dev    Short-circuits on the first failure for efficiency.
///
/// # Arguments
/// * `results` – Vector of audit results.
///
/// # Returns
/// `true` if any result failed, `false` if all passed.
pub fn has_failures(results: &Vec<AuditResult>) -> bool {
    for i in 0..results.len() {
        if let Some(result) = results.get(i) {
            if !result.passed {
                return true;
            }
        }
    }
    false
}

/// @notice Count the number of failed audits.
///
/// @dev    Useful for reporting and metrics dashboards.
///
/// # Arguments
/// * `results` – Vector of audit results.
///
/// # Returns
/// The count of failed audits as a u32.
pub fn count_failures(results: &Vec<AuditResult>) -> u32 {
    let mut count = 0u32;
    for i in 0..results.len() {
        if let Some(result) = results.get(i) {
            if !result.passed {
                count = count.saturating_add(1);
            }
        }
    }
    count
}
