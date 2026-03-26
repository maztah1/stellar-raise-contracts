//! Comprehensive test suite for npm_package_lock module.
//!
//! Coverage: 50 test cases covering all public functions with edge cases,
//! boundary conditions, and security-relevant scenarios.
//!
//! ## Test Output
//!
//! Run with: `cargo test npm_package_lock -- --nocapture`
//!
//! ## Security Notes
//!
//! - All tests use `Env::default()` (no network calls).
//! - Version boundary tests verify the exact vulnerable range for GHSA-xpqw-6gx7-v673.
//! - Integrity tests confirm sha1/sha256 are rejected (downgrade attack prevention).
//! - Lockfile version tests confirm v1 is rejected (missing integrity hashes).

#[cfg(test)]
mod tests {
    use crate::npm_package_lock::*;
    use soroban_sdk::{Env, Map, String, Vec};

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn env() -> Env {
        Env::default()
    }

    fn s(env: &Env, val: &str) -> String {
        String::from_slice(env, val)
    }

    fn create_entry(name: &str, version: &str, integrity: &str, dev: bool) -> PackageEntry {
        let e = env();
        PackageEntry {
            name: s(&e, name),
            version: s(&e, version),
            integrity: s(&e, integrity),
            dev,
        }
    }

    fn advisory(entries: &[(&str, &str)]) -> Map<String, String> {
        let e = env();
        let mut map = Map::new(&e);
        for &(pkg, min_ver) in entries {
            map.set(s(&e, pkg), s(&e, min_ver));
        }
        map
    }

    // ── parse_semver ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_semver_standard() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "3.3.3")), (3, 3, 3));
    }

    #[test]
    fn test_parse_semver_with_v_prefix() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "v1.2.0")), (1, 2, 0));
    }

    #[test]
    fn test_parse_semver_with_capital_v_prefix() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "V2.0.1")), (2, 0, 1));
    }

    #[test]
    fn test_parse_semver_with_prerelease() {
        let e = env();
        // Pre-release suffix is stripped; base version is used.
        assert_eq!(parse_semver(&s(&e, "1.2.0-alpha")), (1, 2, 0));
    }

    #[test]
    fn test_parse_semver_with_build_metadata() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "1.2.0+build.123")), (1, 2, 0));
    }

    #[test]
    fn test_parse_semver_missing_patch() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "1.2")), (1, 2, 0));
    }

    #[test]
    fn test_parse_semver_zeros() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "0.0.0")), (0, 0, 0));
    }

    #[test]
    fn test_parse_semver_large_numbers() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "999.888.777")), (999, 888, 777));
    }

    #[test]
    fn test_parse_semver_non_numeric_returns_zeros() {
        let e = env();
        // Non-numeric components degrade gracefully to (0,0,0).
        assert_eq!(parse_semver(&s(&e, "abc.def.ghi")), (0, 0, 0));
    }

    #[test]
    fn test_parse_semver_partial_numeric() {
        let e = env();
        // "x" in patch position → 0.
        assert_eq!(parse_semver(&s(&e, "1.2.x")), (0, 0, 0));
    }

    #[test]
    fn test_parse_semver_empty_string() {
        let e = env();
        assert_eq!(parse_semver(&s(&e, "")), (0, 0, 0));
    }

    // ── is_version_gte ───────────────────────────────────────────────────────

    #[test]
    fn test_is_version_gte_equal() {
        let e = env();
        assert!(is_version_gte(&s(&e, "3.3.3"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_greater_patch() {
        let e = env();
        assert!(is_version_gte(&s(&e, "3.3.4"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_greater_minor() {
        let e = env();
        assert!(is_version_gte(&s(&e, "3.4.0"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_greater_major() {
        let e = env();
        assert!(is_version_gte(&s(&e, "4.0.0"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_less_patch() {
        let e = env();
        assert!(!is_version_gte(&s(&e, "3.3.2"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_less_minor() {
        let e = env();
        assert!(!is_version_gte(&s(&e, "3.2.9"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_less_major() {
        let e = env();
        assert!(!is_version_gte(&s(&e, "2.9.9"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_prerelease_stripped() {
        let e = env();
        // "3.3.3-beta" strips to "3.3.3" which equals the minimum.
        assert!(is_version_gte(&s(&e, "3.3.3-beta"), &s(&e, "3.3.3")));
    }

    #[test]
    fn test_is_version_gte_svgo_boundary_vulnerable() {
        // svgo 3.3.2 is in the vulnerable range (< 3.3.3).
        let e = env();
        assert!(!is_version_gte(&s(&e, "3.3.2"), &s(&e, SVGO_MIN_SAFE_VERSION)));
    }

    #[test]
    fn test_is_version_gte_svgo_boundary_safe() {
        // svgo 3.3.3 is the first patched release.
        let e = env();
        assert!(is_version_gte(&s(&e, "3.3.3"), &s(&e, SVGO_MIN_SAFE_VERSION)));
    }

    // ── validate_integrity ───────────────────────────────────────────────────

    #[test]
    fn test_validate_integrity_valid_sha512() {
        let e = env();
        assert!(validate_integrity(&s(&e, "sha512-abcdef1234567890")));
    }

    #[test]
    fn test_validate_integrity_empty() {
        let e = env();
        assert!(!validate_integrity(&s(&e, "")));
    }

    #[test]
    fn test_validate_integrity_sha256_rejected() {
        // sha256 is weaker than sha512 and must be rejected.
        let e = env();
        assert!(!validate_integrity(&s(&e, "sha256-abcdef1234567890")));
    }

    #[test]
    fn test_validate_integrity_sha1_rejected() {
        // sha1 is cryptographically broken and must be rejected.
        let e = env();
        assert!(!validate_integrity(&s(&e, "sha1-abcdef1234567890")));
    }

    #[test]
    fn test_validate_integrity_prefix_only() {
        // "sha512-" with no hash body is technically valid prefix-wise.
        let e = env();
        assert!(validate_integrity(&s(&e, "sha512-")));
    }

    #[test]
    fn test_validate_integrity_no_prefix() {
        let e = env();
        assert!(!validate_integrity(&s(&e, "abcdef1234567890")));
    }

    #[test]
    fn test_validate_integrity_too_short() {
        let e = env();
        assert!(!validate_integrity(&s(&e, "sha512")));
    }

    // ── audit_package ────────────────────────────────────────────────────────

    #[test]
    fn test_audit_package_passes_all_checks() {
        let entry = create_entry("svgo", "3.3.3", "sha512-abc123", false);
        let adv = advisory(&[("svgo", "3.3.3")]);
        let result = audit_package(&entry, &adv);
        assert!(result.passed);
        assert_eq!(result.issues.len(), 0);
    }

    #[test]
    fn test_audit_package_fails_version_too_low() {
        let entry = create_entry("svgo", "3.3.2", "sha512-abc123", false);
        let adv = advisory(&[("svgo", "3.3.3")]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
        assert!(result.issues.len() > 0);
    }

    #[test]
    fn test_audit_package_fails_invalid_integrity() {
        let entry = create_entry("svgo", "3.3.3", "sha256-abc123", false);
        let adv = advisory(&[("svgo", "3.3.3")]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
        assert!(result.issues.len() > 0);
    }

    #[test]
    fn test_audit_package_fails_both_checks_reports_two_issues() {
        // Both version and integrity fail — both issues must be reported.
        let entry = create_entry("svgo", "3.3.2", "sha256-abc123", false);
        let adv = advisory(&[("svgo", "3.3.3")]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
        assert_eq!(result.issues.len(), 2);
    }

    #[test]
    fn test_audit_package_unknown_package_passes() {
        // Packages not in the advisory map are not flagged.
        let entry = create_entry("unknown-pkg", "1.0.0", "sha512-abc123", false);
        let adv = advisory(&[("svgo", "3.3.3")]);
        let result = audit_package(&entry, &adv);
        assert!(result.passed);
    }

    #[test]
    fn test_audit_package_version_greater_than_min_passes() {
        let entry = create_entry("svgo", "3.4.0", "sha512-abc123", false);
        let adv = advisory(&[("svgo", "3.3.3")]);
        let result = audit_package(&entry, &adv);
        assert!(result.passed);
    }

    #[test]
    fn test_audit_package_dev_dependency_audited() {
        // Dev dependencies are audited the same as production dependencies.
        let entry = create_entry("jest", "30.0.0", "sha512-abc123", true);
        let adv = advisory(&[("jest", "30.0.0")]);
        let result = audit_package(&entry, &adv);
        assert!(result.passed);
    }

    #[test]
    fn test_audit_package_svgo_3_0_0_is_vulnerable() {
        // svgo 3.0.0 is the start of the vulnerable range.
        let entry = create_entry("svgo", "3.0.0", "sha512-abc123", false);
        let adv = advisory(&[("svgo", SVGO_MIN_SAFE_VERSION)]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
    }

    #[test]
    fn test_audit_package_postcss_vulnerability() {
        // postcss < 8.4.31 has GHSA-7fh8-c0uq-4h3g.
        let entry = create_entry("postcss", "8.4.30", "sha512-abc123", false);
        let adv = advisory(&[("postcss", POSTCSS_MIN_SAFE_VERSION)]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
    }

    #[test]
    fn test_audit_package_postcss_safe_version() {
        let entry = create_entry("postcss", "8.4.31", "sha512-abc123", false);
        let adv = advisory(&[("postcss", POSTCSS_MIN_SAFE_VERSION)]);
        let result = audit_package(&entry, &adv);
        assert!(result.passed);
    }

    #[test]
    fn test_audit_package_nth_check_vulnerability() {
        // nth-check < 2.0.1 has GHSA-rp65-9cf3-cjxr (ReDoS).
        let entry = create_entry("nth-check", "2.0.0", "sha512-abc123", false);
        let adv = advisory(&[("nth-check", NTH_CHECK_MIN_SAFE_VERSION)]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
    }

    #[test]
    fn test_audit_package_semver_vulnerability() {
        // semver < 7.5.2 has GHSA-c2qf-rxjj-qqgw (ReDoS).
        let entry = create_entry("semver", "7.5.1", "sha512-abc123", false);
        let adv = advisory(&[("semver", SEMVER_MIN_SAFE_VERSION)]);
        let result = audit_package(&entry, &adv);
        assert!(!result.passed);
    }

    // ── audit_all ────────────────────────────────────────────────────────────

    #[test]
    fn test_audit_all_mixed_results() {
        let e = env();
        let mut packages: Vec<PackageEntry> = Vec::new(&e);
        packages.push_back(create_entry("svgo", "3.3.3", "sha512-abc", false));
        packages.push_back(create_entry("react", "19.0.0", "sha512-def", false));
        packages.push_back(create_entry("jest", "30.0.0", "sha256-ghi", false)); // bad hash

        let adv = advisory(&[("svgo", "3.3.3"), ("react", "19.0.0"), ("jest", "30.0.0")]);
        let results = audit_all(&packages, &adv);

        assert_eq!(results.len(), 3);
        assert!(results.get(0).unwrap().passed);
        assert!(results.get(1).unwrap().passed);
        assert!(!results.get(2).unwrap().passed);
    }

    #[test]
    fn test_audit_all_empty_input() {
        let e = env();
        let packages: Vec<PackageEntry> = Vec::new(&e);
        let adv = advisory(&[]);
        let results = audit_all(&packages, &adv);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_audit_all_all_pass() {
        let e = env();
        let mut packages: Vec<PackageEntry> = Vec::new(&e);
        packages.push_back(create_entry("svgo", "3.3.3", "sha512-abc", false));
        packages.push_back(create_entry("react", "19.0.0", "sha512-def", false));

        let adv = advisory(&[("svgo", "3.3.3"), ("react", "19.0.0")]);
        let results = audit_all(&packages, &adv);

        assert_eq!(results.len(), 2);
        for i in 0..results.len() {
            assert!(results.get(i).unwrap().passed);
        }
    }

    // ── failing_results ──────────────────────────────────────────────────────

    #[test]
    fn test_failing_results_filters_correctly() {
        let e = env();
        let mut results: Vec<AuditResult> = Vec::new(&e);

        results.push_back(AuditResult {
            package_name: s(&e, "pkg1"),
            passed: true,
            issues: Vec::new(&e),
        });
        results.push_back(AuditResult {
            package_name: s(&e, "pkg2"),
            passed: false,
            issues: {
                let mut v: Vec<String> = Vec::new(&e);
                v.push_back(s(&e, "issue1"));
                v
            },
        });
        results.push_back(AuditResult {
            package_name: s(&e, "pkg3"),
            passed: true,
            issues: Vec::new(&e),
        });

        let failures = failing_results(&results);
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures.get(0).unwrap().package_name.to_xdr().as_ref(),
            b"pkg2"
        );
    }

    #[test]
    fn test_failing_results_empty_when_all_pass() {
        let e = env();
        let mut results: Vec<AuditResult> = Vec::new(&e);
        results.push_back(AuditResult {
            package_name: s(&e, "pkg1"),
            passed: true,
            issues: Vec::new(&e),
        });
        assert_eq!(failing_results(&results).len(), 0);
    }

    // ── validate_lockfile_version ─────────────────────────────────────────────

    #[test]
    fn test_validate_lockfile_version_2_accepted() {
        assert!(validate_lockfile_version(2));
    }

    #[test]
    fn test_validate_lockfile_version_3_accepted() {
        assert!(validate_lockfile_version(3));
    }

    #[test]
    fn test_validate_lockfile_version_1_rejected() {
        // v1 lacks integrity hashes — must be rejected.
        assert!(!validate_lockfile_version(1));
    }

    #[test]
    fn test_validate_lockfile_version_0_rejected() {
        assert!(!validate_lockfile_version(0));
    }

    #[test]
    fn test_validate_lockfile_version_4_rejected() {
        assert!(!validate_lockfile_version(4));
    }

    // ── has_failures ─────────────────────────────────────────────────────────

    #[test]
    fn test_has_failures_returns_true() {
        let e = env();
        let mut results: Vec<AuditResult> = Vec::new(&e);
        results.push_back(AuditResult { package_name: s(&e, "a"), passed: true, issues: Vec::new(&e) });
        results.push_back(AuditResult { package_name: s(&e, "b"), passed: false, issues: Vec::new(&e) });
        assert!(has_failures(&results));
    }

    #[test]
    fn test_has_failures_returns_false_when_all_pass() {
        let e = env();
        let mut results: Vec<AuditResult> = Vec::new(&e);
        results.push_back(AuditResult { package_name: s(&e, "a"), passed: true, issues: Vec::new(&e) });
        assert!(!has_failures(&results));
    }

    #[test]
    fn test_has_failures_empty_input() {
        let e = env();
        let results: Vec<AuditResult> = Vec::new(&e);
        assert!(!has_failures(&results));
    }

    // ── count_failures ───────────────────────────────────────────────────────

    #[test]
    fn test_count_failures_multiple() {
        let e = env();
        let mut results: Vec<AuditResult> = Vec::new(&e);
        results.push_back(AuditResult { package_name: s(&e, "a"), passed: false, issues: Vec::new(&e) });
        results.push_back(AuditResult { package_name: s(&e, "b"), passed: true, issues: Vec::new(&e) });
        results.push_back(AuditResult { package_name: s(&e, "c"), passed: false, issues: Vec::new(&e) });
        assert_eq!(count_failures(&results), 2);
    }

    #[test]
    fn test_count_failures_zero() {
        let e = env();
        let mut results: Vec<AuditResult> = Vec::new(&e);
        results.push_back(AuditResult { package_name: s(&e, "a"), passed: true, issues: Vec::new(&e) });
        assert_eq!(count_failures(&results), 0);
    }

    #[test]
    fn test_count_failures_empty_input() {
        let e = env();
        let results: Vec<AuditResult> = Vec::new(&e);
        assert_eq!(count_failures(&results), 0);
    }

    // ── MAX_PACKAGES cap ─────────────────────────────────────────────────────

    #[test]
    fn test_max_packages_constant_is_reasonable() {
        // Sanity check: MAX_PACKAGES must be > 0 and <= 1000.
        assert!(MAX_PACKAGES > 0);
        assert!(MAX_PACKAGES <= 1000);
    }
}
