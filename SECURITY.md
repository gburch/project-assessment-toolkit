# Security policy

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/gburch/project-assessment-toolkit/security/advisories/new). Include the affected version or commit, impact, and a minimal synthetic reproduction. Keep private source, assessment exports, credentials and exploit details out of public issues and pull requests.

If private reporting is unavailable, open a public issue requesting a private contact without including sensitive details. Maintainers will confirm affected versions and coordinate a fix.

## Local data and trust boundaries

PAT assessment scans read local source and supplied reports without executing the assessed project or contacting its services. Its separate test-value collectors can execute owner-selected tests when explicitly invoked. Treat project text and imported reports as untrusted data; tool diagnostics and suggested fixes do not authorize source changes.

State and exports can contain source excerpts, local paths, review findings and goals. Keep them outside assessed repositories, protect backups, and share only material you are authorized to disclose. Redaction is not a guarantee that an export is safe to publish. Use synthetic fixtures for public reproductions.

The local report UI uses loopback access, and the stdio MCP server requires explicit allowed roots. Saved reads recheck source and imported-report authority. Static analysis does not certify deployed security or replace a project-specific security review. See the [user guide](docs/PROJECT_ASSESS.md#agent-connection-and-limits) for evidence limits and [state recovery](docs/PROJECT_ASSESS.md#local-state-and-updates).
