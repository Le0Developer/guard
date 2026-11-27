# Root Go cutover

User requested replacing the Rust version with Go and updating CI/deployment.
Promote cmd/internal/sql/sqlc/module/docs to root, use canonical repository module
path, remove tracked Rust source/manifests/templates and obsolete editor config,
preserve existing ignored local databases/configuration and caches. Preserve
GHCR tags/multiarchitecture publishing behind PostgreSQL race tests, formatting,
SQL generation and vet. Update root Compose, Docker allowlist, env examples,
Makefile and README. Verify generated files, root builds/tests, Linux cross
compiles, workflow and Compose validation; no remote push or publication.

Verification completed:
- Root PostgreSQL race suite on Go1.27.3: PASS (app64.852s).
- Root PostgreSQL full suite on Go1.26.0: PASS (app9.502s).
- go vet, native build and static Linux amd64/arm64 cross-builds: PASS.
- actionlint, YAML parsing, sqlc vet and unchanged regeneration, formatting and diff whitespace checks: PASS.
- Docker Compose CLI configuration validation: PASS, including database persistence/private port and required password checks. Temporary validation directory contained only sample configuration; the existing .env was not read or modified.
- Independent cutover review: no blockers.

No local Docker daemon is installed, so container image assembly was not executed locally; the gated GitHub Actions image job builds both architectures. No commit, push, registry publication or deployment was performed. Existing ignored SQLite/config files and legacy build caches were preserved.
