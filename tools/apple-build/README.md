# Reviewed Apple Host Tools

The build workflows compile the exact source pins used by the A8-A11 runtime for both supported Mac architectures:

- Apple silicon (`arm64`)
- Intel/Hackintosh (`x86_64`)

Each build produces:

- `bin/gaster`
- `bin/irecovery`
- source licence files
- complete build log
- `SHA256SUMS`
- `build-receipt.json`
- architecture-specific compressed artifact

The receipt records source commits, host/toolchain details, binary type, byte length, SHA-256, smoke-test status and build-log SHA-256. Static project dependencies are used for iRecovery, and the workflow rejects binaries linked to the temporary build prefix or Homebrew Cellar.

Tracked receipts contain metadata and hashes only. Executables remain GitHub Actions artifacts and are never committed to the repository.

A reviewed build performs no device operation. Device access is isolated to the protected self-hosted `Authorised Apple Lab` workflow.
