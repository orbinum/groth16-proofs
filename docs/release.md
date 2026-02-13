# Release Process

This document explains how releases are managed for `groth16-proofs`.

## Overview

Releases are **fully automated** using:
- **cargo-release**: Manages version bumping, CHANGELOG updates, and tagging
- **GitHub Actions**: CI/CD pipeline for building, testing, and publishing
- **CHANGELOG.md**: Automatically updated by cargo-release

## How It Works

### Automated CHANGELOG Updates

`cargo-release` automatically updates the CHANGELOG:

1. Moves `[Unreleased]` changes to a new version section
2. Adds the current date
3. Creates version comparison links
4. Commits the changes with message: `chore(release): {{version}}`
5. Creates a git tag

**No manual CHANGELOG editing required!** Just keep adding changes under `[Unreleased]`.

## Release Process

### 1. Add Changes to CHANGELOG

Keep [CHANGELOG.md](../CHANGELOG.md) updated with changes under `[Unreleased]`:

```markdown
## [Unreleased]

### Added
- New decimal witness format support
- `generate_proof_from_decimal_wasm()` function

### Changed
- Updated documentation

### Fixed
- Bug in bounds checking
```

### 2. Bump Version in Cargo.toml

Update the version manually:

```toml
[package]
name = "groth16-proofs"
version = "1.1.0"  # ← Change this
```

### 3. Commit and Push

```bash
git add Cargo.toml
git commit -m "chore: bump version to 1.1.0"
git push origin main
```

### 4. Automatic Pipeline Execution

The GitHub Actions workflow will:

1. ✅ Install cargo-release
2. ✅ Run `cargo release` to update CHANGELOG automatically
3. ✅ Create git tag (e.g., `v1.1.0`)
4. ✅ Push CHANGELOG commit and tag
5. ✅ Build WASM with wasm-pack
6. ✅ Create GitHub Release with WASM artifact
7. ✅ Publish to crates.io

**The CHANGELOG is automatically updated from [Unreleased] to the new version!**

## Manual Changelog Management (Legacy)

If you prefer manual control, you can update CHANGELOG.md before step 2:

### Structure

```markdown
# Changelog

## [Unreleased]
### Added
- New features

### Fixed
- Bug fixes

## [0.1.0] - 2026-02-12
### Added
- Initial release
```

### Updating Before Release

Before triggering a release, update `CHANGELOG.md`:

1. Move items from `[Unreleased]` to a new version section
2. Add today's date
3. Add link references at bottom

**Example**:

```markdown
## [Unreleased]
### Added
- Feature coming soon

## [0.2.0] - 2026-02-15
### Added
- New proof generation improvements
- Performance optimizations

### Fixed
- Iterator bounds checking in witness circuit
```

Then commit:
```bash
git add CHANGELOG.md
git commit -m "chore(changelog): Update for v0.2.0"
```

## Automated Release Trigger

Push any commit with changes to `Cargo.toml` or `src/`:

```bash
git add Cargo.toml src/
git commit -m "feat: add new feature"
git push origin main
```

The GitHub Actions pipeline will:

### 1. **CI Checks** (`.github/workflows/ci.yml`)
- ✅ Run cargo test
- ✅ Check formatting (cargo fmt)
- ✅ Run clippy lints

### 2. **Release Job** (`.github/workflows/release.yml`)

#### compile and publish to crates.io:

```yaml
- Build WASM with wasm-pack
- Publish Rust crate to crates.io
- Run cargo-release to bump version
- Create git tag (v0.2.0)
```

#### Create GitHub Release:

```yaml
- Package WASM as "orb-groth16-proof.tar.gz"
- Upload as release asset
- Create release with tag
```

## Configuration Files

### `.cargo/release.toml`

Controls release behavior:

```toml
[release]
update-crates-io = true          # Auto-publish to crates.io
consolidate-pushes = true        # Single push for all changes
changelog-update = true          # Update CHANGELOG.md
pre-release-commit-message = "chore(release): {{version}}"
tag-name = "v{{version}}"        # Git tag format
pre-release-hook = [
    # Runs wasm-pack before release
    { cmd = "wasm-pack", args = [...] }
]
allow-branch = ["main"]          # Only release from main
```

### `.github/workflows/release.yml`

Defines the release pipeline:

- **Triggers on**: Changes to `Cargo.toml` or `src/**` on `main` branch
- **Perms required**:
  - `contents: write` (GitHub release)
  - `packages: write` (npm publish)

Key steps:
1. Build WASM
2. Package as `orb-groth16-proof.tar.gz`
3. Publish to crates.io
4. Run cargo-release punch, `orb-groth16-proof.tar.gz`
5. Publish WASM to npm

## Required Secrets

Configure in GitHub `Settings > Secrets and variables > Actions`:

| Secret | Source | Purpose |
|--------|--------|---------|
| `CARGO_REGISTRY_TOKEN` | https://crates.io/me | Publish to crates.io |
| `NODE_AUTH_TOKEN` | https://npmjs.com/settings/tokens | Publish to npm |

## Versioning

This project follows **Semantic Versioning**:

- **MAJOR** (0.x.0): Breaking API changes
- **MINOR** (x.1.0): New features (backward compatible)
- **PATCH** (x.x.1): Bug fixes

Example progression:
```
0.1.0  → 0.2.0  (added new circuits) 
0.2.0  → 0.2.1  (fixed bug)
0.2.1  → 1.0.0  (stable API)
```

## What Gets Published

### GitHub Release

**Asset**: `orb-groth16-proof.tar.gz`
- Contains all WASM build artifacts
- `.wasm` binary
- `.js` wrapper
- `.d.ts` types
- `package.json`

**Download**:
```bash
curl -L https://github.com/orbinum/groth16-proofs/releases/download/v0.2.0/orb-groth16-proof.tar.gz -o pkg.tar.gz
tar -xzf pkg.tar.gz
```

### crates.io

Published as: `groth16-proofs`

**Install**:
```toml
[dependencies]
groth16-proofs = "0.2"
```

### WASM

Not published to NPM. Download precompiled binaries from GitHub Releases:

**Download**:
```bash
curl -L https://github.com/orbinum/groth16-proofs/releases/download/v0.2.0/orb-groth16-proof.tar.gz -o wasm.tar.gz
tar -xzf wasm.tar.gz -C ./wasm
```

## Manual Release (Fallback)

If you need to manually trigger a release:

```bash
# Install cargo-release
cargo install cargo-release

# Dry-run to see what would happen
cargo release --no-confirm

# Execute release
cargo release --no-confirm --execute
```

This will:
1. Bump version patch (0.1.0 → 0.1.1)
2. Update `Cargo.toml`
3. Create commit and tag
4. Push to crates.io
5. Create GitHub release (manual)
6. Push WASM to npm (manual)

## Troubleshooting

### "cargo-release failed"

Check:
- `CARGO_REGISTRY_TOKEN` is valid and hasn't expired
- You have push access to main branch
- Version in `Cargo.toml` matches git tag

### "npm publish failed"

Verify:
- `NODE_AUTH_TOKEN` is set correctly
- Package version is unique (not already published)
- `pkg/package.json` exists and has correct version

### "Changelog not updated"

Manual fix:
1. Update `CHANGELOG.md`
2. Commit: `git commit -m "chore(Release): Add v0.2.0"`
3. Push: `git push origin main`

## Example Release Workflow

From start to finish:

```bash
# 1. Make changes
git checkout -b feat/new-circuit
# ... edit src/
git add src/
git commit -m "feat: add transfer circuit support"

# 2. Update changelog
vim CHANGELOG.md
# Move items from [Unreleased] to [0.2.0]
git add CHANGELOG.md
git commit -m "chore(changelog): Update for v0.2.0"

# 3. Update version (optional, cargo-release does this)
# Edit Cargo.toml to bump version manually, or let cargo-release do it

# 4. Push and trigger release
git push origin feat/new-circuit
# Create PR, get review
# Merge to main

git push origin main
# GitHub Actions detects changes to src/ and Cargo.toml
# Automatically runs full release pipeline
# ✅ Tests pass
# ✅ WASM builds
# ✅ Published to crates.io
# ✅ GitHub release created with orb-groth16-proof.tar.gz
```

Then verify:
```bash
# Check on crates.io
curl https://crates.io/api/v1/crates/groth16-proofs/0.2.0

# Check GitHub
curl https://api.github.com/repos/orbinum/groth16-proofs/releases/latest
```

## FAQ

**Q: How often should we release?**  
A: Whenever there are meaningful changes. Not required to be frequent.

**Q: Can we skip a version?**  
A: No, cargo-release auto-increments. Always use semantic versioning.

**Q: What if release fails midway?**  
A: cargo-release is transactional. No partial states. Restart the workflow.

**Q: Can I release from a branch other than main?**  
A: No, cargo-release is configured to only work from main.

**Q: Do I need to update CHANGELOG.md manually?**  
A: Yes. cargo-release handles version bumping, you handle changelog organization.

## See Also

- [Development Guide](../DEVELOPMENT.md)
- [Contributing Guide](../CONTRIBUTING.md)
- [cargo-release docs](https://github.com/crate-ci/cargo-release)
