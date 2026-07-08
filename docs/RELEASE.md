# Digger - Release Checklist

## Version Strategy

Digger uses semantic versioning: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes to CLI interface or output schema
- **MINOR**: New features, new protocol support, new analysis capabilities
- **PATCH**: Bug fixes, documentation updates, corpus additions

Current version: `0.1.0`
Schema version: `2.3` (locked)

## Release Checklist

### Pre-Release

- [ ] All tests pass (`cargo test`)
- [ ] Benchmark passes (`cargo run -- benchmark`)
- [ ] Validate passes (`cargo run -- validate`)
- [ ] Version command works (`cargo run -- version`)
- [ ] CLI commands work (`scan`, `report`, `hypothesis`, `benchmark`, `validate`)
- [ ] Workbench builds (`cd workbench && npm run build`)
- [ ] Documentation is up to date

### Release

- [ ] Update version in `Cargo.toml` (workspace)
- [ ] Update `CHANGELOG.md`
- [ ] Create git tag: `git tag v<version>`
- [ ] Push tag: `git push origin v<version>`
- [ ] GitHub Actions builds cross-platform binaries
- [ ] Create GitHub Release with release notes
- [ ] Verify binaries work on all platforms

### Post-Release

- [ ] Verify `cargo install --git` works
- [ ] Verify binaries download and run
- [ ] Update documentation links
- [ ] Announce release

## Cross-Platform Builds

| Platform | Target | Status |
|----------|--------|--------|
| Linux x86_64 | `x86_64-unknown-linux-gnu` | ✅ |
| macOS x86_64 | `x86_64-apple-darwin` | ✅ |
| macOS ARM64 | `aarch64-apple-darwin` | ✅ |
| Windows x86_64 | `x86_64-pc-windows-msvc` | ✅ |

## Artifacts

Each release produces:
- `digger-linux-amd64`
- `digger-macos-amd64`
- `digger-macos-aarch64`
- `digger-windows-amd64.exe`

## Changelog Format

```markdown
## [version] - YYYY-MM-DD

### Added
- Phase 4.7: Packaging & Distribution
- Documentation (INSTALL, QUICKSTART, CLI_REFERENCE, WORKBENCH, BENCHMARK_CORPUS)
- GitHub Actions CI/CD
- Cross-platform release workflow

### Changed
- Enhanced version command output
- Enhanced validate command

### Fixed
- (none)
```
