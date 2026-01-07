# Semantic Versioning Guidelines

This project follows [Semantic Versioning 2.0.0](https://semver.org/) for releases.

## Version Format

Versions are in the format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Incompatible API or behavior changes, breaking changes
- **MINOR**: New features added in a backwards-compatible manner
- **PATCH**: Bug fixes and patches in a backwards-compatible manner

## Examples

- `1.0.0` - Initial release
- `1.1.0` - New feature added
- `1.1.1` - Bug fix
- `2.0.0` - Major breaking change

## Release Process

### 1. Update Version References

Update the version in the main script file:

```powershell
# In Bootstrap-Server.ps1
.VERSION
    Version: 1.1.0
```

### 2. Update Changelog

Document changes in `CHANGELOG.md` under the new version header:

```markdown
## [1.1.0] - 2026-01-15

### Added
- New feature description

### Fixed
- Bug fix description
```

### 3. Create Git Tag

Create a lightweight or annotated tag:

```bash
# Annotated tag (recommended)
git tag -a v1.1.0 -m "Release version 1.1.0"

# Or lightweight tag
git tag v1.1.0
```

### 4. Push Tag to Remote

```bash
# Push specific tag
git push origin v1.1.0

# Or push all tags
git push origin --tags
```

## Viewing Tags

```bash
# List all tags
git tag

# Show specific tag details
git show v1.1.0

# List tags with commit info
git tag -l --format='%(refname:short) - %(contents:subject) (%(creatordate:short))'
```

## Pre-Release and Build Metadata

For pre-releases or builds, append additional identifiers:

- `1.0.0-alpha` - Alpha release
- `1.0.0-beta` - Beta release
- `1.0.0-rc.1` - Release candidate
- `1.0.0+build.1` - Build metadata

## Current Version

**Latest Release**: 1.0.0  
**Release Date**: 2026-01-06

See [CHANGELOG.md](CHANGELOG.md) for complete release history.
