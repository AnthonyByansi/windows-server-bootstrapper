# Quick Reference: Versioning & Git Tags

## Current Status

- **Latest Version:** v1.0.0
- **Release Date:** 2026-01-07
- **View Release:** `git show v1.0.0`

## Common Commands

### Viewing Version Information

```bash
# List all tags
git tag

# Show details of a specific tag
git show v1.0.0

# Show all tags with commit messages
git tag -l --format='%(refname:short) - %(contents:subject)'

# Show tags with dates
git tag -l --format='%(refname:short) (%(creatordate:short))'
```

### Creating a New Release

```powershell
# Using the helper script (recommended)
.\Manage-Version.ps1 -NewVersion "1.1.0" -Message "Add new features"

# Or manually:

# 1. Update version numbers in files
#    - Bootstrap-Server.ps1
#    - README.md
#    - PROJECT-SUMMARY.md

# 2. Update CHANGELOG.md with release notes

# 3. Commit changes
git add -A
git commit -m "chore: Bump version to 1.1.0"

# 4. Create annotated tag
git tag -a v1.1.0 -m "Release version 1.1.0 - Your release notes"

# 5. Push to remote
git push origin main --tags
```

### Git Workflow

```bash
# After creating a release tag, push to remote
git push origin v1.0.0

# Or push all tags at once
git push origin --tags

# Checkout a specific version
git checkout v1.0.0

# Create new branch from a tag
git checkout -b release-1.0.0 v1.0.0
```

## Version Format Reference

| Example | Meaning |
|---------|---------|
| `1.0.0` | Initial release |
| `1.1.0` | New features added |
| `1.1.1` | Bug fix |
| `2.0.0` | Major breaking changes |
| `1.0.0-alpha` | Alpha release |
| `1.0.0-beta` | Beta release |
| `1.0.0-rc.1` | Release candidate |

## Files to Update for New Release

When creating a new version, update these files:

1. **Bootstrap-Server.ps1** - Update `.VERSION` in help section
2. **README.md** - Update version badge
3. **PROJECT-SUMMARY.md** - Update version reference
4. **CHANGELOG.md** - Add new release section with changes

## .gitignore Configuration

The following directories are excluded from git commits:

- **Logs/** - Execution logs
- **Backups/** - Configuration backups
- **Reports/** - HTML compliance reports

This ensures sensitive server data is not committed to the repository.

## Resources

- [Semantic Versioning](https://semver.org/)
- [VERSIONING.md](VERSIONING.md) - Full versioning guidelines
- [CHANGELOG.md](CHANGELOG.md) - Complete release history
