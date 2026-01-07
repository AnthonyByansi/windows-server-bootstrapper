<#
.SYNOPSIS
    Version management helper script for the Windows Server Bootstrap project

.DESCRIPTION
    Manages semantic versioning, updates version numbers across files, and creates git tags.

.PARAMETER NewVersion
    The new version number in format MAJOR.MINOR.PATCH

.PARAMETER Message
    Release message/notes for the git tag

.EXAMPLE
    .\Manage-Version.ps1 -NewVersion "1.1.0" -Message "Add new features"

.NOTES
    Requires git to be available in PATH
    Must be run from the project root directory
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$NewVersion,

    [Parameter(Mandatory = $true)]
    [string]$Message
)

# Validate version format
if ($NewVersion -notmatch '^\d+\.\d+\.\d+') {
    Write-Error "Invalid version format. Use MAJOR.MINOR.PATCH (e.g., 1.1.0)"
    exit 1
}

# Files to update with version
$VersionFiles = @(
    @{
        Path    = ".\Bootstrap-Server.ps1"
        Pattern = "Version: \d+\.\d+\.\d+"
        Replacement = "Version: $NewVersion"
    },
    @{
        Path    = ".\README.md"
        Pattern = "\*\*Version:\*\* \d+\.\d+\.\d+"
        Replacement = "**Version:** $NewVersion"
    },
    @{
        Path    = ".\PROJECT-SUMMARY.md"
        Pattern = "\*\*Version\*\*: \d+\.\d+\.\d+"
        Replacement = "**Version**: $NewVersion"
    }
)

Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "  Version Management Tool" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`n" -ForegroundColor Cyan

Write-Host "Updating version to: $NewVersion" -ForegroundColor Yellow

# Update version in files
foreach ($file in $VersionFiles) {
    if (Test-Path $file.Path) {
        Write-Host "  ✓ Updating $($file.Path)" -ForegroundColor Green
        $content = Get-Content $file.Path -Raw
        $newContent = $content -replace $file.Pattern, $file.Replacement
        Set-Content $file.Path $newContent -NoNewline
    }
}

# Create changelog entry
Write-Host "  ✓ Update CHANGELOG.md with release notes" -ForegroundColor Yellow
Write-Host "    Add your release notes under:" -ForegroundColor Gray
Write-Host "    ## [$NewVersion] - $(Get-Date -Format 'yyyy-MM-dd')" -ForegroundColor Gray

# Create git commit
Write-Host "`nCreating git commit..." -ForegroundColor Cyan
& git add -A
& git commit -m "chore: Bump version to $NewVersion"

# Create git tag
Write-Host "Creating git tag v$NewVersion..." -ForegroundColor Cyan
& git tag -a "v$NewVersion" -m "Release version $NewVersion - $Message"

Write-Host "`n✓ Version update completed!" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Review your changes: git log --oneline -3" -ForegroundColor Gray
Write-Host "  2. Push to remote: git push origin main --tags" -ForegroundColor Gray
Write-Host "`n"
