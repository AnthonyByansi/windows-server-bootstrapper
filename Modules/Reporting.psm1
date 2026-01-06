<#
.SYNOPSIS
    Reporting Module

.DESCRIPTION
    Generates HTML compliance and execution reports
#>

function New-ComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Results,
        
        [Parameter(Mandatory = $true)]
        [string]$ReportPath,
        
        [Parameter(Mandatory = $false)]
        [array]$ChangesMade
    )
    
    Write-Log "Generating compliance report..." -Level Info
    
    try {
        $html = Get-HTMLReportTemplate -Results $Results -ChangesMade $ChangesMade
        $html | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Log "✓ Report generated: $ReportPath" -Level Success
        
    } catch {
        Write-Log "Failed to generate report: $($_.Exception.Message)" -Level Error
    }
}

function Get-HTMLReportTemplate {
    param(
        $Results,
        $ChangesMade
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $hostname = $env:COMPUTERNAME
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    
    # Calculate statistics
    $totalChecks = 0
    $passedChecks = 0
    $failedChecks = 0
    $warningChecks = 0
    
    foreach ($category in $Results.Categories.Values) {
        foreach ($check in $category.Checks) {
            $totalChecks++
            switch ($check.Status) {
                'Pass' { $passedChecks++ }
                'Fail' { $failedChecks++ }
                'Warning' { $warningChecks++ }
            }
        }
    }
    
    $compliancePercent = if ($totalChecks -gt 0) {
        [math]::Round(($passedChecks / $totalChecks) * 100, 1)
    } else { 0 }
    
    # Generate category rows
    $categoryRows = ""
    foreach ($category in $Results.Categories.Values) {
        $categoryRows += Get-CategoryHTML -Category $category
    }
    
    # Generate changes list
    $changesHTML = ""
    if ($ChangesMade -and $ChangesMade.Count -gt 0) {
        foreach ($change in $ChangesMade) {
            $changesHTML += "<li>$change</li>"
        }
    } else {
        $changesHTML = "<li><em>No changes were made (Report Only mode or WhatIf)</em></li>"
    }
    
    # Build HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Server Bootstrap Compliance Report - $hostname</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .summary-card.pass .value { color: #28a745; }
        .summary-card.fail .value { color: #dc3545; }
        .summary-card.warning .value { color: #ffc107; }
        
        .content {
            padding: 30px;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        .category {
            margin-bottom: 30px;
            background: #f8f9fa;
            border-radius: 8px;
            overflow: hidden;
        }
        
        .category-header {
            background: #667eea;
            color: white;
            padding: 15px 20px;
            font-weight: bold;
            font-size: 1.2em;
        }
        
        .checks-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .checks-table th {
            background: #495057;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        .checks-table td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        
        .checks-table tr:last-child td {
            border-bottom: none;
        }
        
        .checks-table tr:hover {
            background: #e9ecef;
        }
        
        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        .status-pass {
            background: #28a745;
            color: white;
        }
        
        .status-fail {
            background: #dc3545;
            color: white;
        }
        
        .status-warning {
            background: #ffc107;
            color: #333;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
        }
        
        .info-label {
            font-weight: bold;
            color: #495057;
        }
        
        .info-value {
            color: #667eea;
        }
        
        .changes-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
        }
        
        .changes-list ul {
            list-style-position: inside;
            line-height: 1.8;
        }
        
        .footer {
            background: #343a40;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
        
        .compliance-meter {
            width: 100%;
            height: 30px;
            background: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .compliance-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745 0%, #20c997 100%);
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Server Bootstrap Compliance Report</h1>
            <p>Security Hardening Assessment</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Overall Status</h3>
                <div class="value">$($Results.OverallStatus)</div>
            </div>
            <div class="summary-card pass">
                <h3>Passed Checks</h3>
                <div class="value">$passedChecks</div>
            </div>
            <div class="summary-card fail">
                <h3>Failed Checks</h3>
                <div class="value">$failedChecks</div>
            </div>
            <div class="summary-card warning">
                <h3>Warnings</h3>
                <div class="value">$warningChecks</div>
            </div>
            <div class="summary-card">
                <h3>Compliance Score</h3>
                <div class="value">$compliancePercent%</div>
                <div class="compliance-meter">
                    <div class="compliance-fill" style="width: $compliancePercent%">
                        $compliancePercent%
                    </div>
                </div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📋 System Information</h2>
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Hostname:</span>
                        <span class="info-value">$hostname</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Operating System:</span>
                        <span class="info-value">$($osInfo.Caption)</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">OS Version:</span>
                        <span class="info-value">$($osInfo.Version)</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Report Date:</span>
                        <span class="info-value">$timestamp</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Hardening Profile:</span>
                        <span class="info-value">$($Results.Profile)</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Total Checks:</span>
                        <span class="info-value">$totalChecks</span>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Compliance Checks</h2>
                $categoryRows
            </div>
            
            <div class="section">
                <h2>✅ Changes Applied</h2>
                <div class="changes-list">
                    <ul>
                        $changesHTML
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Windows Server Bootstrap & Hardening Automation v1.0.0</p>
            <p>Report generated at $timestamp</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Get-CategoryHTML {
    param($Category)
    
    $rows = ""
    foreach ($check in $Category.Checks) {
        $statusClass = switch ($check.Status) {
            'Pass' { 'status-pass' }
            'Fail' { 'status-fail' }
            'Warning' { 'status-warning' }
            default { 'status-warning' }
        }
        
        $rows += @"
                <tr>
                    <td>$($check.Name)</td>
                    <td>$($check.Expected)</td>
                    <td>$($check.Actual)</td>
                    <td><span class="status-badge $statusClass">$($check.Status)</span></td>
                </tr>
"@
    }
    
    $html = @"
            <div class="category">
                <div class="category-header">$($Category.Category)</div>
                <table class="checks-table">
                    <thead>
                        <tr>
                            <th>Check</th>
                            <th>Expected</th>
                            <th>Actual</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        $rows
                    </tbody>
                </table>
            </div>
"@
    
    return $html
}

Export-ModuleMember -Function New-ComplianceReport
