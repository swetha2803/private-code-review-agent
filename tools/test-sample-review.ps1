$ErrorActionPreference = "Stop"

$samplePath = ".\samples\vendor-mobile-backend"
$outputPath = ".\sample-reports"

if (-not (Test-Path -LiteralPath $samplePath)) {
  throw "Sample path not found: $samplePath"
}

npm run agent -- $samplePath $outputPath
$agentExitCode = $LASTEXITCODE

if ($agentExitCode -ne 0 -and $agentExitCode -ne 2) {
  exit $agentExitCode
}

$json = Get-ChildItem $outputPath -Filter "agent-review-*.json" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1

if (-not $json) {
  throw "No agent JSON report generated."
}

$report = Get-Content $json.FullName -Raw | ConvertFrom-Json

if ($report.summary.decision -ne "Reject") {
  throw "Expected sample decision Reject, got $($report.summary.decision)."
}

if ($report.findings.Count -lt 10) {
  throw "Expected at least 10 findings, got $($report.findings.Count)."
}

if ($report.apiInventory.Count -lt 4) {
  throw "Expected at least 4 APIs, got $($report.apiInventory.Count)."
}

if ($report.logFindings.Count -lt 4) {
  throw "Expected at least 4 log findings, got $($report.logFindings.Count)."
}

Write-Host "Sample review validation passed."
Write-Host "Decision: $($report.summary.decision)"
Write-Host "Risk score: $($report.summary.riskScore)"
Write-Host "Findings: $($report.findings.Count)"
Write-Host "APIs: $($report.apiInventory.Count)"
Write-Host "Log findings: $($report.logFindings.Count)"
Write-Host "Report: $($json.FullName)"
