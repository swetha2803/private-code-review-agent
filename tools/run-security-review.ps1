param(
  [Parameter(Mandatory = $true)]
  [string]$SourcePath,

  [string]$OutputPath = ".\reports"
)

$ErrorActionPreference = "Stop"

$resolvedSource = Resolve-Path -LiteralPath $SourcePath
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$summaryPath = Join-Path $OutputPath "security-review-$timestamp.md"

function Test-Command($Name) {
  $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-Summary($Text) {
  Add-Content -Path $summaryPath -Value $Text
}

Set-Content -Path $summaryPath -Value "# Vendor Code Security Review"
Add-Summary ""
Add-Summary "- Source: $resolvedSource"
Add-Summary "- Generated: $(Get-Date -Format o)"
Add-Summary "- Mode: local execution, no source upload by this script"
Add-Summary ""

if (Test-Command "node") {
  node .\agent\review-agent.js $resolvedSource $OutputPath
  Add-Summary "- Private Review Agent: completed, reports written to `$OutputPath`"
} else {
  Add-Summary "- Private Review Agent: Node.js not installed"
}

if (Test-Command "semgrep") {
  $semgrepOut = Join-Path $OutputPath "semgrep-$timestamp.json"
  semgrep scan --config auto --json --output $semgrepOut $resolvedSource
  Add-Summary "- Semgrep: completed, report `$semgrepOut`"
} else {
  Add-Summary "- Semgrep: not installed"
}

if (Test-Command "gitleaks") {
  $gitleaksOut = Join-Path $OutputPath "gitleaks-$timestamp.json"
  gitleaks detect --source $resolvedSource --report-format json --report-path $gitleaksOut --no-git
  Add-Summary "- Gitleaks: completed, report `$gitleaksOut`"
} else {
  Add-Summary "- Gitleaks: not installed"
}

if (Test-Command "dependency-check") {
  $dependencyOut = Join-Path $OutputPath "dependency-check-$timestamp"
  dependency-check --scan $resolvedSource --out $dependencyOut --format "ALL"
  Add-Summary "- OWASP Dependency-Check: completed, report folder `$dependencyOut`"
} else {
  Add-Summary "- OWASP Dependency-Check: not installed"
}

if (Test-Command "sonar-scanner") {
  Add-Summary "- Sonar Scanner: installed. Run it with your approved SonarQube project key and token."
} else {
  Add-Summary "- Sonar Scanner: not installed"
}

Add-Summary ""
Add-Summary "Import the agent, Semgrep, Gitleaks, or SARIF JSON report into `index.html` for local review."

Write-Host "Review summary written to $summaryPath"
