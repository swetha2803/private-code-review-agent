param(
  [Parameter(Mandatory = $true)]
  [string]$RepoUrl,

  [string]$Branch = "main",

  [string]$OutputPath = ".\reports",

  [string]$SparsePath = ""
)

$ErrorActionPreference = "Stop"

function Test-Command($Name) {
  $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command "git")) {
  throw "git is not installed or not available in PATH."
}

if (-not (Test-Command "node")) {
  throw "node is not installed or not available in PATH."
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("azure-review-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

try {
  Write-Host "Cloning Azure repo into temporary local folder..."

  if ([string]::IsNullOrWhiteSpace($SparsePath)) {
    git clone --depth 1 --branch $Branch $RepoUrl $tempRoot
  } else {
    git clone --depth 1 --branch $Branch --filter=blob:none --sparse $RepoUrl $tempRoot
    git -C $tempRoot sparse-checkout set $SparsePath
  }

  Write-Host "Running local review agent..."
  node .\agent\review-agent.js $tempRoot $OutputPath
  $agentExitCode = $LASTEXITCODE

  if ($agentExitCode -ne 0 -and $agentExitCode -ne 2) {
    exit $agentExitCode
  }

  Write-Host "Azure repo review completed. Reports written to $OutputPath"
  if ($agentExitCode -eq 2) {
    Write-Host "Review completed with critical/high findings."
  }
} finally {
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
