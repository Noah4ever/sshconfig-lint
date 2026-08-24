$ErrorActionPreference = "Stop"

$repo = "Noah4ever/sshconfig-lint"
$version = $env:SSHCONFIG_LINT_VERSION
if ($version -notmatch '^v\d+\.\d+\.\d+([.-].*)?$') {
  throw "SSHCONFIG_LINT_VERSION must be a release tag"
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$asset = switch ($arch) {
  "x64" { "sshconfig-lint-windows-x86_64.exe" }
  "arm64" { "sshconfig-lint-windows-arm64.exe" }
  default { throw "Unsupported Windows architecture: $arch" }
}

$installDir = Join-Path $env:RUNNER_TEMP "sshconfig-lint-action/$version"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$baseUrl = "https://github.com/$repo/releases/download/$version"
$assetPath = Join-Path $installDir "sshconfig-lint.exe"
$checksumsPath = Join-Path $installDir "SHA256SUMS"
Invoke-WebRequest "$baseUrl/$asset" -OutFile $assetPath
Invoke-WebRequest "$baseUrl/SHA256SUMS" -OutFile $checksumsPath

$expected = (Get-Content $checksumsPath | Where-Object { $_ -match "\s+$([regex]::Escape($asset))$" } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
if (-not $expected) { throw "$asset is missing from SHA256SUMS" }
$actual = (Get-FileHash -Algorithm SHA256 $assetPath).Hash.ToLowerInvariant()
if ($actual -ne $expected.ToLowerInvariant()) { throw "Checksum verification failed for $asset" }

$installDir | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
