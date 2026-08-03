#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

$master = [Environment]::GetEnvironmentVariable("RELAYDOCK_MASTER_URL", "Process")
$token = [Environment]::GetEnvironmentVariable("RELAYDOCK_SPEEDTEST_TOKEN", "Process")
$name = [Environment]::GetEnvironmentVariable("RELAYDOCK_SPEEDTEST_NAME", "Process")
if ([string]::IsNullOrWhiteSpace($master) -or [string]::IsNullOrWhiteSpace($token) -or [string]::IsNullOrWhiteSpace($name)) {
    throw "RELAYDOCK_MASTER_URL, RELAYDOCK_SPEEDTEST_TOKEN and RELAYDOCK_SPEEDTEST_NAME are required"
}
if ($master -notmatch '^https?://') { throw "RELAYDOCK_MASTER_URL must use http or https" }
if ($master.Contains("`r") -or $master.Contains("`n") -or $token.Contains("`r") -or $token.Contains("`n") -or $name.Contains("`r") -or $name.Contains("`n")) {
    throw "Environment values must be single-line"
}

$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
switch ($arch) {
    "x64" { $asset = "relaydock-speedtester-windows-amd64.exe" }
    "arm64" { $asset = "relaydock-speedtester-windows-arm64.exe" }
    default { throw "Unsupported architecture: $arch" }
}

$downloadBase = if ($env:RELAYDOCK_SPEEDTESTER_DOWNLOAD_BASE) { $env:RELAYDOCK_SPEEDTESTER_DOWNLOAD_BASE.TrimEnd('/') } else { "https://github.com/violetaini/relaydock/releases/latest/download" }
$installDir = Join-Path $env:ProgramData "RelayDock\Speedtester"
$target = Join-Path $installDir "relaydock-speedtester.exe"
$temporary = Join-Path ([IO.Path]::GetTempPath()) ("relaydock-speedtester-" + [guid]::NewGuid().ToString("N") + ".exe")
$checksums = Join-Path ([IO.Path]::GetTempPath()) ("relaydock-speedtester-checksums-" + [guid]::NewGuid().ToString("N") + ".txt")

try {
    Invoke-WebRequest -UseBasicParsing -Uri "$downloadBase/checksums.txt" -OutFile $checksums
    Invoke-WebRequest -UseBasicParsing -Uri "$downloadBase/$asset" -OutFile $temporary
    $expected = ((Get-Content -LiteralPath $checksums) | Where-Object { $_ -match ("^([0-9a-fA-F]{64})\s+" + [regex]::Escape($asset) + "$") } | Select-Object -First 1)
    if (-not $expected) { throw "GitHub Release checksum is missing for $asset" }
    $expectedHash = ($expected -split '\s+')[0].ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw "Downloaded binary checksum does not match the GitHub Release" }

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Get-Process -Name "relaydock-speedtester" -ErrorAction SilentlyContinue | Stop-Process -Force
    Move-Item -Force -LiteralPath $temporary -Destination $target
    [Environment]::SetEnvironmentVariable("RELAYDOCK_MASTER_URL", $master, "Machine")
    [Environment]::SetEnvironmentVariable("RELAYDOCK_SPEEDTEST_TOKEN", $token, "Machine")
    [Environment]::SetEnvironmentVariable("RELAYDOCK_SPEEDTEST_NAME", $name, "Machine")
    $taskCommand = "`"$target`""
    & schtasks.exe /Create /TN "RelayDock Speedtester" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR $taskCommand /F | Out-Null
    Start-Process -FilePath $target -WindowStyle Hidden
    Write-Host "RelayDock speedtester installed from GitHub Release"
} finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $temporary, $checksums
}
