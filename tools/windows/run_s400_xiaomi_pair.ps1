param(
    [ValidateSet("cn", "de", "i2", "in", "ru", "sg", "tw", "us")]
    [string]$Region = "de"
)

$ErrorActionPreference = "Stop"
$repo = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$statusPath = Join-Path $repo "private\s400-last-run.json"
$errorStatusPath = Join-Path $repo "private\s400-last-error.json"
$outputPath = Join-Path $repo "private\s400-secrets.json"
$startedAt = [DateTime]::UtcNow.ToString("o")
$cdpUrl = "http://127.0.0.1:18800"
$windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
$uv = Join-Path $env:USERPROFILE ".local\bin\uv.exe"

New-Item -ItemType Directory -Force (Split-Path $statusPath) | Out-Null
Remove-Item $errorStatusPath -Force -ErrorAction SilentlyContinue
@{
    state = "started"
    started_at = $startedAt
    region = $Region
} | ConvertTo-Json | Set-Content -Encoding UTF8 $statusPath

try {
    if (-not $env:S400_BLE_ADDRESS) {
        throw "Set S400_BLE_ADDRESS in this PowerShell session before starting pairing."
    }
    try {
        Invoke-RestMethod "$cdpUrl/json/version" -TimeoutSec 2 | Out-Null
    } catch {
        $edgeLauncher = Join-Path $PSScriptRoot "start_s400_edge.ps1"
        & $windowsPowerShell -NoProfile -ExecutionPolicy Bypass -File $edgeLauncher
        if ($LASTEXITCODE -ne 0) {
            throw "The dedicated Edge login session did not start."
        }
    }
    if (-not (Test-Path $uv)) {
        $uv = (Get-Command uv.exe -ErrorAction Stop).Source
    }
    Write-Host "Log in to Xiaomi in the dedicated Edge window." -ForegroundColor Cyan
    Write-Host "Return here only after the Xiaomi account page confirms the login."
    Read-Host "Press Enter after browser login"

    & $uv run --python 3.12 --no-project `
        --with-requirements (Join-Path $repo "requirements-lab.txt") `
        (Join-Path $repo "tools\s400_xiaomi_pair.py") `
        --region $Region `
        --output $outputPath `
        --trace (Join-Path $repo "captures\s400-xiaomi-pair.jsonl") `
        --error-status $errorStatusPath `
        --browser-cdp $cdpUrl
    $exitCode = $LASTEXITCODE
    if (($exitCode -eq 0) -and (Test-Path $outputPath)) {
        $unc = [regex]::Match(
            $outputPath,
            '^\\\\wsl(?:\.localhost|\$)\\(?<distro>[^\\]+)(?<path>\\.*)$',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if ($unc.Success) {
            $distro = $unc.Groups["distro"].Value
            $linuxPath = $unc.Groups["path"].Value.Replace("\", "/")
            & (Join-Path $env:SystemRoot "System32\wsl.exe") `
                --distribution $distro --exec chmod 600 $linuxPath
            if ($LASTEXITCODE -ne 0) {
                throw "Provisioning succeeded, but securing the output file failed."
            }
        }
    }
} catch {
    Write-Host $_ -ForegroundColor Red
    $exitCode = 1
    @{
        category = "launcher_error"
        message = $_.Exception.Message
        exit_code = $exitCode
        occurred_at = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json | Set-Content -Encoding UTF8 $errorStatusPath
}
if (($exitCode -ne 0) -and (-not (Test-Path $errorStatusPath))) {
    @{
        category = "uv_exit"
        exit_code = $exitCode
        occurred_at = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json | Set-Content -Encoding UTF8 $errorStatusPath
}
@{
    state = $(if ($exitCode -eq 0) { "succeeded" } else { "failed" })
    started_at = $startedAt
    finished_at = [DateTime]::UtcNow.ToString("o")
    exit_code = $exitCode
    region = $Region
} | ConvertTo-Json | Set-Content -Encoding UTF8 $statusPath
Write-Host ""
if ($exitCode -eq 0) {
    Write-Host "Provisioning completed successfully." -ForegroundColor Green
} else {
    Write-Host "Provisioning failed with exit code $exitCode." -ForegroundColor Red
}
Read-Host "Press Enter to close"
exit $exitCode
