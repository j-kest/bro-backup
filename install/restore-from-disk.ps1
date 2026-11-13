# version : 0.2
# created by : JK and CF
# last edited : 08/11/2026
# Name : restore-from-disk.ps1
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Restores your files from a disk your bro made (Copy to disk in his BRO Backup), on any PC with
# Docker Desktop. No NAS and no internet needed: only the disk and your recovery code.
#
#   .\restore-from-disk.ps1 -Disk E:\
#   .\restore-from-disk.ps1 -Disk E:\backup-of-alice-20261103 -To D:\Restored
#
# The newest version of every folder lands in -To (default: BRO-restore in your user folder).
# The disk is mounted read-only and the container has no network.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Disk,     # the disk, or the backup-of-... folder on it
    [string]$To = (Join-Path $HOME "BRO-restore"),   # where the files go
    [string]$Image = "ghcr.io/j-kest/bro-backup:1.1",
    [switch]$CodeFromInput,                          # read the recovery code from standard input (for scripts)
    [Parameter(ValueFromPipeline = $true)][string]$CodeInput  # filled by PowerShell when input is piped in
)

function Write-Ok([string]$Message) { Write-Host $Message -ForegroundColor Green }
function Write-Err([string]$Message) { Write-Host $Message -ForegroundColor Red }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Err "Docker is not installed. Install Docker Desktop first: https://www.docker.com/products/docker-desktop/"
    exit 1
}
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker is not running. Start Docker Desktop and try again."
    exit 1
}
if (-not (Test-Path -LiteralPath $Disk)) {
    Write-Err "Disk or folder not found: $Disk"
    exit 1
}
$source = (Resolve-Path -LiteralPath $Disk).Path
New-Item -ItemType Directory -Force -Path $To | Out-Null
$target = (Resolve-Path -LiteralPath $To).Path

# A disk with one backup folder works, and so does the backup folder itself
$restoreArgs = @("python", "main.py", "restore-from-disk", "--to", "/out")
if (Test-Path -LiteralPath (Join-Path $source "bro-pickup.json")) {
    $restoreArgs += @("--path", "/seed")
}
if ($CodeFromInput) { $restoreArgs += @("--code", "-") }

$tty = if ($CodeFromInput -or [Console]::IsInputRedirected) { "-i" } else { "-it" }
Write-Host "Reading $source, restoring to $target"
$dockerArgs = @("run", "--rm", $tty, "--network", "none",
    "--mount", "type=bind,source=$source,target=/seed,readonly",
    "--mount", "type=bind,source=$target,target=/out",
    $Image) + $restoreArgs
if ($CodeFromInput) {
    $code = if ($CodeInput) { $CodeInput } else { [Console]::In.ReadLine() }
    $code | & docker @dockerArgs
} else {
    & docker @dockerArgs
}
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Done. Your files are in $target"
    exit 0
}
Write-Err "Restoring did not succeed (exit code $LASTEXITCODE). See the messages above."
exit $LASTEXITCODE
