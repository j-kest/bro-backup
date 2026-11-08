# version : 0.2
# created by : JK and CF
# last edited : 01/11/2026
# Name : lab.ps1 (BRO Backup test lab)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs two bros (alice and bob) and a mail catcher on one computer with Docker,
# so you can test BRO Backup without a NAS. Works with PowerShell 7 on Windows, macOS and Linux,
# and with Windows PowerShell 5.1.
#
# Examples:
#   .\lab.ps1                         start the lab (builds the image the first time)
#   .\lab.ps1 -Only bob               only bob, for example on a second PC on another network
#   .\lab.ps1 -Action Status          is everything running?
#   .\lab.ps1 -Action NewSnapshot     make a new fake ZFS snapshot of alice's data
#   .\lab.ps1 -Action ChangeData      change, add and delete some of alice's files
#   .\lab.ps1 -Action CorruptBackup   damage alice's backup at bob (the restore test must notice)
#   .\lab.ps1 -Action Crash           alice "loses her NAS": recover with the recovery code
#   .\lab.ps1 -Action ChangeAddress   alice gets another IP address, like after a new internet connection
#   .\lab.ps1 -Action Stop            stop the lab, keep everything
#   .\lab.ps1 -Action Reset -Force    stop and delete all lab data

[CmdletBinding()]
param(
    [ValidateSet("Start", "Stop", "Status", "Reset", "NewSnapshot", "ChangeData", "CorruptBackup", "Crash", "ChangeAddress", "Logs")]
    [string]$Action = "Start",
    [ValidateSet("alice", "bob")]
    [string]$Bro = "alice",
    [ValidateSet("", "alice", "bob")]
    [string]$Only = "",          # start just one bro (the mail catcher always starts)
    [int]$SizeMB = 200,          # how much test data each bro gets
    [string]$Image = "",         # use an existing image instead of building, e.g. ghcr.io/j-kest/bro-backup:0.7
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Lab = $PSScriptRoot
Set-Location $Lab

function Ok($msg)   { Write-Host "  OK    $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  ERROR $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "        $msg" }
function Step($msg) { Write-Host ""; Write-Host $msg }

function Invoke-Compose {
    param([string[]]$ComposeArgs)
    & docker compose @ComposeArgs
    if ($LASTEXITCODE -ne 0) { throw "docker compose $($ComposeArgs -join ' ') failed (exit $LASTEXITCODE)" }
}

function Test-Docker {
    $null = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $?) { Fail "Docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1 }
    & docker info *> $null
    if ($LASTEXITCODE -ne 0) { Fail "Docker is installed but not running. Start Docker Desktop and try again."; exit 1 }
    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) { Fail "docker compose is missing. Update Docker Desktop."; exit 1 }
    Ok "Docker is running"
}

function New-RandomFile([string]$Path, [int]$Bytes) {
    $buf = New-Object byte[] $Bytes
    (New-Object System.Random).NextBytes($buf)
    [System.IO.File]::WriteAllBytes($Path, $buf)
}

function Get-SnapshotName([datetime]$When) { "auto-" + $When.ToString("yyyy-MM-dd_HH-mm") }

function New-FakeSnapshot([string]$Name, [datetime]$When) {
    # A ZFS dataset shows its snapshots in the hidden folder .zfs/snapshot/<name>.
    # BRO Backup looks for exactly that, so a copy in that place behaves like a snapshot.
    $tank = Join-Path $Lab "$Name/nas/tank"
    $snapRoot = Join-Path $tank ".zfs/snapshot"
    $snap = Join-Path $snapRoot (Get-SnapshotName $When)
    New-Item -ItemType Directory -Force -Path $snap | Out-Null
    Get-ChildItem -Force $tank | Where-Object { $_.Name -ne ".zfs" } | Copy-Item -Destination $snap -Recurse -Force
    (Get-Item $snap).LastWriteTime = $When
    # keep the 5 newest, like a snapshot task with a short lifetime
    Get-ChildItem $snapRoot -Directory | Sort-Object Name -Descending | Select-Object -Skip 5 |
        Remove-Item -Recurse -Force
    return (Split-Path $snap -Leaf)
}

function New-TestData([string]$Name) {
    $nas = Join-Path $Lab "$Name/nas"
    if (Test-Path (Join-Path $nas "tank")) { Ok "$Name already has test data"; return }
    Info "Creating about $SizeMB MB of test data for $Name"
    $photos = Join-Path $nas "tank/photos/2026"
    $docs = Join-Path $nas "tank/documents"
    $db = Join-Path $nas "tank/apps/database"
    $media = Join-Path $nas "media/music"
    foreach ($d in $photos, $docs, $db, $media) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    $big = [math]::Max(1, [int]($SizeMB * 0.7))
    for ($i = 1; $i -le $big; $i++) { New-RandomFile (Join-Path $photos ("IMG_{0:D4}.jpg" -f $i)) (1MB) }
    for ($i = 1; $i -le 60; $i++) {
        Set-Content -Path (Join-Path $docs ("note-{0:D2}.txt" -f $i)) -Value ("$Name note $i`n" * (50 * $i))
    }
    New-RandomFile (Join-Path $db "app.db") (8MB)
    $rest = [math]::Max(1, [int]($SizeMB * 0.3) - 8)
    for ($i = 1; $i -le $rest; $i++) { New-RandomFile (Join-Path $media ("track-{0:D3}.flac" -f $i)) (1MB) }
    # tank behaves like a ZFS dataset with snapshots, media like a dataset without them
    $snap = New-FakeSnapshot $Name ((Get-Date).AddHours(-1))
    Ok "$Name test data ready (tank with snapshot $snap, media without snapshots)"
}

function Wait-Healthy([string]$Name, [int]$Port) {
    for ($i = 0; $i -lt 60; $i++) {
        try {
            $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$Port/healthz"
            if ($r.StatusCode -eq 200) { Ok "$Name answers on http://localhost:$Port"; return $true }
        } catch { }
        Start-Sleep -Seconds 2
    }
    Fail "$Name does not answer on port $Port. Run: .\lab.ps1 -Action Logs -Bro $Name"
    return $false
}

function Start-Lab {
    Step "Starting the BRO Backup lab"
    Test-Docker
    $names = if ($Only) { @($Only) } else { @("alice", "bob") }
    $services = $names + @("mail")
    foreach ($n in $names) {
        foreach ($d in "data", "nas") { New-Item -ItemType Directory -Force -Path (Join-Path $Lab "$n/$d") | Out-Null }
        New-TestData $n
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $Lab "usb") | Out-Null
    if ($Image) {
        $env:BRO_IMAGE = $Image
        Info "Using image $Image"
        Invoke-Compose (@("up", "-d", "--no-build") + $services)
    } else {
        $env:BRO_IMAGE = "bro-backup:lab"
        Info "Building the image (the first time takes a few minutes)"
        Invoke-Compose @("build", "alice")
        Ok "Image bro-backup:lab built"
        Invoke-Compose (@("up", "-d") + $services)
    }
    $healthy = $true
    if ($names -contains "alice") { $healthy = (Wait-Healthy "alice" 8481) -and $healthy }
    if ($names -contains "bob") { $healthy = (Wait-Healthy "bob" 8482) -and $healthy }
    if (-not $healthy) { exit 1 }
    Step "Lab is running"
    if ($names -contains "alice") { Info "alice:  http://localhost:8481" }
    if ($names -contains "bob") { Info "bob:    http://localhost:8482" }
    Info "emails: http://localhost:8025   (in BRO Backup: server mail, port 1025, security None)"
    Info "Folders to pick in the setup: tank and media"
    Info "Test checklist: TESTING.md in this folder"
}

function Show-Status {
    Step "Lab status"
    Test-Docker
    & docker compose ps
    foreach ($p in @(@("alice", 8481), @("bob", 8482))) {
        try {
            Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://127.0.0.1:$($p[1])/healthz" | Out-Null
            Ok "$($p[0]) answers on http://localhost:$($p[1])"
        } catch { Fail "$($p[0]) does not answer on port $($p[1])" }
    }
}

function Invoke-ChangeData {
    Step "Changing $Bro's data"
    $tank = Join-Path $Lab "$Bro/nas/tank"
    if (-not (Test-Path $tank)) { Fail "No test data for $Bro. Start the lab first."; exit 1 }
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    New-RandomFile (Join-Path $tank "photos/2026/NEW_$stamp.jpg") (2MB)
    Add-Content -Path (Join-Path $tank "documents/note-01.txt") -Value "changed $stamp"
    $victim = Get-ChildItem (Join-Path $tank "photos/2026") -File | Sort-Object Name | Select-Object -First 1
    if ($victim) { Remove-Item $victim.FullName -Force; Info "Deleted $($victim.Name)" }
    Ok "Added NEW_$stamp.jpg, changed note-01.txt"
    Info "Run a backup, then: the new version has the new file, an older version still has $($victim.Name)"
}

function Invoke-CorruptBackup {
    # alice's backup lives at bob, and the other way round
    $holder = if ($Bro -eq "alice") { "bob" } else { "alice" }
    Step "Damaging $Bro's backup that is stored at $holder"
    $packs = Get-ChildItem -Recurse -File (Join-Path $Lab "$holder/data/receive") -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match "[\\/]data[\\/][0-9a-f]{2}$" -and $_.Length -gt 4096 }
    if (-not $packs) { Fail "No backup data of $Bro found at $holder. Run a backup first."; exit 1 }
    $pick = $packs | Get-Random -Count ([math]::Min(3, @($packs).Count))
    foreach ($f in $pick) {
        $fs = [System.IO.File]::Open($f.FullName, "Open", "ReadWrite")
        try { $fs.Seek(1000, "Begin") | Out-Null; $junk = New-Object byte[] 64; (New-Object System.Random).NextBytes($junk); $fs.Write($junk, 0, 64) }
        finally { $fs.Close() }
    }
    Ok "Damaged $(@($pick).Count) of $(@($packs).Count) data files"
    Info "In $Bro's BRO Backup: open Restore, click 'Run a restore test'. It should fail and turn the overview red."
    Info "This is not always caught: the test reads a sample. Run it a few times, or damage more files."
}

function Invoke-Crash {
    Step "Simulating a crashed NAS for $Bro"
    if (-not $Force) {
        Write-Host "  This moves $Bro's BRO Backup data aside, as if the NAS was lost. Your test files stay." -ForegroundColor Yellow
        $ok = Read-Host "  Type yes to continue"
        if ($ok -ne "yes") { Info "Nothing changed"; return }
    }
    Invoke-Compose @("stop", $Bro)
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    Move-Item (Join-Path $Lab "$Bro/data") (Join-Path $Lab "$Bro/data-crashed-$stamp")
    New-Item -ItemType Directory -Force -Path (Join-Path $Lab "$Bro/data") | Out-Null
    Invoke-Compose @("start", $Bro)
    $port = if ($Bro -eq "alice") { 8481 } else { 8482 }
    if (Wait-Healthy $Bro $port) {
        Ok "$Bro starts fresh. Old data kept in $Bro/data-crashed-$stamp"
        Info "Recover: on the other bro, Overview, 'help code' next to $Bro. In $Bro's setup choose 'Recover'."
    }
}

function Invoke-ChangeAddress {
    # Each bro switches between two fixed addresses: alice .11 and .21, bob .12 and .22.
    Step "Giving $Bro another IP address"
    $container = (& docker compose ps -q $Bro)
    if (-not $container) { Fail "$Bro is not running. Start the lab first."; exit 1 }
    $network = (& docker inspect -f "{{range `$k, `$v := .NetworkSettings.Networks}}{{`$k}}{{end}}" $container)
    $old = (& docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" $container)
    $base = if ($Bro -eq "alice") { 11 } else { 12 }
    $new = if ($old -eq "172.29.71.$base") { "172.29.71.$($base + 10)" } else { "172.29.71.$base" }
    & docker network disconnect $network $container
    & docker network connect --ip $new $network $container
    if ($LASTEXITCODE -ne 0) { Fail "Could not give $Bro the address $new"; exit 1 }
    Ok "$Bro moved from $old to $new"
    Info "Without the internet relays the other bro can only find $Bro through the new address that $Bro sends him."
    Info "Within about a minute: the other bro's Overview shows 'new address received' and backups keep working."
}

switch ($Action) {
    "Start"  { Start-Lab }
    "Stop"   { Step "Stopping the lab"; Invoke-Compose @("stop"); Ok "Stopped. Start again with .\lab.ps1" }
    "Status" { Show-Status }
    "Logs"   { Invoke-Compose @("logs", "--tail", "200", $Bro) }
    "NewSnapshot" {
        Step "New fake ZFS snapshot for $Bro"
        if (-not (Test-Path (Join-Path $Lab "$Bro/nas/tank"))) { Fail "No test data for $Bro. Start the lab first."; exit 1 }
        $n = New-FakeSnapshot $Bro (Get-Date)
        Ok "Snapshot $n created. Settings in BRO Backup shows it under 'Where each folder is read from'."
    }
    "ChangeData"    { Invoke-ChangeData }
    "CorruptBackup" { Invoke-CorruptBackup }
    "Crash"         { Invoke-Crash }
    "ChangeAddress" { Invoke-ChangeAddress }
    "Reset" {
        Step "Resetting the lab"
        if (-not $Force) { Fail "This deletes all lab data. Run again with -Force to confirm."; exit 1 }
        & docker compose down *> $null
        foreach ($p in "alice", "bob", "usb") {
            $full = Join-Path $Lab $p
            if (Test-Path $full) { Remove-Item -Recurse -Force $full }
        }
        Ok "Lab removed. Start fresh with .\lab.ps1"
    }
}
