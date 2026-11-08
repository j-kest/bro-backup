# version : 0.3
# created by : JK and CF
# last edited : 08/11/2026
# Name : urbackup-client.ps1
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Installs the UrBackup client on this Windows PC, already linked to your UrBackup server.
# The script asks the server for a client installer made for this PC (with its name and its own
# key inside) and runs it silently. This is the same flow as UrBackup's own Python example
# ("Download custom client installer via Python" on the UrBackup wiki).
#
#   .\urbackup-client.ps1 -Server http://truenas.local:55414 -AllowHttp   # plain http: see -AllowHttp below
#   .\urbackup-client.ps1 -Server https://backup.example.be -ClientName PC-ANNE
#   .\urbackup-client.ps1 -Server http://truenas.local:55414 -DownloadOnly   # only fetch the installer
#
# Login: -Credential, or the environment variables URBACKUP_USER and URBACKUP_PASSWORD (for an
# RMM tool), or you are asked. Make a separate UrBackup web user for this with only the rights
# "status: some" and "add_client: all". To reinstall a PC the server already knows, that user
# also needs "settings: all".
#
# On the server, "Download client from update server" must be on (Settings, General), or the
# client update must be placed there by hand. Without it the server cannot make an installer.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,        # UrBackup web address, such as http://truenas.local:55414
    [string]$ClientName = $env:COMPUTERNAME,               # the name this PC gets in UrBackup
    [pscredential]$Credential,                             # UrBackup web user (see above)
    [string]$OutFile = (Join-Path ([IO.Path]::GetTempPath()) "UrBackupClientSetup.exe"),
    [switch]$DownloadOnly,                                 # fetch the installer, do not install
    [switch]$Force,                                        # install even if the client is already there
    [switch]$AllowHttp                                     # accept a download over plain http (see below)
)

function Write-Ok([string]$Message) { Write-Host $Message -ForegroundColor Green }
function Write-Err([string]$Message) { Write-Host $Message -ForegroundColor Red }

$ErrorActionPreference = "Stop"
$ServiceName = "UrBackupClientBackend"

# --- Before anything: are we allowed to install, and is it needed? ---
if (-not $DownloadOnly) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Err "Run this script as administrator: installing a service needs it."
        exit 1
    }
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing -and -not $Force) {
        Write-Ok "The UrBackup client is already installed on this PC (service $ServiceName is $($existing.Status))."
        Write-Host "Use -Force to install it again."
        exit 0
    }
}
if ([string]::IsNullOrWhiteSpace($ClientName) -or $ClientName -notmatch '^[A-Za-z0-9._-]{1,64}$') {
    Write-Err "Client name '$ClientName' is not usable. Use letters, digits, dot, dash or underscore, at most 64."
    exit 1
}

# The web interface answers on <address>/x
$base = $Server.TrimEnd("/")
if ($base -notmatch "/x$") { $base = "$base/x" }
if ($base -notmatch "^https?://") {
    Write-Err "Give the server as a web address, such as http://truenas.local:55414"
    exit 1
}
$serverHost = ([uri]$base).Host
$isLocal = $serverHost -notmatch "\." -or $serverHost -match "\.(local|lan|home\.arpa)$" -or
           $serverHost -match "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
if ($base -like "http://*" -and -not $isLocal) {
    Write-Host "Note: plain http to $serverHost, which looks like an internet address. Use https for that." -ForegroundColor Yellow
}

if (-not $Credential) {
    if ($env:URBACKUP_USER -and $env:URBACKUP_PASSWORD) {
        $Credential = [pscredential]::new($env:URBACKUP_USER, (ConvertTo-SecureString $env:URBACKUP_PASSWORD -AsPlainText -Force))
    } else {
        $Credential = Get-Credential -Message "UrBackup web user (needs status and add_client rights)"
    }
}
if (-not $Credential) {
    Write-Err "No UrBackup login given."
    exit 1
}

# --- Talking to the UrBackup web API ---
$script:session = $null

function Invoke-UrBackup([string]$Action, [hashtable]$Params = @{}) {
    $body = @{} + $Params
    if ($script:session) { $body["ses"] = $script:session }
    try {
        return Invoke-RestMethod -Method Post -Uri "$base`?a=$Action" -Body $body -UseBasicParsing -TimeoutSec 30
    } catch {
        throw "The server did not answer '$Action': $($_.Exception.Message)"
    }
}

function Get-Md5Hex([byte[]]$Bytes) {
    $md5 = [Security.Cryptography.MD5]::Create()
    try { return (-join ($md5.ComputeHash($Bytes) | ForEach-Object { $_.ToString("x2") })) } finally { $md5.Dispose() }
}

# UrBackup's challenge login: the password itself never goes over the wire
function Get-PasswordAnswer($Salt, [string]$Password) {
    $utf8 = [Text.Encoding]::UTF8
    $md5 = [Security.Cryptography.MD5]::Create()
    try { $inner = $md5.ComputeHash($utf8.GetBytes($Salt.salt + $Password)) } finally { $md5.Dispose() }
    $hash = -join ($inner | ForEach-Object { $_.ToString("x2") })
    $rounds = 0
    if ($Salt.PSObject.Properties.Name -contains "pbkdf2_rounds") { $rounds = [int]$Salt.pbkdf2_rounds }
    if ($rounds -gt 0) {
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($inner, $utf8.GetBytes($Salt.salt), $rounds,
                                                               [Security.Cryptography.HashAlgorithmName]::SHA256)
        try { $hash = -join ($kdf.GetBytes(32) | ForEach-Object { $_.ToString("x2") }) } finally { $kdf.Dispose() }
    }
    return Get-Md5Hex $utf8.GetBytes($Salt.rnd + $hash)
}

try {
    Write-Host "Logging in to $base as $($Credential.UserName)"
    $salt = Invoke-UrBackup "salt" @{ username = $Credential.UserName }
    if (-not $salt.ses) { throw "UrBackup user '$($Credential.UserName)' does not exist on the server." }
    $script:session = $salt.ses
    if (-not $salt.salt) { throw "The server gave no login challenge for '$($Credential.UserName)'." }
    $plain = $Credential.GetNetworkCredential().Password
    $answer = Get-PasswordAnswer $salt $plain
    Remove-Variable plain
    $login = Invoke-UrBackup "login" @{ username = $Credential.UserName; password = $answer }
    if (-not $login.success) { throw "Login refused: wrong password for '$($Credential.UserName)'." }
    Write-Ok "Logged in"

    # --- Make (or find) this PC on the server ---
    $new = Invoke-UrBackup "add_client" @{ clientname = $ClientName }
    $query = @{ ses = $script:session }
    if ($new.PSObject.Properties.Name -contains "already_exists") {
        $status = Invoke-UrBackup "status"
        $known = @($status.status) | Where-Object { $_.name -eq $ClientName } | Select-Object -First 1
        if (-not $known) {
            $known = @($status.client_downloads) | Where-Object { $_.name -eq $ClientName } | Select-Object -First 1
        }
        if (-not $known) { throw "'$ClientName' exists on the server, but this user cannot see it. Give the user 'settings: all'." }
        $query["clientid"] = $known.id
        Write-Ok "'$ClientName' is already known on the server (id $($known.id)), fetching its installer"
    } elseif ($new.new_authkey) {
        $query["clientid"] = $new.new_clientid
        $query["authkey"] = $new.new_authkey
        Write-Ok "'$ClientName' added on the server (id $($new.new_clientid))"
    } else {
        throw "The server did not add '$ClientName'. Does this user have the right 'add_client: all'?"
    }
    $query["os"] = "windows"

    # --- Download the installer made for this PC ---
    $qs = ($query.GetEnumerator() | ForEach-Object { "$($_.Key)=$([uri]::EscapeDataString([string]$_.Value))" }) -join "&"
    try {
        Invoke-WebRequest -Uri "$base`?a=download_client&$qs" -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
    } catch {
        throw "Download of the installer failed: $($_.Exception.Message)"
    }
    $size = (Get-Item -LiteralPath $OutFile).Length
    if ($size -lt 10KB) {
        $text = Get-Content -LiteralPath $OutFile -Raw -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw "The server sent no installer ($size bytes). Is 'Download client from update server' on? Server said: $text"
    }
    Write-Ok "Installer downloaded: $OutFile ($([math]::Round($size / 1MB, 1)) MB)"
} catch {
    Write-Err $_.Exception.Message
    exit 1
}

if ($DownloadOnly) {
    Write-Ok "Done. Run it on the PC with: `"$OutFile`" /S"
    exit 0
}

# --- Install silently and check the service ---
# The installer runs as administrator, so it must really come from your UrBackup server. UrBackup cannot
# sign an installer that its server makes with your settings inside (the UrBackup developer on the forum),
# so the download itself has to be trusted: https checks the server, plain http does not. Over http
# anyone on your network who pretends to be the server could hand out his own program. A valid signature
# proves nothing here: an attacker can hand out any signed program, so only the way it came in counts.
if ($base -like "https://*") {
    Write-Ok "Downloaded over https from $serverHost (UrBackup does not sign installers it makes per computer)"
} elseif ($AllowHttp) {
    Write-Host "Downloaded over plain http: installing because of -AllowHttp. Only do this on a network you trust." -ForegroundColor Yellow
} else {
    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
    Write-Err "Not installed: the installer came over plain http, so it could have been swapped on the way."
    Write-Err "Reach the UrBackup server over https, or accept that risk on a network you trust with -AllowHttp."
    exit 1
}
Write-Host "Installing silently..."
$p = Start-Process -FilePath $OutFile -ArgumentList "/S" -Wait -PassThru
if ($p.ExitCode -ne 0) {
    Write-Err "The installer stopped with exit code $($p.ExitCode)."
    exit 1
}
$service = $null
foreach ($i in 1..30) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") { break }
    Start-Sleep -Seconds 2
}
if (-not $service -or $service.Status -ne "Running") {
    Write-Err "The UrBackup client service ($ServiceName) is not running after the install."
    exit 1
}
Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
Write-Ok "UrBackup client installed and running as '$ClientName'."
Write-Ok "It shows up on the UrBackup status page within a few minutes. Set the folders and image backups on the server."
exit 0
