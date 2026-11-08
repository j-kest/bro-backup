# version : 0.1
# created by : JK and CF
# last edited : 06/11/2026
# Name : m365-mail-setup.ps1
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Prepares Microsoft 365 so BRO Backup can send its notification mail through the Microsoft Graph API.
#
#   .\m365-mail-setup.ps1 -Mailbox nas@contoso.com
#
# What it does:
#   1. Makes an app registration in Entra ID with a client secret (24 months unless -SecretMonths says less).
#   2. Allows that app to send mail as this one mailbox only, with RBAC for Applications in Exchange
#      Online (role "Application Mail.Send" with a management scope on that mailbox).
#      It deliberately gives the app NO Mail.Send consent in Entra ID: that consent counts for every
#      mailbox in the tenant, and Exchange adds it on top of the scoped role.
#   3. Checks the result with Test-ServicePrincipalAuthorization and prints what to fill in under
#      Settings, Email in BRO Backup.
#
# Needs the modules Microsoft.Graph.Applications and ExchangeOnlineManagement, and an account that is
# Application Administrator (or Cloud Application Administrator) and Exchange Administrator.
# A shared mailbox works as the mailbox to send from and needs no license.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Mailbox,       # the mailbox BRO Backup sends from
    [string]$AppName = "BRO Backup mail",
    [ValidateRange(1, 24)][int]$SecretMonths = 24
)

function Write-Ok([string]$Message) { Write-Host $Message -ForegroundColor Green }
function Write-Err([string]$Message) { Write-Host $Message -ForegroundColor Red }

$ErrorActionPreference = "Stop"

foreach ($module in "Microsoft.Graph.Applications", "ExchangeOnlineManagement") {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Err "The module $module is missing. Install it with: Install-Module $module -Scope CurrentUser"
        exit 1
    }
}
Import-Module Microsoft.Graph.Applications
Import-Module ExchangeOnlineManagement

try {
    Write-Host "Signing in to Microsoft Graph (to make the app registration)..."
    Connect-MgGraph -Scopes "Application.ReadWrite.All" -NoWelcome
    $tenantId = (Get-MgContext).TenantId
    Write-Ok "Signed in to tenant $tenantId"

    Write-Host "Signing in to Exchange Online (to limit the app to one mailbox)..."
    Connect-ExchangeOnline -ShowBanner:$false
    $mbx = Get-EXOMailbox -Identity $Mailbox
    $address = [string]$mbx.PrimarySmtpAddress
    Write-Ok "Mailbox found: $address ($($mbx.RecipientTypeDetails))"

    # --- 1. App registration and client secret ---
    $app = New-MgApplication -DisplayName $AppName -SignInAudience "AzureADMyOrg"
    $sp = New-MgServicePrincipal -AppId $app.AppId
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "BRO Backup"; EndDateTime = (Get-Date).AddMonths($SecretMonths)
    }
    Write-Ok "App registration '$AppName' made (client ID $($app.AppId))"

    # --- 2. Send as this mailbox only (RBAC for Applications) ---
    New-ServicePrincipal -AppId $app.AppId -ObjectId $sp.Id -DisplayName $AppName | Out-Null
    $scopeName = "BRO Backup mail - $address"
    if (-not (Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue)) {
        New-ManagementScope -Name $scopeName -RecipientRestrictionFilter "PrimarySmtpAddress -eq '$address'" | Out-Null
    }
    New-ManagementRoleAssignment -App $app.AppId -Role "Application Mail.Send" -CustomResourceScope $scopeName | Out-Null
    Write-Ok "The app may send as $address, and as no other mailbox"

    # --- 3. Check ---
    $check = Test-ServicePrincipalAuthorization -Identity $app.AppId -Resource $address |
        Where-Object { $_.RoleName -eq "Application Mail.Send" }
    if (-not $check -or -not $check.InScope) {
        Write-Err "Exchange does not confirm the permission for $address yet. Run this later to check:"
        Write-Host "  Test-ServicePrincipalAuthorization -Identity $($app.AppId) -Resource $address"
    } else {
        Write-Ok "Checked: Application Mail.Send for $address is in scope"
    }
} catch {
    Write-Err "Stopped: $($_.Exception.Message)"
    Write-Err "What was already made stays. Remove the app registration '$AppName' in Entra ID before you run this again."
    exit 1
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

Write-Host ""
Write-Ok "Fill this in under Settings, Email in BRO Backup (Send with: Microsoft 365):"
Write-Host "  Tenant ID or domain        : $tenantId"
Write-Host "  Application (client) ID    : $($app.AppId)"
Write-Host "  Client secret              : $($secret.SecretText)"
Write-Host "  Send from mailbox          : $address"
Write-Host "  Client secret expires on   : $($secret.EndDateTime.ToString('yyyy-MM-dd'))"
Write-Host ""
Write-Host "The secret is shown only now: store it in your password manager as well."
Write-Host "Exchange can take 30 minutes to 2 hours before the permission works. Then use 'Send a test notification'."
exit 0
