# Installs, or removes, a signed test package (#333), for
# tests/package_installed.rs, so installed-package listing, executable
# mapping and app execution alias resolution are tested against a package
# the OS really installed.
#
# -Action install, with -Layout (a package layout whose AppxManifest.xml
# holds the placeholder __PUBLISHER__) and -Out:
#
# 1. removes any earlier copy of the package -Name, for every user;
# 2. makes a throwaway self-signed code-signing certificate in the current
#    user's store and puts its subject in the manifest;
# 3. packs the layout with the SDK's packaging tool and signs it (SHA-256,
#    no timestamp);
# 4. trusts the certificate's public part in the machine's TrustedPeople
#    store, which is what sideloading a package needs, and deletes its
#    private key;
# 5. installs the package for the current user.
#
# Output, tab-separated, in -Out\installed.txt:
#   FULLNAME <tab> the installed package's full name
#   LOCATION <tab> its install folder
#   SUBJECT <tab> the certificate subject
#   ALIAS <tab> the path of its app execution alias -Alias, in the
#   current user's alias folder (the OS creates it at install)
#   USER <tab> the current user's SID
#
# -Action remove removes the package -Name for every user and every
# TrustedPeople certificate with the test subject. Run it whatever
# happened.
#
# Needs an elevated shell. Exit codes: 0 done, 3 a tool or cmdlet is
# missing, 1 a step failed (its output is printed).
param(
    [Parameter(Mandatory = $true)][ValidateSet('install', 'remove')][string]$Action,
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Layout,
    [string]$Out,
    [string]$Alias
)
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'sdk-tools.ps1')

$Subject = 'CN=Palisade Installed Package Test, O=Palisade Tests'

function Invoke-Tool([string]$tool, [string[]]$arguments) {
    $ErrorActionPreference = 'Continue'
    $output = & $tool @arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Output "$tool $($arguments -join ' ') failed with exit code $($LASTEXITCODE):"
        Write-Output $output
        exit 1
    }
}

function Remove-TestPackage {
    Get-AppxPackage -AllUsers -Name $Name -ErrorAction SilentlyContinue |
        ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }
    Get-ChildItem -Path Cert:\LocalMachine\TrustedPeople |
        Where-Object { $_.Subject -eq $Subject } |
        ForEach-Object { Remove-Item -LiteralPath $_.PSPath -ErrorAction SilentlyContinue }
}

if (-not (Get-Command Add-AppxPackage -ErrorAction SilentlyContinue)) {
    Write-Output 'the package deployment cmdlets are not available'
    exit 3
}

if ($Action -eq 'remove') {
    Remove-TestPackage
    exit 0
}

$pack = Find-SdkTool 'makeappx.exe'
$sign = Find-SdkTool 'signtool.exe'
if (-not $pack -or -not $sign) {
    Write-Output "the SDK packaging tools are missing: makeappx.exe=$pack signtool.exe=$sign (looked under Windows Kits\10\bin)"
    exit 3
}

Remove-TestPackage

$cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
    -Subject $Subject `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}') `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
try {
    $manifest = Join-Path $Layout 'AppxManifest.xml'
    $text = [System.IO.File]::ReadAllText($manifest)
    [System.IO.File]::WriteAllText($manifest, $text.Replace('__PUBLISHER__', $cert.Subject))

    $package = Join-Path $Out 'installed-test.msix'
    Invoke-Tool $pack @('pack', '/o', '/d', $Layout, '/p', $package)
    Invoke-Tool $sign @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $cert.Thumbprint, $package)

    $cer = Join-Path $Out 'installed-test.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
} finally {
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
}

try {
    Add-AppxPackage -Path $package
} catch {
    Write-Output "installing the package failed: $_"
    Get-AppxLog -ErrorAction SilentlyContinue | Select-Object -Last 20 | Out-String | Write-Output
    exit 1
}
$installed = Get-AppxPackage -Name $Name
if (-not $installed) {
    Write-Output "the package $Name is not installed after Add-AppxPackage"
    exit 1
}

# The OS writes the alias reparse point, in the user's alias folder two
# levels under %LOCALAPPDATA% (its name is the OS vendor's, which this
# repository does not spell), shortly after the install returns.
function Find-Alias {
    Get-ChildItem -LiteralPath $env:LOCALAPPDATA -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
        ForEach-Object { Join-Path $_.FullName $Alias } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
}
$aliasPath = $null
for ($i = 0; $i -lt 30 -and -not $aliasPath; $i++) {
    $aliasPath = Find-Alias
    if (-not $aliasPath) { Start-Sleep -Milliseconds 500 }
}
if (-not $aliasPath) {
    Write-Output "the alias $Alias was not created under $env:LOCALAPPDATA"
    exit 1
}

$lines = @(
    ("FULLNAME`t{0}" -f $installed.PackageFullName),
    ("LOCATION`t{0}" -f $installed.InstallLocation),
    ("SUBJECT`t{0}" -f $cert.Subject),
    ("ALIAS`t{0}" -f $aliasPath),
    ("USER`t{0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
)
Set-Content -LiteralPath (Join-Path $Out 'installed.txt') -Value $lines -Encoding UTF8
