# Builds and signs app packages with the OS SDK's own tools (#53), for
# tests/package_os.rs, so the test compares this crate with the OS on
# packages the OS's own tools made rather than on our fixtures.
#
# -Layout is a package layout directory written by the test. Its
# AppxManifest.xml holds the placeholder __PUBLISHER__. The script:
#
# 1. finds the SDK's packaging tool (makeappx.exe) and signing tool
#    (signtool.exe) under the Windows Kits bin directory, newest version
#    first, for this machine's architecture, then x64, then x86;
# 2. makes a throwaway self-signed code-signing certificate in the current
#    user's store, and puts its subject in the manifest;
# 3. packs the layout into -Out\sdk-app.msix, and bundles a copy of that
#    package into -Out\sdk-bundle.msixbundle;
# 4. signs both (SHA-256, no timestamp), then deletes the certificate.
#
# Output, tab-separated, in -Out\sdk.txt:
#   TOOL <tab> pack|sign <tab> path
#   SUBJECT <tab> the certificate subject, as written in the manifest
#
# Exit codes: 0 done, 3 a tool or the signing cmdlets are missing, 1 a tool
# failed (its output is printed).
param(
    [Parameter(Mandatory = $true)][string]$Layout,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'sdk-tools.ps1')

function Invoke-Tool([string]$tool, [string[]]$arguments) {
    # A native tool's stderr must not stop the script before its exit code
    # and output are reported.
    $ErrorActionPreference = 'Continue'
    $output = & $tool @arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Write-Output "$tool $($arguments -join ' ') failed with exit code $($LASTEXITCODE):"
        Write-Output $output
        exit 1
    }
}

$pack = Find-SdkTool 'makeappx.exe'
$sign = Find-SdkTool 'signtool.exe'
if (-not $pack -or -not $sign) {
    Write-Output "the SDK packaging tools are missing: makeappx.exe=$pack signtool.exe=$sign (looked under Windows Kits\10\bin)"
    exit 3
}
if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    Write-Output 'the certificate cmdlets are not available'
    exit 3
}

# The package-signing certificate the SDK documentation describes: code
# signing usage and an end-entity basic constraints extension.
$cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
    -Subject 'CN=Palisade Test SDK Signer, O=Palisade Tests' `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}') `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
try {
    $subject = $cert.Subject
    $manifest = Join-Path $Layout 'AppxManifest.xml'
    $text = [System.IO.File]::ReadAllText($manifest)
    [System.IO.File]::WriteAllText($manifest, $text.Replace('__PUBLISHER__', $subject))

    $app = Join-Path $Out 'sdk-app.msix'
    Invoke-Tool $pack @('pack', '/o', '/d', $Layout, '/p', $app)
    $payloads = Join-Path $Out 'sdk-payloads'
    New-Item -ItemType Directory -Force -Path $payloads | Out-Null
    Copy-Item -LiteralPath $app -Destination (Join-Path $payloads 'sdk-app_x64.msix')
    $bundle = Join-Path $Out 'sdk-bundle.msixbundle'
    Invoke-Tool $pack @('bundle', '/o', '/bv', '1.2.3.4', '/d', $payloads, '/p', $bundle)
    Remove-Item -LiteralPath $payloads -Recurse -Force

    foreach ($file in @($app, $bundle)) {
        Invoke-Tool $sign @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $cert.Thumbprint, $file)
    }
} finally {
    # -DeleteKey also removes the throwaway certificate's private key.
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
}

$lines = @(
    ("TOOL`tpack`t{0}" -f $pack),
    ("TOOL`tsign`t{0}" -f $sign),
    ("SUBJECT`t{0}" -f $subject)
)
Set-Content -LiteralPath (Join-Path $Out 'sdk.txt') -Value $lines -Encoding UTF8
