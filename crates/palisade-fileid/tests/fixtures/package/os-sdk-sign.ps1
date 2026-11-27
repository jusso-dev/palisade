# Signs packages with the OS SDK's own signing tool (#53), for
# tests/package_os.rs: it lets the test compare this crate's package digest
# with the one the OS's own signer writes, on packages this crate's test
# builder made, and ask the OS about the result.
#
# Every .msix and .msixbundle file in -Dir is signed in place (SHA-256, no
# timestamp) with a throwaway self-signed code-signing certificate whose
# subject is -Subject (the manifests' publisher), made in the current
# user's store and deleted afterwards. A file the tool refuses is reported,
# not fatal, so one run shows every result.
#
# Output, tab-separated, in -Dir\sign.txt:
#   SIGNED <tab> file name
#   REFUSED <tab> file name <tab> the tool's output, on one line
#   TOOL <tab> sign <tab> path
#
# Exit codes: 0 done, 3 the tool or the certificate cmdlets are missing.
param(
    [Parameter(Mandatory = $true)][string]$Dir,
    [Parameter(Mandatory = $true)][string]$Subject
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'sdk-tools.ps1')

$sign = Find-SdkTool 'signtool.exe'
if (-not $sign) {
    Write-Output 'the SDK signing tool is missing: signtool.exe (looked under Windows Kits\10\bin)'
    exit 3
}
if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    Write-Output 'the certificate cmdlets are not available'
    exit 3
}
$cert = New-SelfSignedCertificate -Type Custom -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 `
    -Subject $Subject `
    -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}') `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add(("TOOL`tsign`t{0}" -f $sign))
try {
    foreach ($file in Get-ChildItem -LiteralPath $Dir -File) {
        if ($file.Extension -notin '.msix', '.msixbundle') { continue }
        $ErrorActionPreference = 'Continue'
        $output = & $sign sign /fd SHA256 /s My /sha1 $cert.Thumbprint $file.FullName 2>&1 | Out-String
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($code -eq 0) {
            $lines.Add(("SIGNED`t{0}" -f $file.Name))
        } else {
            $lines.Add(("REFUSED`t{0}`texit {1}: {2}" -f $file.Name, $code, ($output -replace '\s+', ' ')))
        }
    }
} finally {
    # -DeleteKey also removes the throwaway certificate's private key.
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
}
Set-Content -LiteralPath (Join-Path $Dir 'sign.txt') -Value $lines -Encoding UTF8
