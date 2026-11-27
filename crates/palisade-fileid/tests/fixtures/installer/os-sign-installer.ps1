# Signs an installer package with the OS's own signing cmdlet, so
# tests/installer_os.rs can check that palisade-fileid verifies a
# signature the OS made (#53). It makes a throwaway self-signed
# code-signing certificate in the current user's store, signs a copy of
# -In to -Out (SHA-256, no timestamp), then deletes the certificate.
#
# Exit codes: 0 done, 3 the cmdlets are not available on this machine.
param(
    [Parameter(Mandatory = $true)][string]$In,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue) -or
    -not (Get-Command Set-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
    Write-Output 'the signing cmdlets are not available'
    exit 3
}
$cert = New-SelfSignedCertificate -Type CodeSigningCert -KeyAlgorithm RSA -KeyLength 2048 `
    -Subject 'CN=Palisade Test OS Installer Signer, O=Palisade Tests' `
    -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
try {
    Copy-Item -LiteralPath $In -Destination $Out -Force
    $result = Set-AuthenticodeSignature -LiteralPath $Out -Certificate $cert -HashAlgorithm SHA256
    if ($null -eq $result.SignerCertificate) {
        throw "signing failed: $($result.StatusMessage)"
    }
} finally {
    # -DeleteKey also removes the throwaway certificate's private key.
    Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $cert.Thumbprint) -DeleteKey -ErrorAction SilentlyContinue
}
