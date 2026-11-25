<#
.SYNOPSIS
  Proves the `pfx` signing path end to end on a disposable CI runner (#24),
  with a throwaway self-signed certificate made here and deleted at the end.

.DESCRIPTION
  1. Creates a self-signed code-signing certificate and exports it as a PFX
     with a random password, which doubles as a canary secret.
  2. Signs an unsigned copy of pal.exe with `cargo xtask sign --signer pfx`,
     the PFX and password passed only through the environment, exactly as
     the release workflow passes its secrets.
  3. Checks the canary and the base64 PFX appear nowhere in that output.
  4. Trusts the certificate on this runner, verifies the signature, and
     checks that verifying an unsigned copy fails.
  5. Packages the unsigned executables in -UnsignedDir, signs only the
     package, and checks `cargo xtask release verify` rejects it because
     the executables inside are unsigned.
  6. Removes the certificate and every file it wrote, whatever happened.

  -UnsignedDir is cargo's own release output folder, whose executables
  `dist` never signs (it signs its copies).
  It needs an elevated shell, to trust the certificate machine-wide.
#>
param([Parameter(Mandatory)] [string] $UnsignedDir)
$Unsigned = Join-Path $UnsignedDir 'pal.exe'

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$work = Join-Path ([IO.Path]::GetTempPath()) ('palisade-pfx-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$subject = 'CN=Palisade PFX path test (throwaway), O=Palisade Project'
$failures = 0
function Check([bool] $Ok, [string] $What) {
  if ($Ok) { Write-Host "ok:   $What" } else { Write-Host "::error title=PFX signing test::$What"; $script:failures++ }
}

try {
  $canary = 'canary-' + [guid]::NewGuid().ToString('N')
  $cert = New-SelfSignedCertificate -Subject $subject -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(1)
  $pfx = Join-Path $work 'throwaway.pfx'
  Export-PfxCertificate -Cert $cert -FilePath $pfx -Password (ConvertTo-SecureString $canary -AsPlainText -Force) | Out-Null
  $cer = Join-Path $work 'throwaway.cer'
  Export-Certificate -Cert $cert -FilePath $cer | Out-Null
  # Only the PFX file is used from here on, as in a release.
  Remove-Item -Path $cert.PSPath -DeleteKey
  $base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx))

  $target = Join-Path $work 'pal.exe'
  Copy-Item $Unsigned $target
  $unsignedCopy = Join-Path $work 'unsigned.exe'
  Copy-Item $Unsigned $unsignedCopy
  Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null

  $env:PALISADE_SIGN_PFX_BASE64 = $base64
  $env:PALISADE_SIGN_PFX_PASSWORD = $canary
  $output = & cargo xtask sign --signer pfx --no-timestamp $target 2>&1 | Out-String
  $code = $LASTEXITCODE
  Remove-Item Env:\PALISADE_SIGN_PFX_BASE64, Env:\PALISADE_SIGN_PFX_PASSWORD
  # Shown with the canary removed, in case the check below fails.
  Write-Host ($output.Replace($canary, '<canary>').Replace($base64, '<pfx>'))
  Check ($code -eq 0) 'cargo xtask sign --signer pfx signs and verifies the file'
  Check (-not $output.Contains($canary)) 'the PFX password is not in the signing output'
  Check (-not $output.Contains($base64.Substring(0, 64))) 'the PFX is not in the signing output'

  $signature = Get-AuthenticodeSignature -FilePath $target
  Check ($signature.Status -eq 'Valid') "the signature is valid ($($signature.Status))"
  Check ($signature.SignerCertificate.Subject -eq $subject) 'it is signed by the throwaway certificate'
  Check (@(Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq $subject).Count -eq 0) 'the signing step removed the certificate from the store'

  & cargo xtask sign --signer none --verify --no-timestamp $unsignedCopy 2>&1 | Out-Null
  Check ($LASTEXITCODE -ne 0) 'verifying an unsigned file fails'

  # A signed package around unsigned executables.
  $inner = Join-Path $work 'inner-unsigned'
  $env:PALISADE_SIGN_PFX_BASE64 = $base64
  $env:PALISADE_SIGN_PFX_PASSWORD = $canary
  & cargo xtask dist --msi --from $UnsignedDir --sign pfx --no-timestamp --out $inner 2>&1 | Out-Null
  $built = $LASTEXITCODE
  Remove-Item Env:\PALISADE_SIGN_PFX_BASE64, Env:\PALISADE_SIGN_PFX_PASSWORD
  Check ($built -eq 0) 'a package of unsigned executables can be built and signed (for this test)'
  $msi = @(Get-ChildItem $inner -Filter 'Palisade-*.msi')
  Check ($msi.Count -eq 1 -and (Get-AuthenticodeSignature $msi[0].FullName).Status -eq 'Valid') 'the package itself is validly signed'
  $verifyDir = Join-Path $work 'verify'
  New-Item -ItemType Directory $verifyDir | Out-Null
  Copy-Item $msi[0].FullName $verifyDir
  $report = & cargo xtask release verify $verifyDir --allow-untimestamped 2>&1 | Out-String
  Check ($LASTEXITCODE -ne 0) 'release verify rejects a signed package with unsigned executables inside'
  Check ($report -match 'palisade-agent\.exe' -and $report -match 'pal\.exe') 'the report names the unsigned executables'
} finally {
  Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\TrustedPublisher, Cert:\CurrentUser\My |
    Where-Object Subject -eq $subject | ForEach-Object { Remove-Item -Path $_.PSPath -DeleteKey -ErrorAction SilentlyContinue }
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $work
}

if ($failures -gt 0) { exit 1 }
Write-Host 'The pfx signing path works end to end.'
# The expected failures above leave a non-zero $LASTEXITCODE behind.
exit 0
