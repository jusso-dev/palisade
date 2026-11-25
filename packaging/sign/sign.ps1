<#
.SYNOPSIS
  Signs or verifies one file with Authenticode, for `cargo xtask sign` (#24).

.DESCRIPTION
  -Signer pfx      The PKCS#12 file (base64) and its password come from
                   PALISADE_SIGN_PFX_BASE64 and PALISADE_SIGN_PFX_PASSWORD.
                   The file is written to a temporary folder only this user
                   can read, imported into this user's certificate store for
                   the one signature, then removed from the store and deleted,
                   whatever happens.
  -Signer test-ca  Creates a throwaway root CA and a code-signing leaf issued
                   by it in this user's store, signs, and leaves them there
                   for the verify step; `-Action cleanup` removes them. For
                   CI tests on disposable runners only: verification needs
                   the root trusted, which -Action trust does, machine-wide.

  Every signature uses a SHA-256 file digest. With PALISADE_TSA_URLS set
  (space-separated), an RFC 3161 SHA-256 timestamp is added from the first
  server that answers; -RequireTimestamp makes it mandatory.

  -Action verify checks the file with the OS signing tool's default
  Authenticode policy (/pa) and every signature (/all), that the signing
  certificate uses SHA-256 or better, and with -RequireTimestamp that the
  signature is timestamped.

  No secret is passed on a command line or printed; the signing tool is
  given only a thumbprint.
#>
param(
  [Parameter(Mandatory)] [ValidateSet('sign', 'verify', 'trust', 'cleanup')] [string] $Action,
  # Not needed to verify.
  [ValidateSet('test-ca', 'pfx')] [string] $Signer = 'test-ca',
  [string] $Path,
  # Sign: fail unless a timestamp server answers. Verify: fail unless the
  # signature is timestamped.
  [switch] $RequireTimestamp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TestSubject = 'CN=Palisade test signing (not trusted), O=Palisade Project'
$TestRootSubject = 'CN=Palisade test root (not trusted), O=Palisade Project'

function SignTool {
  # The newest SDK's signing tool for this machine's architecture.
  $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
  $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $found = Get-ChildItem -Path $kits -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^10\.' } | Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName "$arch\signtool.exe" } | Where-Object { Test-Path $_ } |
    Select-Object -First 1
  if (-not $found) { throw "the Windows SDK signing tool was not found under $kits" }
  $found
}

# The configured servers, always as an array (empty when none).
function TsaUrls {
  $urls = @()
  foreach ($url in ("$env:PALISADE_TSA_URLS" -split '\s+')) { if ($url) { $urls += $url } }
  , $urls
}

function Run([string] $Tool, [string[]] $Arguments) {
  & $Tool @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$(Split-Path -Leaf $Tool) exited with $LASTEXITCODE" }
}

# Signs with the certificate whose thumbprint is given, trying each timestamp
# server in turn.
function SignWith([string] $Thumbprint, [bool] $TimestampRequired) {
  $tool = SignTool
  $base = @('sign', '/fd', 'SHA256', '/sha1', $Thumbprint, '/s', 'My')
  $urls = TsaUrls
  if ($urls.Count -eq 0) {
    if ($TimestampRequired) { throw 'PALISADE_TSA_URLS is required for this signer' }
    Write-Host "sign: $Path (no timestamp server configured)"
    Run $tool ($base + @($Path))
    return
  }
  foreach ($url in $urls) {
    & $tool @($base + @('/tr', $url, '/td', 'SHA256', $Path))
    if ($LASTEXITCODE -eq 0) {
      Write-Host "sign: $Path (timestamped by $url)"
      return
    }
    Write-Host "::warning title=Timestamp server::$url failed; trying the next one"
  }
  throw "every timestamp server failed for $Path"
}

function TestCerts {
  @(Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $TestSubject -or $_.Subject -eq $TestRootSubject })
}

switch ($Action) {
  'sign' {
    if (-not $Path) { throw '-Path is required' }
    if ($Signer -eq 'test-ca') {
      $leaf = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq $TestSubject) | Select-Object -First 1
      if (-not $leaf) {
        # The root is a CA (basic constraints) limited to code signing
        # (extended key usage), because the OS checks the whole chain is
        # valid for that usage.
        $root = New-SelfSignedCertificate -Subject $TestRootSubject -CertStoreLocation Cert:\CurrentUser\My `
          -KeyUsage CertSign, CRLSign -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
          -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0', '2.5.29.37={text}1.3.6.1.5.5.7.3.3') `
          -NotAfter (Get-Date).AddDays(2)
        $leaf = New-SelfSignedCertificate -Subject $TestSubject -Type CodeSigningCert -Signer $root `
          -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
          -NotAfter (Get-Date).AddDays(1)
        # The root's public certificate, for -Action trust.
        Export-Certificate -Cert $root -FilePath (Join-Path ([IO.Path]::GetTempPath()) 'palisade-test-root.cer') | Out-Null
        Write-Host "sign: created the throwaway test CA ($($root.Thumbprint)) and leaf ($($leaf.Thumbprint))"
      }
      SignWith $leaf.Thumbprint $RequireTimestamp.IsPresent
    } else {
      if (-not $env:PALISADE_SIGN_PFX_BASE64 -or -not $env:PALISADE_SIGN_PFX_PASSWORD) {
        throw 'PALISADE_SIGN_PFX_BASE64 and PALISADE_SIGN_PFX_PASSWORD must be set'
      }
      $dir = Join-Path ([IO.Path]::GetTempPath()) ('palisade-sign-' + [guid]::NewGuid().ToString('N'))
      $cert = $null
      try {
        New-Item -ItemType Directory -Path $dir | Out-Null
        # Only this user may read the folder.
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
        Set-Acl -Path $dir -AclObject $acl
        $pfx = Join-Path $dir 'signing.pfx'
        [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:PALISADE_SIGN_PFX_BASE64))
        $password = ConvertTo-SecureString -String $env:PALISADE_SIGN_PFX_PASSWORD -AsPlainText -Force
        $cert = Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\CurrentUser\My -Password $password
        $cert = @($cert | Where-Object HasPrivateKey) | Select-Object -First 1
        if (-not $cert) { throw 'the PFX has no certificate with a private key' }
        SignWith $cert.Thumbprint $RequireTimestamp.IsPresent
      } finally {
        if ($cert) { Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue }
        Remove-Item -Recurse -Force -Path $dir -ErrorAction SilentlyContinue
      }
    }
  }
  'verify' {
    if (-not $Path) { throw '-Path is required' }
    $tool = SignTool
    Run $tool @('verify', '/pa', '/all', $Path)
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid') { throw "$Path`: signature status $($signature.Status)" }
    if ($RequireTimestamp -and -not $signature.TimeStamperCertificate) {
      throw "$Path`: the signature has no timestamp"
    }
    if ($signature.SignerCertificate.SignatureAlgorithm.FriendlyName -notmatch 'sha256|sha384|sha512') {
      throw "$Path`: signed with $($signature.SignerCertificate.SignatureAlgorithm.FriendlyName)"
    }
    Write-Host "verify: $Path signed by $($signature.SignerCertificate.Subject)"
  }
  'trust' {
    # Disposable runners only: trusts the throwaway root machine-wide so
    # verification can build a chain.
    if ($Signer -ne 'test-ca') { throw 'trust is for the test CA only' }
    $cer = Join-Path ([IO.Path]::GetTempPath()) 'palisade-test-root.cer'
    if (-not (Test-Path $cer)) { throw 'sign with the test CA first' }
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Write-Host 'trust: the throwaway test root is trusted on this machine'
  }
  'cleanup' {
    foreach ($cert in TestCerts) { Remove-Item -Path $cert.PSPath -DeleteKey -ErrorAction SilentlyContinue }
    Get-ChildItem Cert:\LocalMachine\Root | Where-Object Subject -eq $TestRootSubject |
      ForEach-Object { Remove-Item -Path $_.PSPath -ErrorAction SilentlyContinue }
    Remove-Item -Force -ErrorAction SilentlyContinue -Path (Join-Path ([IO.Path]::GetTempPath()) 'palisade-test-root.cer')
    Write-Host 'cleanup: test certificates removed'
  }
}
