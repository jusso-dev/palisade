# Captures reference values from OS tooling for the file identity corpus
# (#55). For each path it writes one tab-separated line:
#   path, flat SHA-256 (Get-FileHash), signature status
#   (Get-AuthenticodeSignature), signature type (Authenticode or catalog),
#   signer certificate SHA-1 thumbprint, OriginalFilename, FileVersion
#   (the version resource's fixed info, as the OS file-version API reports
#   it), CompanyName, and the number of embedded signatures (the PE
#   certificate table's entries, read from the file itself, so a file signed
#   both in a catalog and inside is told apart from a catalog-only one).
# tests/identity_os.rs calls this on Windows and compares each value with
# palisade_fileid::identity.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Paths
)
$ErrorActionPreference = 'Stop'
$lines = foreach ($p in $Paths) {
    $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()
    $sig = Get-AuthenticodeSignature -LiteralPath $p
    $thumb = ''
    if ($sig.SignerCertificate) { $thumb = $sig.SignerCertificate.Thumbprint.ToLowerInvariant() }
    $v = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p)
    $fixed = '{0}.{1}.{2}.{3}' -f $v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart
    # The certificate table: the security data directory of the optional
    # header, read with the file's own offsets. Its size is 0 when the file
    # carries no embedded signature.
    $bytes = [System.IO.File]::ReadAllBytes($p)
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    $magic = [BitConverter]::ToUInt16($bytes, $pe + 24)
    $dirs = $pe + 24 + $(if ($magic -eq 0x20b) { 112 } else { 96 })
    $certSize = [BitConverter]::ToUInt32($bytes, $dirs + 4 * 8 + 4)
    $embedded = $(if ($certSize -gt 0) { 1 } else { 0 })
    "{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}" -f $p, $hash, $sig.Status, $sig.SignatureType, $thumb, $v.OriginalFilename, $fixed, $v.CompanyName, $embedded
}
Set-Content -LiteralPath $Out -Value $lines -Encoding UTF8
