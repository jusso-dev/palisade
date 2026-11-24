# Runs the OS code integrity policy cmdlets over a directory of PE files
# and writes every hash rule they emit, one per line: the rule's friendly
# name, a tab, then its hash in hex. tests/os_policy_tooling.rs calls this
# on Windows and compares each value with palisade-fileid's (#47).
#
# The friendly names end in " Hash Sha1", " Hash Sha256" (the Authenticode
# image hashes), " Hash Page Sha1" or " Hash Page Sha256" (the code
# integrity page hash values).
#
# Exit codes: 0 done, 3 the cmdlets are not installed on this machine.
param(
    [Parameter(Mandatory = $true)][string]$Dir,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
    Write-Output 'the code integrity policy cmdlets are not installed'
    exit 3
}
$policy = Join-Path ([System.IO.Path]::GetTempPath()) ("palisade-ci-{0}.xml" -f [guid]::NewGuid())
try {
    New-CIPolicy -Level Hash -ScanPath $Dir -UserPEs -NoShadowCopy -FilePath $policy | Out-Null
    [xml]$xml = Get-Content -LiteralPath $policy -Raw
    $lines = foreach ($rule in $xml.SelectNodes("//*[local-name()='FileRules']/*[@Hash]")) {
        "{0}`t{1}" -f $rule.GetAttribute('FriendlyName'), $rule.GetAttribute('Hash')
    }
    Set-Content -LiteralPath $Out -Value $lines -Encoding Ascii
} finally {
    Remove-Item -LiteralPath $policy -ErrorAction SilentlyContinue
}
