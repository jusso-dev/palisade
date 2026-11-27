# Finds the OS SDK's command-line tools (#53), for the package OS tests.
# Dot-sourced by os-sdk-package.ps1 and os-sdk-sign.ps1.
#
# Find-SdkTool NAME returns the path of NAME (for example makeappx.exe)
# under the Windows Kits bin directories: the newest SDK version across
# both Program Files roots first (root order only breaks a tie), and within
# a version this machine's own architecture first, then x64, then x86;
# or $null.
function Find-SdkTool([string]$name) {
    $roots = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base) { $roots += Join-Path $base 'Windows Kits\10\bin' }
    }
    $arches = @()
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { $arches += 'arm64' }
        'AMD64' { $arches += 'x64' }
        'x86' { $arches += 'x86' }
    }
    $arches += 'x64', 'x86'
    $arches = $arches | Select-Object -Unique
    $candidates = @()
    for ($i = 0; $i -lt $roots.Count; $i++) {
        if (-not (Test-Path -LiteralPath $roots[$i])) { continue }
        foreach ($v in Get-ChildItem -LiteralPath $roots[$i] -Directory) {
            if ($v.Name -match '^\d+\.\d+\.\d+\.\d+$') {
                $candidates += [pscustomobject]@{ Version = [version]$v.Name; Root = $i; Path = $v.FullName }
            }
        }
    }
    $sorted = $candidates | Sort-Object -Property @{ Expression = 'Version'; Descending = $true }, @{ Expression = 'Root'; Descending = $false }
    foreach ($c in $sorted) {
        foreach ($a in $arches) {
            $p = Join-Path $c.Path (Join-Path $a $name)
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    return $null
}
