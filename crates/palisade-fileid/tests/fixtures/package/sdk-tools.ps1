# Finds the OS SDK's command-line tools (#53), for the package OS tests.
# Dot-sourced by os-sdk-package.ps1 and os-package-identity.ps1.
#
# Find-SdkTool NAME returns the path of NAME (for example makeappx.exe)
# under the Windows Kits bin directory, newest SDK version first, for this
# machine's architecture, then x64, then x86; or $null.
function Find-SdkTool([string]$name) {
    $roots = @()
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base) { $roots += Join-Path $base 'Windows Kits\10\bin' }
    }
    $arches = @()
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'ARM64' { $arches += 'arm64' }
        'AMD64' { $arches += 'x64' }
    }
    $arches += 'x64', 'x86'
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $versions = Get-ChildItem -LiteralPath $root -Directory |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending
        foreach ($v in $versions) {
            foreach ($a in $arches) {
                $p = Join-Path $v.FullName (Join-Path $a $name)
                if (Test-Path -LiteralPath $p) { return $p }
            }
        }
    }
    return $null
}
