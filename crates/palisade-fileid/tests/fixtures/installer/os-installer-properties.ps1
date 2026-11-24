# Reads installer packages with the OS installer API (the
# WindowsInstaller.Installer automation object) and writes, for each one,
# tab-separated lines: file name, field, value. Fields: the Property
# table's ProductCode, UpgradeCode, ProductName, ProductVersion,
# Manufacturer and ProductLanguage; the summary information's revision
# number (PackageCode, PID 9) and template (PID 7); and, for signed
# packages, whether the OS verifies the signature against the content
# (Signature: Valid or the OS status). tests/installer_os.rs calls this on
# Windows and compares each value with palisade-fileid's (#53).
#
# Exit codes: 0 done, 3 the installer API is not available on this machine.
param(
    [Parameter(Mandatory = $true)][string]$Dir,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
} catch {
    Write-Output 'the installer API is not available'
    exit 3
}
$fields = 'ProductCode', 'UpgradeCode', 'ProductName', 'ProductVersion', 'Manufacturer', 'ProductLanguage'
$lines = foreach ($file in Get-ChildItem -LiteralPath $Dir -Filter '*.msi') {
    # 0 = msiOpenDatabaseModeReadOnly.
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($file.FullName, 0))
    foreach ($name in $fields) {
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db,
            @("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$name'"))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -ne $record) {
            $value = $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
            "{0}`t{1}`t{2}" -f $file.Name, $name, $value
        }
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
    }
    $info = $db.GetType().InvokeMember('SummaryInformation', 'GetProperty', $null, $db, 0)
    foreach ($propId in 7, 9) {
        $value = $info.GetType().InvokeMember('Property', 'GetProperty', $null, $info, $propId)
        "{0}`tPID{1}`t{2}" -f $file.Name, $propId, $value
    }
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null
    $sig = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($sig.Status -ne 'NotSigned') {
        # The test root is not trusted here, so a signature whose content
        # hash verifies reports UnknownError (untrusted root), and one that
        # does not reports HashMismatch.
        "{0}`tSignature`t{1}" -f $file.Name, $sig.Status
    }
}
Set-Content -LiteralPath $Out -Value $lines -Encoding UTF8
