# Asks the OS about app packages (#53), for tests/package_os.rs.
#
# For each publisher string in -Publishers (one per line), the OS package
# identity API (Windows.ApplicationModel package family name derivation,
# via the PackageFamilyNameFromId function) computes the family name of a
# package called Palisade.Probe from that publisher. For each package in
# -Dir, the OS trust-verification API (WinVerifyTrust, the generic
# verify action, no revocation check, no UI) reports its result code.
# Output, tab-separated:
#   PFN <tab> publisher <tab> family name
#   FULL <tab> x64|bundle <tab> full name (of the first publisher)
#   SIG <tab> file name <tab> result code (hex)
#
# Exit codes: 0 done, 3 a needed OS component is not available.
param(
    [Parameter(Mandatory = $true)][string]$Publishers,
    [Parameter(Mandatory = $true)][string]$Dir,
    [Parameter(Mandatory = $true)][string]$Out
)
$ErrorActionPreference = 'Stop'
$source = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class PalisadePackageId {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PACKAGE_ID {
        public uint reserved;
        public uint processorArchitecture;
        public ulong version;
        public string name;
        public string publisher;
        public string resourceId;
        public string publisherId;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern int PackageFamilyNameFromId(ref PACKAGE_ID id, ref uint len, StringBuilder name);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern int PackageFullNameFromId(ref PACKAGE_ID id, ref uint len, StringBuilder name);
    // Full name of a package: version 1.2.3.4, the given architecture
    // (PROCESSOR_ARCHITECTURE_*, 11 = neutral) and resource ID.
    public static string Full(string name, string publisher, uint arch, string resourceId) {
        var id = new PACKAGE_ID { name = name, publisher = publisher, processorArchitecture = arch,
            resourceId = resourceId, version = (1UL << 48) | (2UL << 32) | (3UL << 16) | 4UL };
        uint len = 256;
        var sb = new StringBuilder((int)len);
        int rc = PackageFullNameFromId(ref id, ref len, sb);
        if (rc != 0) { throw new Exception("PackageFullNameFromId failed: " + rc); }
        return sb.ToString();
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_FILE_INFO {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    public static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
    public static int Verify(string path) {
        // WINTRUST_ACTION_GENERIC_VERIFY_V2.
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(file));
        try {
            Marshal.StructureToPtr(file, pFile, false);
            var data = new WINTRUST_DATA {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice = 2,          // WTD_UI_NONE
                fdwRevocationChecks = 0, // WTD_REVOKE_NONE
                dwUnionChoice = 1,       // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 1,       // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x40,      // WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            int rc = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;      // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return rc;
        } finally {
            Marshal.FreeHGlobal(pFile);
        }
    }
    public static string Family(string name, string publisher) {
        var id = new PACKAGE_ID { name = name, publisher = publisher, processorArchitecture = 11 };
        uint len = 256;
        var sb = new StringBuilder((int)len);
        int rc = PackageFamilyNameFromId(ref id, ref len, sb);
        if (rc != 0) { throw new Exception("PackageFamilyNameFromId failed: " + rc); }
        return sb.ToString();
    }
}
'@
try {
    Add-Type -TypeDefinition $source -Language CSharp
} catch {
    Write-Output "the package identity API is not available: $_"
    exit 3
}
$lines = New-Object System.Collections.Generic.List[string]
foreach ($p in Get-Content -LiteralPath $Publishers -Encoding UTF8) {
    if ($p.Length -eq 0) { continue }
    $lines.Add("PFN`t{0}`t{1}" -f $p, [PalisadePackageId]::Family('Palisade.Probe', $p))
}
# Full names: x64 (9) with no resource ID, and neutral with the bundle's `~`.
$first = (Get-Content -LiteralPath $Publishers -Encoding UTF8 | Where-Object { $_ })[0]
$lines.Add("FULL`tx64`t{0}" -f [PalisadePackageId]::Full('Palisade.Probe', $first, 9, $null))
$lines.Add("FULL`tbundle`t{0}" -f [PalisadePackageId]::Full('Palisade.Probe', $first, 11, '~'))
foreach ($file in Get-ChildItem -LiteralPath $Dir -File) {
    if ($file.Extension -notin '.msix', '.msixbundle') { continue }
    $rc = [PalisadePackageId]::Verify($file.FullName)
    $lines.Add("SIG`t{0}`t{1:x8}" -f $file.Name, $rc)
}
Set-Content -LiteralPath $Out -Value $lines -Encoding UTF8
