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
#   DIAG <tab> file name <tab> route=result
#
# DIAG lines ask the OS about each package by other routes, so that one
# run shows why a package is or is not recognised:
#   handle    WinVerifyTrust as for SIG, with an open file handle too
#   subject   the subject type the OS signature layer assigns the file
#             (CryptSIPRetrieveSubjectGuid): the package or bundle GUID
#             when the OS takes it for one
#   reader    the OS packaging API's package or bundle reader
#             (CreatePackageReader / CreateBundleReader), which validates
#             the container, the manifest and the block map
#   readerlog what that API wrote to its operational event log meanwhile
#             (why it refused the package)
#   cmdlet    Get-AuthenticodeSignature's status and message
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
        return Verify(path, IntPtr.Zero);
    }
    // The same, with the file open: the OS reads through the handle.
    public static int VerifyHandle(string path) {
        using (var fs = new System.IO.FileStream(path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read)) {
            return Verify(path, fs.SafeFileHandle.DangerousGetHandle());
        }
    }
    public static int Verify(string path, IntPtr handle) {
        // WINTRUST_ACTION_GENERIC_VERIFY_V2.
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path, hFile = handle };
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
                // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL:
                // no revocation checking and no network, so the verdict
                // does not depend on the runner's network or CRL caches.
                dwProvFlags = 0x10 | 0x1000,
            };
            int rc = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;      // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return rc;
        } finally {
            Marshal.FreeHGlobal(pFile);
        }
    }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CryptSIPRetrieveSubjectGuid(string fileName, IntPtr file, out Guid subject);
    // The subject type the OS signature layer assigns the file.
    public static string Subject(string path) {
        Guid g;
        if (CryptSIPRetrieveSubjectGuid(path, IntPtr.Zero, out g)) {
            string s = g.ToString().ToUpperInvariant();
            if (s == "0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1") { return s + " (package)"; }
            if (s == "0F5F58B3-AADE-4B9A-A434-95742D92ECEB") { return s + " (bundle)"; }
            return s;
        }
        return "error " + Marshal.GetLastWin32Error().ToString("x8");
    }
    [ComImport, Guid("beb94909-e451-438b-b5a7-d79e767b75d8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IPackageFactory {
        [PreserveSig] int CreatePackageWriter(IntPtr output, IntPtr settings, out IntPtr writer);
        [PreserveSig] int CreatePackageReader(IntPtr input, out IntPtr reader);
    }
    [ComImport, Guid("bba65864-965f-4a5f-855f-f074bdbf3a7b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IBundleFactory {
        [PreserveSig] int CreateBundleWriter(IntPtr output, ulong version, out IntPtr writer);
        [PreserveSig] int CreateBundleReader(IntPtr input, out IntPtr reader);
    }
    [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
    public static extern int SHCreateStreamOnFileEx(string file, uint mode, uint attributes, bool create, IntPtr template, out IntPtr stream);
    // The OS packaging API's reader: its result code.
    public static string Reader(string path, bool bundle) {
        IntPtr stream;
        // STGM_READ | STGM_SHARE_DENY_WRITE.
        int hr = SHCreateStreamOnFileEx(path, 0x20, 0, false, IntPtr.Zero, out stream);
        if (hr != 0) { return "open " + hr.ToString("x8"); }
        try {
            IntPtr reader = IntPtr.Zero;
            if (bundle) {
                var f = (IBundleFactory)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("378E0446-5384-43B7-8877-E7DBDD883446")));
                hr = f.CreateBundleReader(stream, out reader);
            } else {
                var f = (IPackageFactory)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("5842A140-FF9F-4166-8F5C-62F5B7B0C781")));
                hr = f.CreatePackageReader(stream, out reader);
            }
            if (reader != IntPtr.Zero) { Marshal.Release(reader); }
            return hr.ToString("x8");
        } catch (Exception e) {
            return "error " + e.Message;
        } finally {
            Marshal.Release(stream);
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
    $lines.Add(("PFN`t{0}`t{1}" -f $p, [PalisadePackageId]::Family('Palisade.Probe', $p)))
}
# Full names: x64 (9) with no resource ID, and neutral with the bundle's `~`,
# of the first publisher (if any were given).
$first = @(Get-Content -LiteralPath $Publishers -Encoding UTF8 | Where-Object { $_ }) | Select-Object -First 1
if ($first) {
    $lines.Add("FULL`tx64`t{0}" -f [PalisadePackageId]::Full('Palisade.Probe', $first, 9, $null))
    $lines.Add("FULL`tbundle`t{0}" -f [PalisadePackageId]::Full('Palisade.Probe', $first, 11, '~'))
}
foreach ($file in Get-ChildItem -LiteralPath $Dir -File) {
    if ($file.Extension -notin '.msix', '.msixbundle') { continue }
    $rc = [PalisadePackageId]::Verify($file.FullName)
    $lines.Add(("SIG`t{0}`t{1:x8}" -f $file.Name, $rc))
    # Diagnostics. Each route is asked on its own, so one that fails does
    # not hide the others.
    $diag = [ordered]@{}
    try { $diag.handle = '{0:x8}' -f [PalisadePackageId]::VerifyHandle($file.FullName) } catch { $diag.handle = "error $_" }
    try { $diag.subject = [PalisadePackageId]::Subject($file.FullName) } catch { $diag.subject = "error $_" }
    $since = Get-Date
    try { $diag.reader = [PalisadePackageId]::Reader($file.FullName, $file.Extension -eq '.msixbundle') } catch { $diag.reader = "error $_" }
    # The packaging API logs why it refused a package (the manifest line
    # and rule, for example) to its operational event log.
    try {
        # The log is found by its name's ending, which avoids spelling out
        # the vendor prefix it carries.
        $log = (Get-WinEvent -ListLog '*-Windows-AppxPackaging/Operational' -ErrorAction Stop | Select-Object -First 1).LogName
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $since.AddSeconds(-1) } -MaxEvents 4 -ErrorAction Stop
        $diag.readerlog = ($events | ForEach-Object { "[$($_.Id)] $($_.Message)" }) -join ' | '
    } catch { $diag.readerlog = "none ($($_.Exception.Message))" }
    try {
        $a = Get-AuthenticodeSignature -LiteralPath $file.FullName
        $diag.cmdlet = "$($a.Status) $($a.StatusMessage)"
    } catch { $diag.cmdlet = "error $_" }
    foreach ($k in $diag.Keys) {
        $v = ([string]$diag[$k]) -replace '\s+', ' '
        $lines.Add(("DIAG`t{0}`t{1}={2}" -f $file.Name, $k, $v))
    }
}
Set-Content -LiteralPath $Out -Value $lines -Encoding UTF8
