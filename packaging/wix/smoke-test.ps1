<#
.SYNOPSIS
  Installs, upgrades, downgrades, repairs and removes the Palisade package
  on this machine, checking each step (#22). CI runs it on the hosted
  Windows runners; see docs/packaging.md.

.DESCRIPTION
  It installs a Windows service and writes to HKLM, so it needs an
  elevated shell, and it is meant for a throwaway machine. `cargo xtask ci`
  never runs it.

  -Current and -Next are `cargo xtask dist --msi` output folders, the second
  built with --bump-patch. -Arch is x64 or arm64.
#>
param(
  [Parameter(Mandatory)] [string] $Current,
  [Parameter(Mandatory)] [string] $Next,
  [Parameter(Mandatory)] [ValidateSet('x64', 'arm64')] [string] $Arch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Service = 'PalisadeAgent'
$InstallDir = Join-Path $env:ProgramFiles 'Palisade'
$DataDir = Join-Path $env:ProgramData 'Palisade'
$SettingsKey = 'HKLM:\SOFTWARE\Palisade\Agent'
$Logs = Join-Path ([IO.Path]::GetTempPath()) 'palisade-smoke'
New-Item -ItemType Directory -Force $Logs | Out-Null
# A value that must never reach a log. Random per run, so a match cannot
# be a coincidence from an earlier run.
$Canary = 'canary-' + [guid]::NewGuid().ToString('N')
$script:Failures = 0

function Check([bool] $Ok, [string] $What) {
  if ($Ok) {
    Write-Host "ok:   $What"
  } else {
    Write-Host "::error title=Package smoke test::$What"
    $script:Failures++
  }
}

function Package([string] $Dir) {
  $found = @(Get-ChildItem -Path $Dir -Filter "Palisade-*-$Arch.msi")
  if ($found.Count -ne 1) { throw "expected one Palisade-*-$Arch.msi in $Dir, found $($found.Count)" }
  $found[0].FullName
}

function Msiexec([string] $Name, [string[]] $Arguments) {
  $log = Join-Path $Logs "$Name.log"
  $all = $Arguments + @('/qn', '/norestart', '/l*vx', "`"$log`"")
  $p = Start-Process -FilePath msiexec.exe -ArgumentList $all -Wait -PassThru
  Write-Host "msiexec $Name -> $($p.ExitCode)"
  [pscustomobject]@{ Code = $p.ExitCode; Log = $log }
}

# Prints the part of a log around the first failed action, with the
# canary redacted, so a failure in CI can be diagnosed from the job log.
function ShowFailure([string] $Log) {
  $lines = @(Get-Content -Path $Log)
  $at = 0
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'Return value 3') { $at = $i; break }
  }
  $from = [Math]::Max(0, $at - 60)
  $to = [Math]::Min($lines.Count - 1, $at + 5)
  Write-Host "--- $Log, lines $from to $to ---"
  foreach ($line in $lines[$from..$to]) { Write-Host ($line.Replace($Canary, '<canary>')) }
  Write-Host '--- end ---'
}

# Stops the run: later checks depend on this one.
function Require([bool] $Ok, [string] $What, $Result) {
  Check $Ok $What
  if (-not $Ok) {
    if ($null -ne $Result) { ShowFailure $Result.Log }
    Write-Host "$($script:Failures) check(s) failed. Logs: $Logs"
    exit 1
  }
}

# Reads the first column of a query on a package, through the Windows
# Installer API. A table the package does not have has no rows.
function MsiQuery([string] $Msi, [string] $Sql) {
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Msi, 0))
  if ($Sql -match 'FROM `(\w+)`') {
    $state = $db.GetType().InvokeMember('TablePersistent', 'GetProperty', $null, $db, @($Matches[1]))
    # 1 = the table exists (MSICONDITION_TRUE).
    if ($state -ne 1) {
      [Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null
      return , @()
    }
  }
  $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($Sql))
  $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
  $rows = @()
  while ($true) {
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    if ($null -eq $record) { break }
    $rows += $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
  }
  $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
  [Runtime.InteropServices.Marshal]::ReleaseComObject($db) | Out-Null
  , $rows
}

function MsiProperty([string] $Msi, [string] $Name) {
  $rows = MsiQuery $Msi "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$Name'"
  if ($rows.Count -eq 0) { $null } else { $rows[0] }
}

function Installed([string] $UpgradeCode) {
  # Products registered under this upgrade code, as product codes. Always
  # an array, even when empty.
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $list = $installer.GetType().InvokeMember('RelatedProducts', 'GetProperty', $null, $installer, @($UpgradeCode))
  $codes = @()
  foreach ($code in $list) { $codes += [string]$code }
  , $codes
}

# A registry value, or $null when it or its key does not exist.
function RegValue([string] $Key, [string] $Name) {
  $item = Get-Item -Path $Key -ErrorAction SilentlyContinue
  if ($null -eq $item) { return $null }
  $item.GetValue($Name, $null)
}

function Setting([string] $Name) { RegValue $SettingsKey $Name }

# The sign-in (Run) key, read from the package's Registry table, so the
# OS-defined path is written in one place only (xtask/src/dist/os_ids.rs).
$script:RunKey = $null
function RunValue { RegValue "HKLM:\$script:RunKey" 'Palisade' }

function MachinePath { [Environment]::GetEnvironmentVariable('Path', 'Machine') }

function PeMachine([string] $File) {
  $bytes = [IO.File]::ReadAllBytes($File)
  $pe = [BitConverter]::ToInt32($bytes, 0x3c)
  [BitConverter]::ToUInt16($bytes, $pe + 4)
}

function NoCanary([string] $Log, [string] $What) {
  $text = Get-Content -Raw -Path $Log
  Check (-not $text.Contains($Canary)) "$What`: the enrolment token is not in the verbose log"
}

$CurrentMsi = Package $Current
$NextMsi = Package $Next
$UpgradeCode = MsiProperty $CurrentMsi 'UpgradeCode'
$OldVersion = MsiProperty $CurrentMsi 'ProductVersion'
$NewVersion = MsiProperty $NextMsi 'ProductVersion'
$script:RunKey = @(MsiQuery $CurrentMsi "SELECT ``Key`` FROM ``Registry`` WHERE ``Name`` = 'Palisade'")[0]
Write-Host "package $CurrentMsi ($OldVersion), upgrade $NextMsi ($NewVersion), upgrade code $UpgradeCode"

# --- The package itself --------------------------------------------------
Check ((MsiProperty $NextMsi 'UpgradeCode') -eq $UpgradeCode) 'both packages share the upgrade code'
Check ((MsiProperty $NextMsi 'ProductCode') -ne (MsiProperty $CurrentMsi 'ProductCode')) 'each build has its own product code'
Check ([version]$NewVersion -gt [version]$OldVersion) 'the upgrade package has the higher version'
$hidden = (MsiProperty $CurrentMsi 'MsiHiddenProperties') -split ';'
Check ($hidden -contains 'ENROLL_TOKEN') 'ENROLL_TOKEN is in MsiHiddenProperties'
Check ($hidden -contains 'ALLOW_UNINSTALL') 'ALLOW_UNINSTALL is in MsiHiddenProperties'
$files = MsiQuery $CurrentMsi 'SELECT `FileName` FROM `File`'
# File names are stored as `short|long`.
Check (@($files | Where-Object { $_ -match '\.pdb$' }).Count -eq 0) 'no PDB is packaged'
Check ($files.Count -eq 3) "exactly three files are packaged ($($files -join ', '))"
$ca = MsiQuery $CurrentMsi 'SELECT `Action` FROM `CustomAction`'
$types = MsiQuery $CurrentMsi 'SELECT `Type` FROM `CustomAction` WHERE `Action` <> ''ConfigureRecovery'''
# Type 51 sets a property and type 19 shows an error and stops; every custom
# action but the recovery one must be one of those.
Check (@($types | Where-Object { ([int]$_ -band 0x3f) -notin 51, 19 }).Count -eq 0) "custom actions only set properties or stop with an error ($($ca -join ', '))"
$uiSearch = MsiQuery $CurrentMsi "SELECT ``Action`` FROM ``InstallUISequence`` WHERE ``Action`` = 'AppSearch'"
Check ($uiSearch.Count -eq 0) 'the unelevated user-interface sequence does not read the protected settings key'
# Every property-setting custom action (type 51) applies a kept setting or
# the MODE default, so none may run in the unelevated UI sequence.
$kept = MsiQuery $CurrentMsi 'SELECT `Action` FROM `CustomAction` WHERE `Type` = 51'
Check ($kept.Count -ge 8) "the kept settings and MODE are set by custom actions ($($kept -join ', '))"
$uiActions = MsiQuery $CurrentMsi 'SELECT `Action` FROM `InstallUISequence`'
$uiSet = @($uiActions | Where-Object { $kept -contains $_ })
Check ($uiSet.Count -eq 0) "kept settings and MODE are applied in the elevated execute sequence only ($($uiSet -join ', '))"
$exec = MsiQuery $CurrentMsi 'SELECT `Action` FROM `InstallExecuteSequence`'
Check (@($kept | Where-Object { $exec -notcontains $_ }).Count -eq 0) 'every kept setting is applied in the execute sequence'
$schedule = MsiQuery $CurrentMsi "SELECT ``Sequence`` FROM ``InstallExecuteSequence`` WHERE ``Action`` = 'RemoveExistingProducts'"
$initialize = MsiQuery $CurrentMsi "SELECT ``Sequence`` FROM ``InstallExecuteSequence`` WHERE ``Action`` = 'InstallInitialize'"
Check ([int]$schedule[0] -gt [int]$initialize[0] -and [int]$schedule[0] -lt [int]$initialize[0] + 10) 'the old version is removed inside the install transaction'
$recovery = MsiQuery $CurrentMsi 'SELECT `Target` FROM `CustomAction` WHERE `Action` = ''ConfigureRecovery'''
Check ($recovery.Count -eq 1 -and $recovery[0].StartsWith('"[System64Folder]sc.exe" failure PalisadeAgent ')) "the one other custom action runs the system service-control tool ($recovery)"
$binaries = MsiQuery $CurrentMsi 'SELECT `Name` FROM `Binary`'
Check ($binaries.Count -eq 0) "no binary (custom action code) is embedded ($($binaries -join ', '))"

# --- Refused before anything is installed ---------------------------------
$r = Msiexec 'bad-mode' @('/i', "`"$CurrentMsi`"", 'MODE=strict')
Check ($r.Code -eq 1603) 'an unknown MODE is refused'
$r = Msiexec 'bad-url' @('/i', "`"$CurrentMsi`"", 'SERVER_URL=http://palisade.invalid')
Check ($r.Code -eq 1603) 'a non-HTTPS SERVER_URL is refused'
Check ((Installed $UpgradeCode).Count -eq 0) 'nothing is installed after a refused install'

# --- Install --------------------------------------------------------------
$r = Msiexec 'install' @('/i', "`"$CurrentMsi`"", 'SERVER_URL=https://palisade.invalid/', "ENROLL_TOKEN=$Canary", 'GROUP_KEY=smoke', 'PROXY=system')
Require ($r.Code -eq 0) 'silent install succeeds' $r
NoCanary $r.Log 'install'
Check ((Get-Content -Raw $r.Log) -match 'ENROLL_TOKEN = \*+') 'the verbose log shows the token masked'

$svc = Get-CimInstance Win32_Service -Filter "Name = '$Service'"
Require ($null -ne $svc) 'the service is registered' $null
Check ($svc.State -eq 'Running') "the service is running ($($svc.State))"
Check ($svc.StartMode -eq 'Auto') 'the service starts automatically'
Check ($svc.DelayedAutoStart) 'the service uses delayed start'
Check ($svc.StartName -eq 'LocalSystem') "the service runs as LocalSystem ($($svc.StartName))"
Check ($svc.PathName -like "*palisade-agent.exe*--service*") "the service command line ($($svc.PathName))"
Check ($svc.DisplayName -eq 'Palisade Agent' -and $svc.Description -like 'Palisade*') 'display name and description'
$failure = (sc.exe qfailure $Service) -join "`n"
Check ($failure -match 'RESTART -- Delay = 0 milliseconds' -and $failure -match 'RESTART -- Delay = 5000 milliseconds' -and $failure -match 'RESTART -- Delay = 30000 milliseconds') 'recovery restarts after 0, 5 and 30 seconds'
Check ($failure -match 'RESET_PERIOD \(in seconds\)\s*:\s*86400') 'the failure count resets after a day'
Check (((sc.exe qsidtype $Service) -join "`n") -match 'UNRESTRICTED') 'the service SID type is unrestricted'

foreach ($name in 'palisade-agent.exe', 'palisade-tray.exe', 'pal.exe') {
  $file = Join-Path $InstallDir $name
  Check (Test-Path $file) "$name is installed"
  $info = (Get-Item $file).VersionInfo
  Check ($info.CompanyName -eq 'Palisade Project' -and $info.ProductName -eq 'Palisade') "$name names the company and product"
  Check ($info.OriginalFilename -eq $name) "$name OriginalFilename"
  Check ($info.FileVersion -eq "$OldVersion.0") "$name FileVersion $($info.FileVersion)"
  Check ($info.ProductVersion -like "*+g*") "$name ProductVersion has the commit ($($info.ProductVersion))"
  $machine = PeMachine $file
  $want = if ($Arch -eq 'arm64') { 0xAA64 } else { 0x8664 }
  Check ($machine -eq $want) ("$name is built for $Arch (machine 0x{0:X4})" -f $machine)
}
Check (@(Get-ChildItem $InstallDir -Filter '*.pdb').Count -eq 0) 'no PDB is installed'
$version = & (Join-Path $InstallDir 'palisade-agent.exe') --version
Check ($LASTEXITCODE -eq 0 -and $version -like 'palisade-agent *') "the agent runs natively ($version)"

function CheckDataAcl([string] $Dir) {
  $acl = Get-Acl $Dir
  Check ($acl.AreAccessRulesProtected) "$Dir does not inherit permissions"
  Check ($acl.Owner -eq 'NT AUTHORITY\SYSTEM') "$Dir is owned by SYSTEM ($($acl.Owner))"
  $rules = @($acl.Access | ForEach-Object { "$($_.AccessControlType):$($_.IdentityReference)=$($_.FileSystemRights)" } | Sort-Object -Unique)
  Check (($rules -join ',') -eq 'Allow:BUILTIN\Administrators=FullControl,Allow:NT AUTHORITY\SYSTEM=FullControl') "$Dir is SYSTEM and Administrators only ($($rules -join ', '))"
}
CheckDataAcl $DataDir
foreach ($sub in 'policy', 'queue', 'logs') {
  $dir = Join-Path $DataDir $sub
  Check (Test-Path $dir) "$dir exists"
  CheckDataAcl $dir
}
$keyAcl = Get-Acl $SettingsKey
$keyRules = @($keyAcl.Access | ForEach-Object { "$($_.AccessControlType):$($_.IdentityReference)" } | Sort-Object -Unique)
Check ($keyAcl.AreAccessRulesProtected -and ($keyRules -join ',') -eq 'Allow:BUILTIN\Administrators,Allow:NT AUTHORITY\SYSTEM') "the settings key is SYSTEM and Administrators only ($($keyRules -join ', '))"
Check ((Setting 'ServerUrl') -eq 'https://palisade.invalid/') 'SERVER_URL is stored'
Check ($null -eq (Setting 'EnrollToken')) 'ENROLL_TOKEN is not written to the registry (#57 stores it protected)'
Check ((Setting 'GroupKey') -eq 'smoke') 'GROUP_KEY is stored'
Check ((Setting 'Proxy') -eq 'system') 'PROXY is stored'
Check ((Setting 'Mode') -eq 'audit') 'MODE defaults to audit'
Check ($null -eq (Setting 'SkipEnroll')) 'SKIP_ENROLL is not set'
Check ((RunValue) -eq "`"$InstallDir\palisade-tray.exe`"") 'the notifier starts at sign-in'
Check (-not ((MachinePath) -split ';' | Where-Object { $_.TrimEnd('\') -eq $InstallDir })) 'the install folder is not on PATH by default'

# State the agent would have written, which no install step may remove.
$state = Join-Path $DataDir 'policy\smoke-state.txt'
Set-Content -Path $state -Value 'kept across upgrades'

# --- Upgrade --------------------------------------------------------------
$r = Msiexec 'upgrade' @('/i', "`"$NextMsi`"")
Require ($r.Code -eq 0) 'the upgrade succeeds' $r
NoCanary $r.Log 'upgrade'
$products = Installed $UpgradeCode
Check ($products.Count -eq 1) "one product is installed after the upgrade ($($products.Count))"
$installer = New-Object -ComObject WindowsInstaller.Installer
$installedVersion = $installer.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installer, @($products[0], 'VersionString'))
Check ($installedVersion -eq $NewVersion) "the upgraded version is installed ($installedVersion)"
Check ((Get-Content $state) -eq 'kept across upgrades') 'ProgramData state survives the upgrade'
Check ((Setting 'ServerUrl') -eq 'https://palisade.invalid/') 'the upgrade keeps SERVER_URL'
Check ((Setting 'GroupKey') -eq 'smoke' -and (Setting 'Proxy') -eq 'system' -and (Setting 'Mode') -eq 'audit') 'the upgrade keeps GROUP_KEY, PROXY and MODE'
Check ((Get-Service $Service).Status -eq 'Running') 'the service runs after the upgrade'
Check ((Get-Item (Join-Path $InstallDir 'pal.exe')).VersionInfo.FileVersion -eq "$NewVersion.0") 'the upgraded binaries are in place'

# --- Downgrade is refused -------------------------------------------------
$r = Msiexec 'downgrade' @('/i', "`"$CurrentMsi`"")
Check ($r.Code -eq 1603) "a downgrade is refused ($($r.Code))"
Check ((Get-Content -Raw $r.Log) -match 'A newer version of Palisade is already installed') 'the downgrade log explains why'
Check ((Installed $UpgradeCode).Count -eq 1 -and (Get-Service $Service).Status -eq 'Running') 'the refused downgrade changes nothing'

# --- Repair ---------------------------------------------------------------
Remove-Item (Join-Path $InstallDir 'pal.exe')
$r = Msiexec 'repair' @('/fa', "`"$NextMsi`"")
Require ($r.Code -eq 0) 'repair succeeds' $r
Check (Test-Path (Join-Path $InstallDir 'pal.exe')) 'repair restores a deleted binary'
Check ((Get-Content $state) -eq 'kept across upgrades') 'repair keeps ProgramData state'

# --- Remove ---------------------------------------------------------------
$r = Msiexec 'uninstall' @('/x', "`"$NextMsi`"")
Require ($r.Code -eq 0) 'silent uninstall succeeds' $r
Check ($null -eq (Get-Service $Service -ErrorAction SilentlyContinue)) 'the service is removed'
Check (-not (Test-Path $InstallDir)) 'the install folder is removed'
Check (-not (Test-Path $SettingsKey)) 'the settings key is removed'
Check ($null -eq (RunValue)) 'the sign-in entry is removed'
Check ((Installed $UpgradeCode).Count -eq 0) 'no product is registered'

# --- A folder planted before the install ---------------------------------
# What a standard user could do: create a data folder with an ACL that
# gives Users full control and does not inherit.
New-Item -ItemType Directory -Force (Join-Path $DataDir 'queue') | Out-Null
$planted = New-Object Security.AccessControl.DirectorySecurity
$planted.SetAccessRuleProtection($true, $false)
$planted.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Users', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
$planted.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
Set-Acl -Path (Join-Path $DataDir 'queue') -AclObject $planted

# --- The other switches ---------------------------------------------------
$r = Msiexec 'install-offline' @('/i', "`"$CurrentMsi`"", 'SKIP_ENROLL=1', 'NO_TRAY=1', 'ADD_TO_PATH=1', 'MODE=enforce')
Require ($r.Code -eq 0) 'offline install succeeds' $r
Check ((Setting 'SkipEnroll') -eq '1' -and $null -eq (Setting 'ServerUrl')) 'SKIP_ENROLL is stored, with no server'
CheckDataAcl (Join-Path $DataDir 'queue')
Check ((Setting 'Mode') -eq 'enforce') 'MODE is stored as given'
Check ($null -eq (RunValue)) 'NO_TRAY=1 leaves out the sign-in entry'
Check ([bool]((MachinePath) -split ';' | Where-Object { $_.TrimEnd('\') -eq $InstallDir })) 'ADD_TO_PATH=1 puts the install folder on PATH'
$r = Msiexec 'upgrade-offline' @('/i', "`"$NextMsi`"")
Require ($r.Code -eq 0) 'upgrading the offline install succeeds' $r
Check ((Setting 'SkipEnroll') -eq '1' -and (Setting 'Mode') -eq 'enforce' -and $null -eq (RunValue)) 'the upgrade keeps SKIP_ENROLL, MODE and NO_TRAY'
# A repair with the basic user interface. Windows Installer runs the
# user-interface sequence only for reduced and full UI, which need a
# person; the table checks above cover that sequence. This repair checks
# that a second elevated pass keeps the settings.
$all = @('/fa', "`"$NextMsi`"", '/qb!-', '/norestart', '/l*vx', "`"$(Join-Path $Logs 'repair-basic-ui.log')`"")
$p = Start-Process -FilePath msiexec.exe -ArgumentList $all -Wait -PassThru
Check ($p.ExitCode -eq 0) "a repair with the basic user interface succeeds ($($p.ExitCode))"
Check ((Setting 'Mode') -eq 'enforce' -and (Setting 'SkipEnroll') -eq '1') 'a basic-UI repair keeps MODE and SKIP_ENROLL'
# A damaged stored MODE must not block removal.
Set-ItemProperty -Path $SettingsKey -Name Mode -Value 'damaged'
Check ([bool]((MachinePath) -split ';' | Where-Object { $_.TrimEnd('\') -eq $InstallDir })) 'the upgrade keeps ADD_TO_PATH'
$r = Msiexec 'uninstall-offline' @('/x', "`"$NextMsi`"")
Require ($r.Code -eq 0) 'removing the offline install succeeds' $r
Check (-not ((MachinePath) -split ';' | Where-Object { $_.TrimEnd('\') -eq $InstallDir })) 'removal takes the install folder off PATH'

# --- The Application log --------------------------------------------------
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1033, 1034 } -MaxEvents 200 |
  Where-Object { $_.Message -like '*Palisade*' })
Check (@($events | Where-Object Id -eq 1033).Count -ge 1) 'installs are recorded in the Application log'
Check (@($events | Where-Object Id -eq 1034).Count -ge 1) 'removals are recorded in the Application log'

foreach ($log in Get-ChildItem $Logs -Filter '*.log') {
  NoCanary $log.FullName "log $($log.Name)"
}

if ($script:Failures -gt 0) {
  Write-Host "$($script:Failures) check(s) failed. Logs: $Logs"
  exit 1
}
Write-Host 'All package checks passed.'
