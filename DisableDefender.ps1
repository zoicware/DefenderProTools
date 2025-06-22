#DISABLE DEFENDER SCRIPT BY ZOIC


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit	
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

  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
  #get bin path to revert later
  $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'"
  $DefaultBinPath = $service.PathName
  #convert command to base64 to avoid errors with spaces
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $base64Command = [Convert]::ToBase64String($bytes)
  #change bin to command
  sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
  #run the command
  sc.exe start TrustedInstaller | Out-Null
  #set bin back to default
  sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue

}


#refactor of https://github.com/AveYo/LeanAndMean/blob/main/disableDefender.ps1
$code = @'
function defeatMsMpEng {
    
$key = 'Registry::HKU\S-1-5-21-*\Volatile Environment'
    
# Define types and modules
$I = [int32]
$M = $I.module.GetType("System.Runtime.InteropServices.Marshal")
$P = $I.module.GetType("System.IntPtr")
$S = [string]
$D = @()
$DM = [AppDomain]::CurrentDomain.DefineDynamicAssembly(1, 1).DefineDynamicModule(1)
$U = [uintptr]
$Z = [uintptr]::Size

# Define dynamic types
0..5 | ForEach-Object { $D += $DM.DefineType("AveYo_$_", 1179913, [ValueType]) }
$D += $U
4..6 | ForEach-Object { $D += $D[$_].MakeByRefType() }

# Define PInvoke methods
$F = @(
    'kernel', 'CreateProcess', ($S, $S, $I, $I, $I, $I, $I, $S, $D[7], $D[8]),
    'advapi', 'RegOpenKeyEx', ($U, $S, $I, $I, $D[9]),
    'advapi', 'RegSetValueEx', ($U, $S, $I, $I, [byte[]], $I),
    'advapi', 'RegFlushKey', ($U),
    'advapi', 'RegCloseKey', ($U)
)
0..4 | ForEach-Object { $9 = $D[0].DefinePInvokeMethod($F[3 * $_ + 1], $F[3 * $_] + "32", 8214, 1, $S, $F[3 * $_ + 2], 1, 4) }

# Define fields
$DF = @(
    ($P, $I, $P),
    ($I, $I, $I, $I, $P, $D[1]),
    ($I, $S, $S, $S, $I, $I, $I, $I, $I, $I, $I, $I, [int16], [int16], $P, $P, $P, $P),
    ($D[3], $P),
    ($P, $P, $I, $I)
)
1..5 | ForEach-Object { $k = $_; $n = 1; $DF[$_ - 1] | ForEach-Object { $9 = $D[$k].DefineField("f" + $n++, $_, 6) } }

# Create types
$T = @()
0..5 | ForEach-Object { $T += $D[$_].CreateType() }

# Create instances
0..5 | ForEach-Object { New-Variable -Name "A$_" -Value ([Activator]::CreateInstance($T[$_])) -Force }

# Define functions
function F ($1, $2) { $T[0].GetMethod($1).Invoke(0, $2) }
function M ($1, $2, $3) { $M.GetMethod($1, [type[]]$2).Invoke(0, $3) }

# Allocate memory
$H = @()
$Z, (4 * $Z + 16) | ForEach-Object { $H += M "AllocHGlobal" $I $_ }

# Check user and start service if necessary
if ([environment]::username -ne "system") {
    $TI = "TrustedInstaller"
    Start-Service $TI -ErrorAction SilentlyContinue
    $As = Get-Process -Name $TI -ErrorAction SilentlyContinue
    M "WriteIntPtr" ($P, $P) ($H[0], $As.Handle)
    $A1.f1 = 131072
    $A1.f2 = $Z
    $A1.f3 = $H[0]
    $A2.f1 = 1
    $A2.f2 = 1
    $A2.f3 = 1
    $A2.f4 = 1
    $A2.f6 = $A1
    $A3.f1 = 10 * $Z + 32
    $A4.f1 = $A3
    $A4.f2 = $H[1]
    M "StructureToPtr" ($D[2], $P, [boolean]) (($A2 -as $D[2]), $A4.f2, $false)
    $R = @($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
    F 'CreateProcess' $R
    return
}

# Clear environment variable
$env:R = ''
Remove-ItemProperty -Path $key -Name $id -Force -ErrorAction SilentlyContinue

# Set privileges
$e = [diagnostics.process].GetMember('SetPrivilege', 42)[0]
'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege' | ForEach-Object { $e.Invoke($null, @("$_", 2)) }

# Define function to set registry DWORD values
function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE = 4, $REG_ACCESS = 2, $REG_OPTION = 0) {
    $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]))
    F "RegOpenKeyEx" $rok
    $rsv = $rok[4]
    $values | ForEach-Object { $i = 0 } { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
    F "RegFlushKey" @($rsv)
    F "RegCloseKey" @($rsv)
    $rok = $null
    $rsv = $null
}


 
    $disable = 1
    $disable_rev = 0
    $disable_SMARTSCREENFILTER = 1
    #stop security center and defender commandline exe
    stop-service 'wscsvc' -force -ErrorAction SilentlyContinue *>$null
    Stop-Process -name 'OFFmeansOFF', 'MpCmdRun' -force -ErrorAction SilentlyContinue
 
    $HKLM = [uintptr][uint32]2147483650 
    $VALUES = 'ServiceKeepAlive', 'PreviousRunningMode', 'IsServiceRunning', 'DisableAntiSpyware', 'DisableAntiVirus', 'PassiveMode'
    $DWORDS = 0, 0, 0, $disable, $disable, $disable
    #apply registry values (not all will apply)
    RegSetDwords $HKLM 'SOFTWARE\Policies\Microsoft\Windows Defender' $VALUES $DWORDS 
    RegSetDwords $HKLM 'SOFTWARE\Microsoft\Windows Defender' $VALUES $DWORDS
    [GC]::Collect() 
    Start-Sleep 1
    #run defender command line to disable msmpeng service
    Push-Location "$env:programfiles\Windows Defender"
    $mpcmdrun = ('OFFmeansOFF.exe', 'MpCmdRun.exe')[(test-path 'MpCmdRun.exe')]
    Start-Process -wait $mpcmdrun -args '-DisableService -HighPriority'
    #wait for service to close before continuing
    $wait = 14
    while ((get-process -name 'MsMpEng' -ea 0) -and $wait -gt 0) { 
        $wait--
        Start-Sleep 1
    }
 
    #rename defender commandline exe
    $location = split-path $(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' ImagePath -ErrorAction SilentlyContinue).ImagePath.Trim('"')
    Push-Location $location
    Rename-Item MpCmdRun.exe -NewName 'OFFmeansOFF.exe' -force -ErrorAction SilentlyContinue
 
    #cleanup scan history
    Remove-Item "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ErrorAction SilentlyContinue

    #apply keys that are blocked when msmpeng is running
    RegSetDwords $HKLM 'SOFTWARE\Policies\Microsoft\Windows Defender' $VALUES $DWORDS 
    RegSetDwords $HKLM 'SOFTWARE\Microsoft\Windows Defender' $VALUES $DWORDS

    #disable smartscreen
    if ($disable_SMARTSCREENFILTER) {
        Set-ItemProperty 'HKLM:\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ErrorAction SilentlyContinue
        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' -force -ErrorAction SilentlyContinue 
        Get-Item Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 | ForEach-Object {
            Set-ItemProperty "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $disable_rev -type Dword -force -ErrorAction SilentlyContinue
            Set-ItemProperty "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'PreventOverride' $disable_rev -type Dword -force -ErrorAction SilentlyContinue
            New-Item "$($_.PSPath)\Edge\SmartScreenEnabled" -ErrorAction SilentlyContinue *>$null
            Set-ItemProperty "$($_.PSPath)\Edge\SmartScreenEnabled" '(Default)' $disable_rev -ErrorAction SilentlyContinue
        }
        if ($disable_rev -eq 0) { 
            Stop-Process -name smartscreen -force -ErrorAction SilentlyContinue
        }
    }

}
defeatMsMpEng
'@
$script = New-Item "$env:TEMP\DefeatDefend.ps1" -Value $code -Force
$run = "Start-Process powershell.exe -ArgumentList `"-executionpolicy bypass -File $($script.FullName) -Verb runas`""


Write-Host 'Running Initial Stage...'

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


#attempt to kill defender processes and silence notifications from sec center
$command = 'Stop-Process MpDefenderCoreService -Force; Stop-Process smartscreen -Force; Stop-Process SecurityHealthService -Force; Stop-Process SecurityHealthSystray -Force; Stop-Service -Name wscsvc -Force; Stop-Service -Name Sense -Force'
Run-Trusted -command $command
Run-Trusted -command $run

#disable tasks
$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
  if ($task.Taskname -like 'Windows Defender*') {
    Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
  }
}


Write-Host 'Cleaning Up...'
Remove-Item "$env:TEMP\disableReg" -Recurse -Force
Remove-Item "$env:TEMP\DefeatDefend.ps1" -Force


[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?', 'zoicware', 'YesNo', 'Question')

switch ($msgBoxInput) {

  'Yes' {
  
    Restart-Computer
  }

  'No' {
  }

}


