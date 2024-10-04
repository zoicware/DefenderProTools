If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

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

$file1 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=-
"ServiceKeepAlive"=-
"AllowFastServiceStartup"=-
"DisableLocalAdminMerge"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=-
'@
$file2 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"PUAProtection"=-
"DisableAntiSpyware"=-
"RandomizeScheduleTaskTimes"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess]
"value"=dword:00000001

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager]
"DisableScanningNetworkFiles"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
'@
$file3 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]
"FirstRunDisabled"=-
"AntiVirusOverride"=-
"FirewallOverride"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]
"Enabled"=-
'@
$file4 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,\
  00,61,00,74,00,61,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,\
  74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,\
  00,65,00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,\
  72,00,6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,\
  00,2e,00,37,00,2d,00,30,00,5c,00,58,00,38,00,36,00,5c,00,4d,00,70,00,4f,00,\
  61,00,76,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts]
@="Scanned Hosting Applications"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\shdocvw]
@="IAttachmentExecute"
"Enable"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\urlmon]
@="ActiveX controls"
"Enable"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,4d,00,70,00,4f,00,61,00,76,00,2e,00,64,00,6c,00,\
  6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]
@="Windows Defender IAmsiUacProvider implementation"
"AppId"="{2781761E-28E2-4109-99FE-B9D127C57AFE}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]
@="Defender CSP"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,\
  43,00,53,00,50,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Free"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]
@="InfectionState WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]
@="Defender Pua Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]
@="Defender Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"


[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]
@="Status WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]
@="Defender Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]
@="Microsoft Windows Defender"
"AppID"="{A79DB36D-6218-48e6-9EC9-DCBA9A39BF0F}"
"LocalizedString"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,33,00,30,00,30,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\Elevation]
"Enabled"=dword:00000001
"IconReference"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,31,00,30,00,33,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\InprocServer32]
@="C:\\Program Files\\Windows Defender\\MsMpCom.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]
@="Windows Defender WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,50,00,72,00,6f,00,74,00,65,00,63,00,74,00,69,00,\
  6f,00,6e,00,4d,00,61,00,6e,00,61,00,67,00,65,00,6d,00,65,00,6e,00,74,00,2e,\
  00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]
@="AMMonitoring WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,41,00,4d,00,4d,00,6f,00,6e,\
  00,69,00,74,00,6f,00,72,00,69,00,6e,00,67,00,50,00,72,00,6f,00,76,00,69,00,\
  64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]
@="Defender SSO"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}\InProcServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthSSO.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]
@="Defender Pua Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,\
  00,61,00,74,00,61,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,\
  74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,\
  00,65,00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,\
  72,00,6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,\
  00,2e,00,37,00,2d,00,30,00,5c,00,58,00,38,00,36,00,5c,00,4d,00,70,00,4f,00,\
  61,00,76,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts]
@="Scanned Hosting Applications"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\shdocvw]
@="IAttachmentExecute"
"Enable"=dword:00000001

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\urlmon]
@="ActiveX controls"
"Enable"=dword:00000001

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,4d,00,70,00,4f,00,61,00,76,00,2e,00,64,00,6c,00,\
  6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]
@="Windows Defender IAmsiUacProvider implementation"
"AppId"="{2781761E-28E2-4109-99FE-B9D127C57AFE}"

[HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]
@="Defender CSP"

[HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,\
  43,00,53,00,50,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Free"

[HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]
@="InfectionState WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]
@="Defender Pua Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]
@="Defender Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]
@="Status WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]
@="Defender Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]
@="Microsoft Windows Defender"
"AppID"="{A79DB36D-6218-48e6-9EC9-DCBA9A39BF0F}"
"LocalizedString"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,33,00,30,00,30,00,00,00

[HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\Elevation]
"Enabled"=dword:00000001
"IconReference"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,31,00,30,00,33,00,00,00

[HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\InprocServer32]
@="C:\\Program Files\\Windows Defender\\MsMpCom.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]
@="Windows Defender WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,50,00,72,00,6f,00,74,00,65,00,63,00,74,00,69,00,\
  6f,00,6e,00,4d,00,61,00,6e,00,61,00,67,00,65,00,6d,00,65,00,6e,00,74,00,2e,\
  00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]
@="AMMonitoring WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,41,00,4d,00,4d,00,6f,00,6e,\
  00,69,00,74,00,6f,00,72,00,69,00,6e,00,67,00,50,00,72,00,6f,00,76,00,69,00,\
  64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]
@="Defender SSO"

[HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}\InProcServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthSSO.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]
@="Defender Pua Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger]
"Age"=dword:00000001
"BufferSize"=dword:00000040
"ClockType"=dword:00000002
"EnableSecurityProvider"=dword:00000001
"FlushTimer"=dword:00000001
"GUID"="{6B4012D0-22B6-464D-A553-20E9618403A1}"
"LogFileMode"=dword:180001c0
"MaximumBuffers"=dword:00000010
"MinimumBuffers"=dword:00000000
"Start"=dword:00000001
"Status"=dword:00000000
'@
$file5 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger]
"Age"=dword:00000001
"BufferSize"=dword:00000040
"ClockType"=dword:00000002
"FlushTimer"=dword:00000001
"GUID"="{6B4012D0-22B6-464D-A553-20E9618403A2}"
"LogFileMode"=dword:18000180
"MaximumBuffers"=dword:00000010
"MinimumBuffers"=dword:00000000
"Start"=dword:00000001
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{0063715b-eeda-4007-9429-ad526f62696e}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):00,00,70,00,00,00,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{099614a5-5dd7-4788-8bc9-e29f43db28fc}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):01,00,00,00,00,00,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:17

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1edeee53-0afe-4609-b846-d8c0b2075b1f}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1edeee53-0afe-4609-b846-d8c0b2075b1f}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:0b,00,16,00,e5,16,17,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{54849625-5478-4994-a5ba-3e3b0328c30d}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{54849625-5478-4994-a5ba-3e3b0328c30d}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:10,12,11,12,5a,12,5e,12,73,12,74,12,82,12,00,15,03,15,04,15,05,\
  15,06,15,70,12

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{85a62a0d-7e17-485f-9d4f-749a287193a6}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{8c416c79-d49b-4f01-a467-e56d3aa8234c}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):00,04,00,00,00,0c,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:10,00,fe,ff

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{c688cf83-9945-5ff6-0e1e-1ff1f8a2ec9a}]
"Enabled"=dword:00000001
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}]
"Enabled"=dword:00000001
"EnableLevel"=dword:0000001f
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:01,00,02,00,03,00,04,00,07,00,08,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:03,00,fe,ff

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):55,55,fa,dc,14,01,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:01,00,02,00,03,00,04,00,05,00,06,00,07,00,08,00,09,00,0a,00,0b,\
  00,0c,00,0d,00,0e,00,0f,00,10,00,11,00,12,00,13,00,14,00,15,00,16,00,17,00,\
  18,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:4e,04,68,00
'@
$file6 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore]
"Description"="@%SystemRoot%\\System32\\Drivers\\msseccore.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\msseccore.sys,-1001"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,6d,00,73,00,73,00,65,00,63,00,63,\
  00,6f,00,72,00,65,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000000
"Type"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
"DelayedAutoStart"=dword:00000001
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%SystemRoot%\\System32\\wscsvc.dll,-201"
"DisplayName"="@%SystemRoot%\\System32\\wscsvc.dll,-200"
"ErrorControl"=dword:00000001
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,c0,d4,01,00,01,00,00,00,e0,93,04,00,00,00,00,00,00,00,00,00
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,4c,00,6f,00,63,00,61,00,6c,00,53,00,65,00,72,00,76,00,69,00,63,\
  00,65,00,4e,00,65,00,74,00,77,00,6f,00,72,00,6b,00,52,00,65,00,73,00,74,00,\
  72,00,69,00,63,00,74,00,65,00,64,00,20,00,2d,00,70,00,00,00
"LaunchProtected"=dword:00000002
"ObjectName"="NT AUTHORITY\\LocalService"
"RequiredPrivileges"=hex(7):53,00,65,00,43,00,68,00,61,00,6e,00,67,00,65,00,4e,\
  00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,\
  67,00,65,00,00,00,53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,00,6e,\
  00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,\
  00,00,00,00
"ServiceSidType"=dword:00000001
"Start"=dword:00000002
"Type"=dword:00000020

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc\Parameters]
"ServiceDll"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  77,00,73,00,63,00,73,00,76,00,63,00,2e,00,64,00,6c,00,6c,00,00,00
"ServiceDllUnloadOnStop"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc\Security]
"Security"=hex:01,00,14,80,1c,01,00,00,28,01,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ec,00,08,00,00,00,00,00,18,00,9d,00,02,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,21,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  12,00,00,00,00,00,18,00,9d,01,02,00,01,02,00,00,00,00,00,05,20,00,00,00,20,\
  02,00,00,00,00,14,00,9d,00,02,00,01,01,00,00,00,00,00,05,04,00,00,00,00,00,\
  14,00,9d,00,02,00,01,01,00,00,00,00,00,05,06,00,00,00,00,00,28,00,fd,01,02,\
  00,01,06,00,00,00,00,00,05,50,00,00,00,e5,fe,79,5f,a0,ae,0d,3b,22,fa,0a,c9,\
  01,5a,41,3a,e5,a6,4a,b7,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,\
  00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,\
  28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,00,00,00,db,8c,74,0f,c2,72,73,\
  f3,2b,26,b9,44,77,1e,4f,02,76,63,b5,21,01,01,00,00,00,00,00,05,12,00,00,00,\
  01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%systemroot%\\system32\\SecurityHealthAgent.dll,-1001"
"DisplayName"="@%systemroot%\\system32\\SecurityHealthAgent.dll,-1002"
"ErrorControl"=dword:00000001
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,60,ea,00,00,01,00,00,00,60,ea,00,00,00,00,00,00,00,00,00,00
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,53,\
  00,65,00,63,00,75,00,72,00,69,00,74,00,79,00,48,00,65,00,61,00,6c,00,74,00,\
  68,00,53,00,65,00,72,00,76,00,69,00,63,00,65,00,2e,00,65,00,78,00,65,00,00,\
  00
"LaunchProtected"=dword:00000002
"ObjectName"="LocalSystem"
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,53,00,65,00,42,00,61,00,63,00,6b,00,75,00,70,00,50,00,72,00,69,\
  00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,52,00,65,00,73,00,\
  74,00,6f,00,72,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,\
  00,00,00,53,00,65,00,44,00,65,00,62,00,75,00,67,00,50,00,72,00,69,00,76,00,\
  69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,43,00,68,00,61,00,6e,00,67,\
  00,65,00,4e,00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,\
  6c,00,65,00,67,00,65,00,00,00,53,00,65,00,53,00,65,00,63,00,75,00,72,00,69,\
  00,74,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,\
  53,00,65,00,41,00,73,00,73,00,69,00,67,00,6e,00,50,00,72,00,69,00,6d,00,61,\
  00,72,00,79,00,54,00,6f,00,6b,00,65,00,6e,00,50,00,72,00,69,00,76,00,69,00,\
  6c,00,65,00,67,00,65,00,00,00,53,00,65,00,54,00,63,00,62,00,50,00,72,00,69,\
  00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,53,00,79,00,73,00,\
  74,00,65,00,6d,00,45,00,6e,00,76,00,69,00,72,00,6f,00,6e,00,6d,00,65,00,6e,\
  00,74,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,\
  65,00,53,00,68,00,75,00,74,00,64,00,6f,00,77,00,6e,00,50,00,72,00,69,00,76,\
  00,69,00,6c,00,65,00,67,00,65,00,00,00,00,00
"ServiceSidType"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000010

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService\Security]
"Security"=hex:01,00,14,80,1c,01,00,00,28,01,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,00,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ec,00,08,00,00,00,00,00,18,00,9d,00,02,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,21,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  12,00,00,00,00,00,18,00,9d,01,02,00,01,02,00,00,00,00,00,05,20,00,00,00,20,\
  02,00,00,00,00,14,00,9d,00,02,00,01,01,00,00,00,00,00,05,04,00,00,00,00,00,\
  14,00,9d,00,02,00,01,01,00,00,00,00,00,05,06,00,00,00,00,00,28,00,fd,01,02,\
  00,01,06,00,00,00,00,00,05,50,00,00,00,e5,fe,79,5f,a0,ae,0d,3b,22,fa,0a,c9,\
  01,5a,41,3a,e5,a6,4a,b7,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,\
  00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,\
  28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,00,00,00,db,8c,74,0f,c2,72,73,\
  f3,2b,26,b9,44,77,1e,4f,02,76,63,b5,21,01,01,00,00,00,00,00,05,12,00,00,00,\
  01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent]
"Description"="@%SystemRoot%\\System32\\Drivers\\SgrmAgent.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\SgrmAgent.sys,-1001"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,53,00,67,00,72,00,6d,00,41,00,67,\
  00,65,00,6e,00,74,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000004
"Type"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker]
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%SystemRoot%\\System32\\Sgrm\\SgrmBroker.exe,-101"
"DisplayName"="@%SystemRoot%\\System32\\Sgrm\\SgrmBroker.exe,-100"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,53,\
  00,67,00,72,00,6d,00,5c,00,53,00,67,00,72,00,6d,00,42,00,72,00,6f,00,6b,00,\
  65,00,72,00,2e,00,65,00,78,00,65,00,00,00
"LaunchProtected"=dword:00000001
"ObjectName"="LocalSystem"
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,00,00
"ServiceSidType"=dword:00000001
"Start"=dword:00000004
"Type"=dword:00000010

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker\TriggerInfo]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker\TriggerInfo\0]
"Action"=dword:00000001
"Data0"=hex:37,00,61,00,32,00,30,00,66,00,63,00,65,00,63,00,2d,00,64,00,65,00,\
  63,00,34,00,2d,00,34,00,63,00,35,00,39,00,2d,00,62,00,65,00,35,00,37,00,2d,\
  00,32,00,31,00,32,00,65,00,38,00,66,00,36,00,35,00,64,00,33,00,64,00,65,00,\
  00,00
"DataType0"=dword:00000002
"GUID"=hex:67,d1,90,bc,70,94,39,41,a9,ba,be,0b,bb,f5,b7,4d
"Type"=dword:00000006

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt]
"Description"="@%SystemRoot%\\System32\\Drivers\\mssecflt.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\mssecflt.sys,-1001"
"ErrorControl"=dword:00000001
"Group"="Filter"
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,6d,00,73,00,73,00,65,00,63,00,66,\
  00,6c,00,74,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000003
"SupportedFeatures"=dword:0000000f
"Type"=dword:00000001
"DependOnService"=hex(7):66,00,6c,00,74,00,6d,00,67,00,72,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt\Instances]
"DefaultInstance"="MsSecFlt Instance"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt\Instances\MsSecFlt Instance]
"Altitude"="385600"
"Flags"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp]
"DependOnService"=hex(7):54,00,63,00,70,00,69,00,70,00,00,00,00,00
"Description"="@%SystemRoot%\\System32\\Drivers\\mssecwfp.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\mssecwfp.sys,-1001"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,6d,00,73,00,73,00,65,00,63,00,77,\
  00,66,00,70,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000003
"Type"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection]
'@
$file7 = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\windowsdefender]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Windows.Defender]
"ShowInSettings"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Defender]
"ShowInSettings"=dword:00000000

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]
@="Windows Defender SmartScreen"

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Application]
"ApplicationName"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}"
"ApplicationCompany"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/PublisherDisplayName}"
"ApplicationIcon"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"
"ApplicationDescription"="ms-resource:DisplayName"
"AppUserModelID"="Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App"

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\DefaultIcon]
@="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell]

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open]
"ActivatableClassId"="App.AppXc99k5qnnsvxj5szemm7fp3g7y08we5vm.mca"
"PackageId"="Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"
"ContractId"="Windows.Protocol"
"DesiredInitialViewState"=dword:00000000

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open\command]
"DelegateExecute"="{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}"

[HKEY_CURRENT_USER\Software\Classes\ms-cxh]
"URL Protocol"=""
@="URL:ms-cxh"

[HKEY_CLASSES_ROOT\windowsdefender]
@="URL:windowsdefender"
"EditFlags"=dword:00200000
"URL Protocol"=""

[HKEY_CLASSES_ROOT\windowsdefender\DefaultIcon]
@="C:\\Program Files\\Windows Defender\\EppManifest.dll,-100"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]
@="Windows Defender SmartScreen"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Application]
"ApplicationName"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}"
"ApplicationCompany"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/PublisherDisplayName}"
"ApplicationIcon"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"
"ApplicationDescription"="ms-resource:DisplayName"
"AppUserModelID"="Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\DefaultIcon]
@="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell]

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open]
"ActivatableClassId"="App.AppXc99k5qnnsvxj5szemm7fp3g7y08we5vm.mca"
"PackageId"="Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"
"ContractId"="Windows.Protocol"
"DesiredInitialViewState"=dword:00000000

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open\command]
"DelegateExecute"="{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender]
@="URL:Windows Defender"
"EditFlags"=dword:00200000
"URL Protocol"=" "

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender\DefaultIcon]
@="C:\\Program Files\\Windows Defender\\EppManifest.dll,-100"

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"="NT Task\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup"
"CriticalMaintenance_DefenderVerification"="NT Task\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification"

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"WindowsDefender-1"="v2.0|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|App=%ProgramFiles%\\Windows Defender\\MsMpEng.exe|Svc=WinDefend|Name=Allow Out TCP traffic from WinDefend|"
"WindowsDefender-2"="v2.0|Action=Block|Active=TRUE|Dir=In|App=%ProgramFiles%\\Windows Defender\\MsMpEng.exe|Svc=WinDefend|Name=Block All In traffic to WinDefend|"
"WindowsDefender-3"="v2.0|Action=Block|Active=TRUE|Dir=Out|App=%ProgramFiles%\\Windows Defender\\MsMpEng.exe|Svc=WinDefend|Name=Block All Out traffic from WinDefend|"
'@
$file8 = @'
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\System32\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\SysWOW64\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\System32\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\SysWOW64\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager]
"ActivationType"=dword:00000001
"Server"="WebThreatDefSvc"
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager]
"ActivationType"=dword:00000000
"DllPath"="C:\\Windows\\System32\\ThreatExperienceManager.dll"
"Threading"=dword:00000000
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine]
"ActivationType"=dword:00000000
"DllPath"="C:\\Windows\\System32\\ThreatResponseEngine.dll"
"Threading"=dword:00000000
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings]
"ActivationType"=dword:00000001
"Server"="WebThreatDefSvc"
"TrustLevel"=dword:00000000
'@


#restore defender reg keys
Write-Host 'Restoring Defender Registry Keys...'
New-item -Path "$env:TEMP\enableReg" -ItemType Directory -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable1.reg" -Value $file1 -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable2.reg" -Value $file2 -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable3.reg" -Value $file3 -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable5.reg" -Value $file5 -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable6.reg" -Value $file6 -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable7.reg" -Value $file7 -Force | Out-Null
New-Item -Path "$env:TEMP\enableReg\enable8.reg" -Value $file8 -Force | Out-Null

$files = (Get-ChildItem -Path "$env:TEMP\enableReg").FullName
foreach ($file in $files) {
    $command = "Start-Process regedit.exe -ArgumentList `"/s $file`""
    Run-Trusted -command $command
    Start-Sleep 1
}

$command = @'
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen"  /f
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /f 
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\WinDefend" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /f 
Reg delete "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "3" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "3" /f
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /f  
Reg delete "HKLM\NTUSER\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /f 
Reg delete "HKLM\DEFAULT\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /f
Reg delete "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /f
Reg delete "HKLM\NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /f 
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableEnhancedNotifications' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableNotifications' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'SummaryNotificationDisabled' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'NoActionNotificationDisabled' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'FilesBlockedNotificationDisabled' /f
Reg delete 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /f
Reg add 'HKLM\SOFTWARE\Microsoft\Windows Defender' /v 'PUAProtection' /t REG_DWORD /d '2' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'SmartScreenEnabled' /f
'@
New-Item -Path "$env:TEMP\EnableDefend.bat" -Value $command -Force | Out-Null

Run-Trusted -command "Start-process $env:TEMP\EnableDefend.bat"
Write-Host 'Enabling MsMpEng Service...'
function enableMsMpEng {
    $id = 'Defender'; $key = 'Registry::HKU\S-1-5-21-*\Volatile Environment'; $code = @'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+='kernel','CreateProcess',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), 'advapi','RegOpenKeyEx',($U,$S,$I,$I,$D[9])
 $F+='advapi','RegSetValueEx',($U,$S,$I,$I,[byte[]],$I),'advapi','RegFlushKey',($U),'advapi','RegCloseKey',($U)
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+"32", 8214,1,$S, $F[3*$_+2], 1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"("f" + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 if ([environment]::username -ne "system") { $TI="Trusted`Installer"; start-service $TI -ea 0; $As=get-process -name $TI -ea 0
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $R=@($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $R; return}; $env:R=''; rp $key $id -force -ea 0; $e=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$e.Invoke($null,@("$_",2))}
 ## Toggling was unreliable due to multiple windows programs with open handles on these keys
 ## so went with low-level functions instead! do not use them in other scripts without a trip to learn-microsoft-com  
 function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE=4, $REG_ACCESS=2, $REG_OPTION=0) {
   $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]));  F "RegOpenKeyEx" $rok; $rsv = $rok[4]
   $values |% {$i = 0} { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
   F "RegFlushKey" @($rsv); F "RegCloseKey" @($rsv); $rok = $null; $rsv = $null;
 }  
 ## The ` sprinkles are used to keep ps event log clean, not quote the whole snippet on every run
 ################################################################################################################################ 
 
 ## get script options
 $toggle = 0; $toggle_rev = 1; 
$ENABLE_TAMPER_PROTECTION = 1

 stop-service "wscsvc" -force -ea 0 >'' 2>''
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0 
 
 $HKLM = [uintptr][uint32]2147483650
 $VALUES = "ServiceKeepAlive","PreviousRunningMode","IsServiceRunning","DisableAntiSpyware","DisableAntiVirus","PassiveMode"
 $DWORDS = 0, 0, 0, $toggle, $toggle, $toggle
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS
 [GC]::Collect(); sleep 1
 pushd "$env:programfiles\Windows Defender"
 $mpcmdrun=("OFFmeansOFF.exe","MpCmdRun.exe")[(test-path "MpCmdRun.exe")]
 start -wait $mpcmdrun -args "-EnableService -HighPriority"
 $wait=3
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1;}
 
 ## OFF means OFF
 pushd (split-path $(gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath.Trim('"'))
 ren OFFmeansOFF.exe MpCmdRun.exe -force -ea 0

 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS

  ## when re-enabling Defender, also re-enable Tamper Protection - annoying but safer - set to 0 at top of the script to skip it
 if ($ENABLE_TAMPER_PROTECTION -ne 0) {
   RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender\Features" ("TamperProtection","TamperProtectionSource") (1,5)
 }
 
 start-service "windefend" -ea 0
 start-service "wscsvc" -ea 0 >'' 2>'' 
 
 ################################################################################################################################
'@; $V = ''; 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $V, $code -type 7 -force -ea 0
    Start-Process powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas -Wait
}
enableMsMpEng

Write-Host 'Enabling Scheduled Tasks...'
$defenderTasks = Get-ScheduledTask 
foreach ($task in $defenderTasks) {
    if ($task.TaskName -like 'Windows Defender*') {
        Enable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue | Out-Null
    }
}

Write-Host 'Enabling Defender Features...'
$ProgressPreference = 'SilentlyContinue'
Enable-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-Default-Definitions' -NoRestart -ErrorAction SilentlyContinue | Out-Null
Enable-WindowsOptionalFeature -Online -FeatureName 'Windows-Defender-ApplicationGuard' -NoRestart -ErrorAction SilentlyContinue | Out-Null

#rename smartscreen
$command = 'Rename-item -path C:\Windows\System32\smartscreenOFF.exe -newname smartscreen.exe -force -erroraction silentlycontinue' 
Run-Trusted -command $command

Remove-Item "$env:TEMP\EnableDefend.bat" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\enableReg" -Recurse -Force -ErrorAction SilentlyContinue

[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?', 'zoicware', 'YesNo', 'Question')

switch ($msgBoxInput) {

    'Yes' {
  
        Restart-Computer
    }

    'No' {
    }

}