#DISABLE DEFENDER SCRIPT BY ZOIC


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit	
}

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


<#
#check if tamper protection is disabled already
$key = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
try {
  $tamper = Get-ItemPropertyValue -Path $key -Name 'TamperProtection' -ErrorAction Stop
  $tamperSource = Get-ItemPropertyValue -Path $key -Name 'TamperProtectionSource' -ErrorAction Stop
}
catch {
  #do nothing
}
      
if ((!($tamper -eq '4' -or '0' -and $tamperSource -eq '2')) -or !((Get-MpPreference).DisableTamperProtection)) {
       
  #display prompt to user
  [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
  [System.Windows.Forms.MessageBox]::Show('Please DO NOT Press Any Keys While Script Disables Tamper Protection.', 'ZOICWARE')

  #get current uac settings
  $key = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $promptValue = Get-ItemPropertyValue -Path $key -Name 'PromptOnSecureDesktop' -ErrorAction SilentlyContinue
  $luaValue = Get-ItemPropertyValue -Path $key -Name 'EnableLUA' -ErrorAction SilentlyContinue
  $promptValueAdmin = Get-ItemPropertyValue -Path $key -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue

  #disable uac to avoid popup when disabling tamper protection
  $command = {
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'PromptOnSecureDesktop' /t REG_DWORD /d '0' /f
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableLUA' /t REG_DWORD /d '0' /f
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorAdmin' /t REG_DWORD /d '0' /f
  }
  Invoke-Command $command | Out-Null

  #open security app 
  Start-Process -FilePath explorer.exe -ArgumentList windowsdefender://threat -WindowStyle Maximized 
  Start-Sleep 2
  #full screen the app with key shortcuts
  $wshell = New-Object -ComObject wscript.shell
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Keyboard
{
    [DllImport("user32.dll")]
    public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, uint dwExtraInfo);
}
'@

  # Define key codes
  $VK_ALT = 0x12  # Alt key code
  $VK_SPACE = 0x20  # Space key code
  $VK_X = 0x58  # X key code

  # Simulate Alt+Space keystroke combination
  [Keyboard]::keybd_event($VK_ALT, 0, 0, 0)
  [Keyboard]::keybd_event($VK_SPACE, 0, 0, 0)
  Start-Sleep -Milliseconds 100  # Wait for a moment
  [Keyboard]::keybd_event($VK_SPACE, 0, 0x2, 0)
  [Keyboard]::keybd_event($VK_ALT, 0, 0x2, 0)

  # Press the 'X' key
  [Keyboard]::keybd_event($VK_X, 0, 0, 0)
  Start-Sleep -Milliseconds 100  # Wait for a moment
  [Keyboard]::keybd_event($VK_X, 0, 0x2, 0)

  Start-Sleep 2
  #get os version
  $OS = Get-CimInstance Win32_OperatingSystem
  #navigate to tamper protection and turn off
  #different options on windows 11 sec app so more tabs are needed to get to tamper protection

  if ($OS.Caption -like '*Windows 11*') {
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .35
    $wshell.SendKeys(' ')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .35
    $wshell.SendKeys(' ')
  }
  else {
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .35
    $wshell.SendKeys(' ')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .55
    $wshell.SendKeys('{TAB}')
    Start-Sleep .35
    $wshell.SendKeys(' ')
  }
  Start-Sleep .75
  #close sec app
  Stop-Process -name SecHealthUI -Force

  #set uac back to og values
  $command = {
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'PromptOnSecureDesktop' /t REG_DWORD /d $promptValue /f
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableLUA' /t REG_DWORD /d $luaValue /f
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorAdmin' /t REG_DWORD /d $promptValueAdmin /f
  }
  Invoke-Command $command | Out-Null

  #update tamper values
  $key = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
  try {
    $tamper = Get-ItemPropertyValue -Path $key -Name 'TamperProtection' -ErrorAction Stop
    $tamperSource = Get-ItemPropertyValue -Path $key -Name 'TamperProtectionSource' -ErrorAction Stop
  }
  catch {
    #do nothing
  }
}
      
#check again if tamper got disabled
if ((!($tamper -eq '4' -or '0' -and $tamperSource -eq '2')) -or !((Get-MpPreference).DisableTamperProtection)) {
  Write-Host 'Tamper Protection NOT Disabled...Closing Script' -ForegroundColor Red
}
#>

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
#exploit protection
Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /t REG_BINARY /d '222222000001000000000000000000000000000000000000' /f *>$null
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender' /v 'PUAProtection' /t REG_DWORD /d '0' /f"
Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'SmartScreenEnabled' /t REG_SZ /d 'Off' /f"
#first run of defeat function
Run-Trusted -command $run
Start-Sleep 3

#temp anti virus credit https://github.com/es3n1n/no-defender
Write-Host 'Installing Temp Antivirus...'
$ProgressPreference = 'SilentlyContinue'
$tempDir = "$env:TEMP\nodefender"
New-item -Path $tempDir -ItemType Directory -Force | Out-Null
#add dir to exclusion
Add-MpPreference -ExclusionPath $tempDir -Force 
Add-MpPreference -ExclusionProcess 'ilovedefender.exe' -Force 
$splat = @{
  DisableBehaviorMonitoring        = $true 
  DisableIntrusionPreventionSystem = $true 
  DisableRealtimeMonitoring        = $true 
  DisableBlockAtFirstSeen          = $true 
}
Set-MpPreference -ExclusionProcess 'ilovedefender.exe' @splat 
#install files
$uri = 'https://raw.githubusercontent.com/zoicware/DefenderProTools/main/Resources/nodefender'
$files = @(
  'ilovedefender.exe'
  'no-defender-loader.pdb'
  'powrprof.dll'
  'powrprof.pdb'
  'wsc.dll'
  'wsc_proxy.exe'
)
foreach ($file in $files) {
  Invoke-WebRequest -Uri "$uri/$file" -OutFile "$tempDir\$file" -UseBasicParsing
}
#attempt to kill defender processes and silence notifications from sec center
$command = 'Stop-Process MpDefenderCoreService -Force; Stop-Process smartscreen -Force; Stop-Process SecurityHealthService -Force; Stop-Process SecurityHealthSystray -Force; Stop-Service -Name wscsvc -Force; Stop-Service -Name Sense -Force'
Run-Trusted -command $command
#run no defender
Start-Process "$tempDir\ilovedefender.exe" -ArgumentList '--av' -WindowStyle Hidden

#wait for defender service to close before continue
do {
  $proc = Get-Process -Name MsMpEng -ErrorAction SilentlyContinue
  Start-Sleep 1
}while ($proc)

Write-Host 'Disabling MsMpEng Service...'
Run-Trusted -command $run
  
#disables defender through gp edit
 
Write-Host 'Disabling Defender with Group Policy' 

$command = @'
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\WinDefend" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /t REG_DWORD /d 0 /f 
'@


Run-Trusted -command $command

#disable tasks
$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
  if ($task.Taskname -like 'Windows Defender*') {
    Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
  }
}

#stop smartscreen from running
$smartScreen = 'C:\Windows\System32\smartscreen.exe'
$smartScreenOFF = 'C:\Windows\System32\smartscreenOFF.exe'
$command = "Remove-item -path $smartscreenOFF -force -erroraction silentlycontinue; Rename-item -path $smartScreen -newname smartscreenOFF.exe -force"
 
Run-Trusted -command $command

Write-Host 'Cleaning Up...'
#remove temp av
Remove-Item $tempDir -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path 'registry::HKLM\SOFTWARE\Avast Software' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'registry::HKLM\SYSTEM\ControlSet001\Services\wsc_proxy' -Recurse -Force -ErrorAction SilentlyContinue

[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?', 'zoicware', 'YesNo', 'Question')

switch ($msgBoxInput) {

  'Yes' {
  
    Restart-Computer
  }

  'No' {
  }

}


