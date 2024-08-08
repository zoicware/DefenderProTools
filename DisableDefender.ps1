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
function defeatMsMpEng {
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
 $toggle = 1; $toggle_rev = 0; 
 $TOGGLE_SMARTSCREENFILTER = 1

 stop-service "wscsvc" -force -ea 0 >'' 2>''
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0 
 
 $HKLM = [uintptr][uint32]2147483650; $HKU = [uintptr][uint32]2147483651 
 $VALUES = "ServiceKeepAlive","PreviousRunningMode","IsServiceRunning","DisableAntiSpyware","DisableAntiVirus","PassiveMode"
 $DWORDS = 0, 0, 0, $toggle, $toggle, $toggle
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS
 [GC]::Collect(); sleep 1
 pushd "$env:programfiles\Windows Defender"
 $mpcmdrun=("OFFmeansOFF.exe","MpCmdRun.exe")[(test-path "MpCmdRun.exe")]
 start -wait $mpcmdrun -args "-DisableService -HighPriority"
 $wait=14
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1;}
 
 ## OFF means OFF
 pushd (split-path $(gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath.Trim('"'))
 ren MpCmdRun.exe OFFmeansOFF.exe -force -ea 0
 

 ## Comment to keep old scan history
 del "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ea 0 
 del "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ea 0

 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS

 ## when toggling Defender, also toggle SmartScreen - set to 0 at top of the script to skip it
 if ($TOGGLE_SMARTSCREENFILTER -ne 0) {
   sp "HKLM:\CurrentControlSet\Control\CI\Policy" 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ea 0
   sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" 'SmartScreenEnabled' @('Off','Warn')[$toggle -eq 0] -force -ea 0 
   gi Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 |% {
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $toggle_rev -type Dword -force -ea 0
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'PreventOverride' $toggle_rev -type Dword -force -ea 0
     ni "$($_.PSPath)\Edge\SmartScreenEnabled" -ea 0 > ''
     sp "$($_.PSPath)\Edge\SmartScreenEnabled" "(Default)" $toggle_rev
   }
   if ($toggle_rev -eq 0) {kill -name smartscreen -force -ea 0}
 }
 
 
 ################################################################################################################################
'@; $V = ''; 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $V, $code -type 7 -force -ea 0
  Start-Process powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas -WindowStyle Hidden -Wait
}

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
defeatMsMpEng
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
#edited toggle defender function https://github.com/AveYo/LeanAndMean
defeatMsMpEng
  
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


