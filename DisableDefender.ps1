#DISABLE DEFENDER SCRIPT BY ZOIC


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit	
}


#run powershell as trusted installer credit : https://github.com/AveYo/LeanAndMean
#added -wait to prevent script from continuing too fast
function RunAsTI($cmd, $arg) {
  $id = 'RunAsTI'; $key = "Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code = @'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V = ''; 'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $($V, $code) -type 7 -force -ea 0
  Start-Process powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
} # lean & mean snippet by AveYo, 2022.01.28



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
else {

  Write-Host 'Disabling MsMpEng Service...'
  #edited toggle defender function https://github.com/AveYo/LeanAndMean
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
    Start-Process powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas -Wait
  }
  defeatMsMpEng
  #wait for defender service to close before continue
  do {
    $proc = Get-Process -Name MsMpEng -ErrorAction SilentlyContinue
    Start-Sleep 1
  }while ($proc)
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


  RunAsTI powershell "-nologo -windowstyle hidden -command $command"
  Start-Sleep 2
  #disable tasks
  Get-ScheduledTask | Where-Object { $_.Taskname -match 'Windows Defender Cache Maintenance' } | Disable-ScheduledTask -ErrorAction SilentlyContinue
  Get-ScheduledTask | Where-Object { $_.Taskname -match 'Windows Defender Cleanup' } | Disable-ScheduledTask -ErrorAction SilentlyContinue
  Get-ScheduledTask | Where-Object { $_.Taskname -match 'Windows Defender Scheduled Scan' } | Disable-ScheduledTask -ErrorAction SilentlyContinue
  Get-ScheduledTask | Where-Object { $_.Taskname -match 'Windows Defender Verification' } | Disable-ScheduledTask -ErrorAction SilentlyContinue

  #stop smartscreen from running
  $smartScreen = 'C:\Windows\System32\smartscreen.exe'
  $smartScreenOFF = 'C:\Windows\System32\smartscreenOFF.exe'
  $command = "Remove-item -path $smartscreenOFF -force -erroraction silentlycontinue; Rename-item -path $smartScreen -newname smartscreenOFF.exe -force"
 
  RunAsTI powershell "-nologo -windowstyle hidden -command $command"
}
      

[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?', 'zoicware', 'YesNo', 'Question')

switch ($msgBoxInput) {

  'Yes' {
  
    Restart-Computer
  }

  'No' {
  }

}


