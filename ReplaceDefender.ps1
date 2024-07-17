If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


function Run-Trusted([String]$command) {

    Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
    #get bin path to revert later
    $query = sc.exe qc TrustedInstaller | Select-String 'BINARY_PATH_NAME'
    #limit split to only 2 parts
    $binPath = $query -split ':', 2
    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
    #run the command
    sc.exe start TrustedInstaller | Out-Null
    #set bin back to default
    sc.exe config TrustedInstaller binPath= "$($binPath[1].Trim())" | Out-Null
    Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue

}




# -------------------------------------------------------------------------------- REPLACE SECTION ----------------------------



Write-Host 'Downloading AVG Installer...'
$ProgressPreference = 'SilentlyContinue'
#install offline installer for silent switch
$uri = 'https://bits.avcdn.net/productfamily_ANTIVIRUS/insttype_FREE/platform_WIN_AVG/installertype_FULL/build_RELEASE'
Invoke-WebRequest -Uri $uri -UseBasicParsing -OutFile "$env:TEMP\AVG_Installer.exe"
        
Write-Host 'Installing AVG...'
Start-Process "$env:TEMP\AVG_Installer.exe" -ArgumentList '/silent' -Wait

Write-Host 'Disabling AVG Scheduled Tasks...'
Get-ScheduledTask -TaskPath '\AVG\*' | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

Write-Host 'Cleaning AVG Shortcuts and Context Menu...'
Remove-Item -Path 'C:\Users\Public\Desktop\AVG AntiVirus Free.lnk' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AVG AntiVirus Free.lnk' -Force -ErrorAction SilentlyContinue
Reg.exe delete 'HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\AVG' /f >$null
Reg.exe delete 'HKLM\Software\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\00avg' /f >$null
Reg.exe delete 'HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers\AVG' /f >$null

Write-Host 'Disabling Leftover Defender Features...'
#wait for antimalware to close
Write-Host 'Waiting for Win Defend Service to Close...' 
do {
    $proc = Get-Process -Name MsMpEng -ErrorAction SilentlyContinue
    Start-Sleep .5
}while ($proc)

$command = @'
Stop-Process -name smartscreen.exe -Force
Stop-Process -name SecurityHealthService.exe -Force
Stop-Process -name SecurityHealthSystray.exe -Force
Stop-Process -name MpCmdRun.exe -Force
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PreviousRunningMode" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "IsServiceRunning" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PassiveMode" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "PreviousRunningMode" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "PassiveMode" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "IsServiceRunning" /t REG_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\NTUSER\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d 0 /f 
Reg add "HKLM\DEFAULT\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d 0 /f
Reg add "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d 0 /f
Reg add "HKLM\NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d 0 /f 
Reg add "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f 
'@
       
Run-Trusted -command $command
#rename smartscreen exe
$command = 'Rename-item -path C:\Windows\System32\smartscreen.exe -newname smartscreenOFF.exe -force'
Run-Trusted -command $command
Write-Host 'Apply Minimal Settings...'
$ProgressPreference = 'SilentlyContinue'
#download settings from github 
$uri = 'https://raw.githubusercontent.com/zoicware/DefenderProTools/main/Resources/settingsminimal.avgconfig'
Invoke-WebRequest -Uri $uri -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\settingsminimal.avgconfig"

Start-Process "$env:USERPROFILE\Desktop\settingsminimal.avgconfig" -WindowStyle Maximized
