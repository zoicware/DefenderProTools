# DefenderProTools
#### Take Control Over Windows Defender

*Scripts are tested on latest Windows 10 and 11*

> **NOTE:** When running manually use the included registry file to allow PowerShell scripts to run

- Included Scripts
  - [Strip Windows Defender](#strip-windows-defender)
  - [Disable Windows Defender](#disable-windows-defender)
  - [Replace Windows Defender](#replace-windows-defender)
  - [Enable Windows Defender](#enable-windows-defender)

---

## Strip Windows Defender

This powershell script will use dism and trusted installer privileges to remove defender permanently from the latest Windows 10 and 11 ISO files.

### Additional Options

- Strip Windows Defender Firewall
- Disable Virtualization-based Security (VBS) and Mitigation Options Includes [Data Execution Prevention, Control Flow Guard, Randomize Memory Allocations, Validate exception chains, Validate Heap Integrity]
- Strip Bitlocker


***Run Script from Console***
````ps
iwr https://raw.githubusercontent.com/zoicware/DefenderProTools/main/StripDefenderV3.ps1 | iex
````

**USAGE EXAMPLE:**

![image](https://github.com/zoicware/DefenderProTools/assets/118035521/4b1d0211-948a-4ca7-841d-89221b1161c1)

![image](https://github.com/zoicware/DefenderProTools/assets/118035521/56a5e59c-ca57-4732-9713-c640159c0872)

![image](https://github.com/zoicware/DefenderProTools/assets/118035521/761502d9-5f49-46f2-95c5-bdb44238823c)



## Disable Windows Defender

***Run Script from Console***
````ps
iwr https://raw.githubusercontent.com/zoicware/DefenderProTools/main/DisableDefender.ps1 | iex
````

- this script will disable all services/processes related to windows defender
    - Note : windows defender firewall is not touched
    
- to bypass tamper protection a temporary antivirus needs to be installed
    - Credit : https://github.com/es3n1n/no-defender


- Credits to @AveYo for the disable MsMpEng service snippet

> **NOTE:** To prevent smartscreen from running renaming the exe file is needed but windows will repair this file when running `sfc /scannow`

## Replace Windows Defender

***Run Script from Console***
````ps
iwr https://raw.githubusercontent.com/zoicware/DefenderProTools/main/ReplaceDefender.ps1 | iex
````

This script will replace Windows Defender with AVG Antivirus
  - cleanup AVG shortcuts and context menu
  - disable the rest of Windows Defender
  - import minimal settings

AVG is a light weight AV that will provide better protection than Windows Defender

## Enable Windows Defender

***Run Script from Console***
````ps
iwr https://raw.githubusercontent.com/zoicware/DefenderProTools/main/EnableDefender.ps1 | iex
````


If you need to revert Windows Defender this script will restore the registry, services, and scheduled tasks.
