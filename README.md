# DefenderProTools
#### Take Control Over Windows Defender

*Scripts are tested on latest Windows 10 and 11*

> **NOTE:** When running manually use the included registry file to allow PowerShell scripts to run

- Included Scripts
  - [Strip Windows Defender](#strip-windows-defender)
  - [Disable Windows Defender](#disable-windows-defender)
  - [Enable Windows Defender](#enable-windows-defender)

---

## Strip Windows Defender

This powershell script will use dism and trusted installer privileges to remove defender permanently from the latest Windows 10 and 11 ISO files.

### Additional Options

- Disable TPM and hardware requirements (this is for the actual system image not the install process I recommend using rufus for that)
- Disable Virtualization-based Security (VBS) and Mitigation Options Includes [Data Execution Prevention, Control Flow Guard, Randomize Memory Allocations, Validate exception chains, Validate Heap Integrity]
- Strip Bitlocker


***Run Script from Console***
````ps
irm https://raw.githubusercontent.com/zoicware/DefenderProTools/main/StripDefenderV3.ps1 | iex
````



## Disable Windows Defender

***Run Script from Console***
````ps
irm https://raw.githubusercontent.com/zoicware/DefenderProTools/main/DisableDefender.ps1 | iex
````

This script will completely disable defender and all its related processes/services  
Uses kill engine from: https://github.com/wesmar/WinDefCtl  



## Enable Windows Defender

***Run Script from Console***
````ps
irm https://raw.githubusercontent.com/zoicware/DefenderProTools/main/EnableDefender.ps1 | iex
````
If you need to revert Windows Defender this script will restore the registry, services, and scheduled tasks.
