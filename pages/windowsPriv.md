---
layout: default
---
# Windows Priv Escalation

## Tools

[Seatbelt](https://github.com/GhostPack/Seatbelt) → C# project for performing a wide variety of local privilege escalation checks

[Pre-Compiled Binary](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) → WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained 

[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) → PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found

[SharpUp](https://github.com/GhostPack/SharpUp) →  C# version of PowerUp

[Pre-Compiled Binary](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

[JAWS](https://github.com/411Hall/JAWS) →  PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0

[SessionGopher](https://github.com/Arvanaghi/SessionGopher) → SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information

[Watson](https://github.com/rasta-mouse/Watson) → Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.

[LaZagne](https://github.com/AlessandroZ/LaZagne) → Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more

[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng) → WES-NG is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported

Sysinternals Suite → We will use several tools from Sysinternals in our enumeration including [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), and [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)


> Note: Depending on how we gain access to a system we may not have many directories that are writeable by our user to upload tools. It is always a safe bet to upload tools to C:\Windows\Temp because the BUILTIN\Users group has write access.

## Getting lay of the Land

### Situational Awareness

#### Network Information

Interface(s), IP Address(es), DNS Information

```
C:\Users\> ipconfig /all
```
ARP Table

```
C:\Users\> arp -a
```
Routing Table

```
C:\Users\> route print
```
#### Enumerating Protections

Check Windows Defender Status

```
PS C:\Users\> Get-MpComputerStatus
```
List AppLocker Rules

```
PS C:\Users\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

Test AppLocker Policy

```
PS C:\Users\> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

### Initial Enumeration

[Windows COmmand Reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)

[Cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#windows-version-and-configuration)

#### Key Data Points

**OS name**: Knowing the type of Windows OS (workstation or server) and level (Windows 7 or 10, Server 2008, 2012, 2016, 2019, etc.) will give us an idea of the types of tools that may be available (such as the PowerShell version, or lack thereof on legacy systems. This would also identify the operating system version for which there may be public exploits availabl

**Version**: As with the OS version, there may be public exploits that target a vulnerability in a specific version of Windows. Windows system exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.

**Running Services**: Knowing what services are running on the host is important, especially those running as NT AUTHORITY\SYSTEM or an administrator-level account. A misconfigurng in the context of a privileged account can be an easy win for privilege escalation

#### System Information

```
C:\Users\> tasklist /svc
```
**standard Windows processes**: Session Manager Subsystem (smss.exe), Client Server Runtime Subsystem (csrss.exe), WinLogon (winlogon.exe), Local Security Authority Subsystem Service (LSASS), and Service Host (svchost.exe)

#### Display All Environment Variables

```
C:\Users\> set
```
> when running a program, Windows looks for that program in the CWD (Current Working Directory) first, then from the PATH going left to right

> If a file is placed in USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup, when the user logs into a different machine, this file will execute

#### View Detailed Configuration Information

```
C:\Users\> systeminfo
```

> The System Boot Time and OS Version can also be checked to get an idea of the patch level

#### Patches and Updates

```
C:\Users\> wmic qfe
```

```
PS C:\> Get-HotFix | ft -AutoSize
```
> If systeminfo doesn't display hotfixes, they may be queriable with WMI using the WMI-Command binary with QFE (Quick Fix Engineering) to display patches

#### Installed Programs

```
C:\Users\> wmic product get name
```

```
PS C:\> Get-WmiObject -Class Win32_Product |  select Name, Version
```

#### Display Running Processes

```
PS C:\> netstat -ano

PS C:\> netstat -anoy
```
```
PS C:\Windows\system32> Get-Process -Id (Get-NetTCPConnection -LocalPort portnumber).OwningProcess             
```
> Service Listening On specific port
> Elevated Session may Required

#### User & Group Information

```
PS C:\Users\> query user
```
> Logged-In Users

```
C:\Users\ > echo %USERNAME%
```
> Current User

```
C:\> whoami /priv
```
> Current User Privileges

```
PS C:\Users\> whoami /groups
```
> Current User Group Information

```
PS C:\Users\> net user
```
> Get All Users

```
PS C:\Users\> net localgroup
```
> Get All Groups

```
PS C:\Users\> net localgroup administrators
```
> Details About a Group

```
PS C:\Users\> net accounts
```
> Get Password Policy

### Communication WIth Processes

#### Listing Named Pipes with Pipelist

```
C:\> pipelist.exe /accepteula
```

> Listing Named Pipes with PowerShell

```
PS C:\>  gci  \\.\pipe\
```

> Reviewing LSASS Named Pipe Permissions

```
C:\> accesschk.exe /accepteula \\.\Pipe\lsass -v
```

#### Named Pipes Attack Example

```
C:\> accesschk.exe -w \pipe\* -v
```
 
> WindscribeService named pipe allows READ and WRITE access to the Everyone group, meaning all authenticated users.

```
C:\> accesschk.exe -accepteula -w \pipe\WindscribeService -v
```
