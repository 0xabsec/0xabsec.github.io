---
layout: default
---
>> [cheat Sheet](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/)

## Credential Theft

We may find credentials during our privilege escalation enumeration that can lead directly to local admin access, grant us a foothold into the Active Directory domain environment, or even be used to escalate privileges within the domain

### Credential Hunting

#### **Application Configuration Files**

##### Searching for Files

```
PS C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```
>> Sensitive IIS information such as credentials may be stored in a web.config file. For the default IIS website, this could be located at C:\inetpub\wwwroot\web.config, but there may be multiple versions of this file in different locations, which we can search for recursively

#### **Dictionary Files**

Sensitive information such as passwords may be entered in an email client or a browser-based application, which underlines any words it doesn't recognize. The user may add these words to their dictionary to avoid the distracting red underline

```
PS C:\> gc 'C:\Users\abc\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

#### **Unattended Installation Files**

Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the unattend.xml are stored in plaintext or base64 encoded

```
Unattend.xml

<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="specialize">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <AutoLogon>
                <Password>
                    <Value>local_4dmin_p@ss</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>Administrator</Username>
            </AutoLogon>
            <ComputerName>*</ComputerName>
        </component>
    </settings>
```

#### **PowerShell History File**

```
PS C:\> (Get-PSReadLineOption).HistorySavePath

PS C:\> gc (Get-PSReadLineOption).HistorySavePath
```
We can also use this one-liner to retrieve the contents of all Powershell history files that we can access as our current user

```
PS C:\> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

#### **PowerShell Credentials**

PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using DPAPI, which typically means they can only be decrypted by the same user on the same computer they were created on.

##### Decrypting Powershell Credentials

```
PS C:\> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
PS C:\> $credential.GetNetworkCredential().username
PS C:\> $credential.GetNetworkCredential().password
```

##### Decrypting Secure String Pass
```
PS C:\> $pw = Get-Content .creds.txt | ConvertTo-SecureString
PS C:\> $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
PS C:\> $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
PS C:\> $UnsecurePassword
```
### Other Files

There are many other types of files that we may find on a local system or on network share drives that may contain credentials or additional information that can be used to escalate privileges. In an Active Directory environment, we can use a tool such as [Snaffler](https://github.com/SnaffCon/Snaffler) to crawl network share drives for interesting file extensions such as .kdbx, .vmdk, .vdhx, .ppk, etc

#### **Manually Searching the File System for Credentials**

```
--- Example 1 ---

C:\> cd c:\Users\abc\Documents & findstr /SI /M "password" *.xml *.ini *.txt

--- Example 2 ---

C:\> findstr /si password *.xml *.ini *.txt *.config

--- Example 3 ---

C:\> findstr /spin "password" *.*
```

##### Search for File Extensions

```
C:\> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

C:\> where /R C:\ *.config

PS C:\> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

##### Search File Contents with PowerShell

```
PS C:\> select-string -Path C:\Users\abc\Documents\*.txt -Pattern password
```

#### **Sticky Notes Passwords**

People often use the StickyNotes app on Windows workstations to save passwords and other information, not realizing it is a database file. This file is located at **C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite** and is always worth searching for and examining

##### Looking for StickyNotes DB Files

```
PS C:\> ls
 
 
    Directory: C:\Users\abc\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
 
 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/25/2021  11:59 AM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----         5/25/2021  11:59 AM            982 Ecs.dat
-a----         5/25/2021  11:59 AM           4096 plum.sqlite
-a----         5/25/2021  11:59 AM          32768 plum.sqlite-shm
-a----         5/25/2021  12:00 PM         197792 plum.sqlite-wal
```

##### Viewing Sticky Notes Data Using PowerShell

This can also be done with PowerShell using the [PSSQLite module](https://github.com/RamblingCookieMonster/PSSQLite)

```
PS C:\> Set-ExecutionPolicy Bypass -Scope Process
PS C:\> cd .\PSSQLite\
PS C:\> Import-Module .\PSSQLite.psd1
PS C:\> $db = 'C:\Users\abc\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```
>> Strings Can also be used depending on the size of the database

#### **Other Files of Interest**

#### Other Interesting Files

```
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

