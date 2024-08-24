---
layout: default
---
# HackTheBox POV

## RECON

### Nmap

Starting of with the NMAP, It shows  only one port open 80/(http).

![nmap](./htb/pics/1.png)

Going through Script and version scan it shows something like a hostname in http_title

![nmap](./htb/pics/2.png)

Adding hostname in to our /etc/hosts file

![hosts](./htb/pics/3.png)


## Website

### pov.htb

Going through the webpage looks like a static webpage leaking another hostname dev.pov.htb and potential user sfitz.

![site](./htb/pics/4.png)

Adding the hostname dev.pov.htb

![site](./htb/pics/5.png)

### dev.pov.htb

Looking in to the site we can see there is a download button to Download Stephen Fitz CV

![site](./htb/pics/6.png)

* * *

### User Sfitz

Intercepting the Download Request through burp it looks something like this with the file parameter as cv.pdf 

![site](./htb/pics/7.png)

Seding the Request in to the Repeater and changing the cv.pdf in index.aspx it gives error path to /portfolio/default.aspx

![site](./htb/pics/8.png)

Changing the file parameter from index.aspx to default.aspx it shows code of the page means the file parameter is vulnerable to file_disclosure vulnerablity

It also shows index.aspx.cs as a CodeFile

![site](./htb/pics/9.png)

Looking in to th index.aspx.cs file we can see it is filtering ../ for possible directory traversal attacks 

![site](./htb/pics/10.png)

To bypass the filter we can do something like ....//web.config as it will filter out ../ and the req will be processed as ../web.config

We are looking in to web.config because sometimes it holds sensitive information.

![site](./htb/pics/11.png)

Web.Config is leaking Decryption key and Machine key and since the site is using ViewState cookie There is a potential chance of RCE

There are few resources on the internet which goes over this like hacktricks, I personally liked this one [here](https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/) 

Using [ysoserial.exe](https://github.com/pwntester/ysoserial.net/releases/tag/v1.35) in windows VM to generate a RCE payload 

![site](./htb/pics/13.png)

For simplicity i used powershell base64 encoded payload

![powershell](./htb/pics/12.png)

Pasting the resulted payload ysoserial gave us in to the ViewState parameter on the burp

![site](./htb/pics/14.png)

modifying our nishang revshell payload 

![site](./htb/pics/15.png)

Starting the python webserver in and nc in our box and sending the request we get the shell back 

![site](./htb/pics/17.png)

Using whoami we can see we go the shell as sfitz user

![site](./htb/pics/18.png)

* * *

### User alaading

Starting Recon of the Box as Sftiz we can see there is another user on the box as alaading


![site](./htb/pics/19.png)

Looking at the current open ports in the box we can see the smb (445), winrm(5985) ports are open locally

![site](./htb/pics/20.png)

Enumerating sftiz home directory we found connection.xml file in the Documents Directory

![site](./htb/pics/21.png)

Looking in to the contents of the file there is what looks like a secure string pass of user alaading

![site](./htb/pics/22.png)

To Decrypt the Secure string pass we put the pass in to the file.

![site](./htb/pics/23.png)

Decrypting the pass we get the Password for user alaading

![site](./htb/pics/24.png)

Since there is no way we can log in to the box from our box as only port 80 is open to us. But winrm is open locally so we can use Chisel to access the port

Starting chisel server in our box 

![site](./htb/pics/26.png)

Putting Chisel in windows and doing port forwarding of winrm

![site](./htb/pics/27.png)

We can see port 5985 is opened in our box

![site](./htb/pics/28.png)

Using Evil-Winrm to log in as User alaading we can login in to box

![site](./htb/pics/29.png)

We can grab the user.txt 

![site](./htb/pics/31.png)

* * *

### Privilege Escalation To System

whoami /priv shows us that the use alaading has SeDebugPrivilege Enabled

![site](./htb/pics/30.png)

SeDebugPrivilege allows the holder to debug another process, this includes reading and writing to that process memory

To Use it for our advantage i used a powershell script from the [GITHUB](https://github.com/decoder-it/psgetsystem)

Moving it in to the box and then importing it 

![site](./htb/pics/33.png)

Looking in to script it gave us the instruction on how to use it

![site](./htb/pics/34.png)

We need a system process pid so i am using winlogon 

![site](./htb/pics/36.png)

As a command to execute i am going to execute msfvenom revshell payload for windows.

Generating msfvenom payload

![site](./htb/pics/35.png)

copying payload to the Box and Starting our nc listener we can use the powershell script module 

![site](./htb/pics/37.png)

We Get the shell back as nt authority/system now we can grab the flag

![site](./htb/pics/39.png)

* * *

