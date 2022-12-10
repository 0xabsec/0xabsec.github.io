---
layout: default
---
# Windows Command Line (cmd)

## delete without trace
```
C:\Windows> cipher /w
--> Removes data from available unused disk space on the entire volume

C:\Windows> Sdelete 
--> secure delete 

C:\Windows> dban
--> securely erase data
```
## type, more, set
```
C:\Windows> type filename | find /i "[string]"

C:\Windows> type filename | findstr "regex"

C:\Windows> more filename 
--> Display one page at a time

C:\Windows> command name /? 
--> bring help

C:\Windows> set 
--> see env variable
```
## Managing account and users
```
C:\Windows> lusrmgr.msc 
--> bring up GUI

C:\Windows> net user 
--> shows user

C:\Windows> net localgroup 
--> shows localgroup

C:\Windows> net localgroup administrator 
--> who are in admin groups

C:\Windows> net user [logon name] [password] /add 
--> add user

C:\Windows> net user [logon name] * /add 
--> prompt for password

C:\Windows> net localgroup administrator [logon name] /add 
--> add user to local admin groups

C:\Windows> net localgroup [group] [logon name] /del 
--> to remove user from a group

C:\Windows> net user [logon_name] /del 
--> to delete account
```
> the lusrmgr.msc does not seem to work in windows 11.

## analyzing system determining firewall
```
C:\Windows> netsh /? 
--> bring up help

C:\Windows> netsh advfirewall show allprofiles 
--> see whole configuration of bulilt in firewall

C:\Windows> netsh advfirewall firewall add rule name="[]" dir(<--here dir means direction)=in(<-- means inbound) action=allow remoteip=[ipaddr] protocole=TCP localport=[port] 
--> to allow a given port inbound
-----> ex --> C:\Windows>netsh advfirewall firewall add rule name ="ALLOW TCP 23" dir=in action=allow remoteip=10.10.10.10 protocol=TCP localport=23

C:\Windows> netsh advfirewall firewall del rule name="[comment]" 
--> delete a rule

C:\Windows> netsh advfirewall set allprofiles state off 
--> to disable windows firewall altogether

C:\Windows> netsh firewall show portopening 
--> show all ports allowed through the built-in firewall

C:\Windows> netsh firewall show allowedprogram 
--> Show all programs allowed to communicate through the built-in firewall
```
## interacting with registry keys
```
C:\Windows> reg query [key name] 
--> read a reg key

C:\Windows> reg add [KeyName] /v [valueName] /t [type] /d [Data] 
--> Change a reg key

C:\Windows> reg export [KeyName] [filename.reg] 
--> export settings to reg key

C:\Windows> reg import [filename.reg]
--> import setting from a reg key
```
> Warning --> Do not play with registry keys if you don't know what you are doing.

## SMB

```
C:\Windows> net use \\[target ip] [password] /u:[user] 
--> if we skip the password it will prompt for it

C:\Windows> net use * \\[target ip]\[share] [password] /u:[user](<-- or /u:[Machine_name or Domain]\[user]) 
--> mount a share on the target

C:\Windows> net use \\[target_ip] /del 
--> to drop smb session

C:\Windows> net use * /del 
--> to drop all smb sessions

C:\Windows> net use 
--> will show if we have any smb sessions

C:\Windows> net session 
--> will show who has smb session coming to us
```
## Controlling Services with SC
```
C:\Windows> sc query 
--> to see runnning services

C:\Windows> sc query state= all 
--> to list all services

C:\Windows> sc qc [service name] 
--> for detail on one service

C:\Windows> sc start [service name] 
--> to start a service

C:\Windows> sc config [service_name] start= demand 
--> if the service start_type is disabled, you first have to enable it before starting

C:\Windows> sc stop [service_name] 
--> to stop a service

C:\Windows> sc \\[target_ip] query schedule 
--> checking the schedule service is running

C:\Windows> sc \\ [target_ip] create [svcname] binpath= [command]
C:\Windows> sc \\[targetIP] start [svcname]
--> It runs for 30 second only then the system kills it because it does not make an api call back saying that the service started successfully

C:\Windows>sc \\[target_ip] create [svcname] binpath= "cmd.exe /k(<-- run another command) [command]"
--> the cmd.exe will live for 30 seconds but the child process or command it spawns will continue running.

```
## PSEXEC
```
C:\Windows> (sysinternal)psexec \\[targetIP] [-d] [-u user] [-p password] [command] 
--> not builtin by default 
--> microsoft psexec creates a service and leaves behind ...do not delete itself.

msf > (metasploit) use /exploit/windows/smb/psexec 
--> supports passthehash attack
--> write exe into target file system 
--> create a service with pseudo random name 
--> runs with local system priv 
--> automatically removes the executable and service,cleaning up after itself.
```
## wmic
```
C:\Windows> wmic /node:[TargetIP] /user:[admin_user] /password:[password] process call create [command]
--> if leave off the /user and /password it will pass through the existing user credeentials
--> wmic itself is not logged but the command will if it will do something

C:\Windows> wmic /node:[TargetIP] /user:[admin_user] /password:[password] process list brief
--> List processes

C:\Windows> wmic /node:[TargetIP] /user:[admin_user] /password:[password] process where processid="[PID]" delete
--> Delete process by id

C:\Windows> wmic /node:[TargetIP] /user:[admin_user] /password:[password] process where name="[name]" delete
--> Delete process by name

C:\Windows> wmic service where (displayname like "%[whatever]%) get name 
--> determine the service name 
note --> (display name and service names are different) 
```
