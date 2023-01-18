---
layout: default
---
# Windows Powershell

## Basics
```
PS C:\> get-command set*
---> TO get list of cmdlets (in example cmdlets that starts with set)

PS C:\>alias 
show all the alias associated with commands for example 
--> alias gcm

PS C:\> get-alias -definition get-process 
---> to get the alias of the given command (here it will print get-process alias)

PS C:\> help get-process 
--> print out the help page for get-process
                                      ______
PS C:\> help {command name} -detailed       \
PS C:\> help {command name} -examples -------> To get more details
PS C:\> help {command name} -full     ______/

PS C:\> help {command name} -online
--> to get more detail online

PS C:\> remove-item {filename} -whatif
---> whatif flag will tell what the command will do without executing the command
```
## Powershell Pipelines
```
PS C:\> ls | gm (<-- get-member)
--> in powershell we do not pipe ascii or unicode data like bash and cmd instead we pipe down powershell objects.In powershell we ran a cmdlet and it does not generate a stream
of data but instead it generate a variety of objects. Objects are structures which are included in powershell these objects have properties and methods.

PS C:\> ps | format-list -property *
--> show all properties of each process.

PS C:\> ps -name nc | % {stop-process $_}
--> % is a alias for ForEach-Object a super useful cmdlet for interacting with pipelines. In the example the current object is refered
to as $_ . We can have multiple commands inside {} just seperate them with semicolons.

PS C:\> get-service | ? {$_.status -eq running}
--> ? is a alias for where-object it takes input whole bunch of objects and lets us select out specific items that are full whole objects that we can work with.

PS C:\> get-service | select servicename, displayname
--> it takes input of bunch of objects then it manipulate those objects and creates new objects that have a subset of properties and methods that are fed in.
```
## Searching for files and Directories
```
PS C:\> get-childitem -recurse [dir] [string] | % {echo $_.fullname}
PS C:\> ls -r [dir] [string] | % {echo $_.fullname}
--> to find a file with [string] in its name 
example --> PS C:\> ls -r c:\ wmic.exe | % {echo $_.fullname}

PS C:\> ls -r c:\ wmic.exe 2>$null | % {echo $_.fullname}
--> 2>$null is like /dev/null in linux to throw away standard error
```

## Powershell built-in variables
```
PS C:\> ls env:
--> to get list of env variables

PS C:\> ls variable
--> TO get list of all variables 

PS C:\> echo $home
PS C:\> echo $env:PROCESSOR_ARCHITECTURE
```
## Powershell grep like feature
```
PS C:\Users> Select-String -path c:\users\*.txt -pattern password
--> search through .txt files in c:\users to find all files that contain the word "password"(case-insensitive)

PS C:\Users> ls -r c:\users | % {Select-String -path $_  -pattern password} 2>$null
--> Recurse through c:\users to find all files that contain the word "password"
```
## Counting loops
```
PS C:\Users> 1..10 | % {echo $_}

PS C:\Users> 1..255 | % {ping -n 1 10.10.10..$_ | sls ttl}
--> to conduct ping sweep

PS C:\Users> 1..255 | % {echo "10.10.10._$"; ping -n 1 -w 100 10.10.10.$_ | sls ttl}
--> to speed it up a bit
```
## TO display output on screen and paginate it

```
PS C:\Users> ls -r | out-host -paging
--> convert the output in to a text stream instead of series of objects.
```
## Port scan using built in capabilities
```
PS C:\Users> 1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_ is open" } 2>$null
```
## Web-client to fetch a file from server
```
PS C:\> (New-Object system.net.webclient).DownloadFile("http://10.10.10.10/abc.txt","c:\abc.txt")
```
