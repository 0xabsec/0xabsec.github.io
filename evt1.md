---
layout: default
---
# Working with Event Logs using Powershell
Microsoft has two commands for interrogating Windows event logs: 
```
Get-WinEvent 
Get-EventLog
```
Get-EventLog cmdlet uses a Win32 API that has been deprecated. Microsoft recommends using Get-WinEvent
## Listing Event Log Sources
```
PS C:\> Get-WinEvent -ListLog *
PS C:\> Get-WinEVent -ListLog * | Where-Object -Property RecordCount -GT 0 | Select-Object -Property LogName, RecordCount
----> We can use the pipeline and Where-Object to filter the results to show log sources where logging events are available
```
## Retrieving Log Data
```
PS C:\> Get-WinEvent -Logname Security
PS C:\> Get-WinEvent -Logname Security | format-list
-----> Format-List to see the results with each property is listed on a new line

PS C:\> Get-WinEvent -LogName Security -MaxEvents 1 | Get-Member -MemberType Property
----> I added -MaxEvents 1 to the Get-WinEvent command. Without this, Get-WinEvent will retrieve all events from the specified Security event log source before sending the output to the pipeline and Get-Member, Instructing Get-WinEvent to stop collecting events after the first event gets the property information we want without waiting to collect all event log data.

PS C:\> Get-WinEvent -LogName Security -MaxEvents 1 | Select-Object -Property *
---->  Often get property information by looking at the actual values with Select-Object as well
```
## Filtering Event Logs with the Pipeline
```
PS C:\> Get-WinEvent -LogName Security | Where-Object -Property Id -EQ 1102 | Format-List -Property TimeCreated,Message
```
> Not Ideal , takes lot of time and Resources

##  Filtering Event Logs with FilterHashTable
```
PS C:\> Get-WinEvent -FilterHashTable @{LogName='Security'; ID=1100 } | Format-List -Property Timecreated,Message
----> Get-WinEvent can filter using a filter hash table. A hash table (a.k.a. associative array or dictionary) is a mechanism to specify properties and values. When used with the -FilterHashTable option, we can specify attributes to filter the events returned in an optimal manner without relying on the PowerShell pipeline
```
> When using -FilterHashTable, you must specify a LogName in the hash table, not using the -LogName cmdlet argument.
```
PS C:\> $startdate = Get-Date (date in mm/dd/yy)
PS C:\> $enddate = Get-Date (date in mm/dd/yy)
PS C:\> Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startDate; EndTime=$enddate}
```

[Content took from](https://www.sans.org/blog/working-with-event-log-part-1/)
