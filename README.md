# Get-EventsBySource

##SYNOPSIS
PowerShell Function intended to gather data from Windows events logs - the function Get-EventsBySource is wrapper for Get-WinEvent function

##DESCRIPTION
PowerShell Function intended to gather data from Windows events logs - the function Get-EventsBySource is wrapper for Get-WinEvent function. Generally the HashQuerySet parameter set is used but time span can be constructed based not only on start/end time but also 

Function offer additional capabilities to merge multilines event description (using defined char as a lines separator) and can limit amount of returned 
  
##PARAMETERS
  
### ComputerName
Gets events from the event logs on the specified computer. Type the NetBIOS name, an Internet Protocol (IP) address,
or the fully qualified domain name of the computer. The default value is the local computer.
   
### LogName
Gets events from the specified event logs. Enter the event log names in a comma-separated list.

### ProviderName
Gets events written by the specified event log providers. Enter the provider names in a comma-separated list, or use wildcard characters to create provider name patterns.
An event log provider is a program or service that writes events to the event log. It is not a Windows PowerShell provider.
Please remember that ProviderName is usually not equal with a source for event - please check an event XML to check used provider.

### EventID


### StartTime
Date and time which will be used as the begining of a time period to query

### EndTime
Date and time which will be used as the end of a time period to query

### ForLastTimeSpan
Use number for which logs need to be queried - please select also correct "ForLastTimeUnit" value

### ForLastTimeUnit
Use the name of units for construct query.

### ConcatenateMessageLines
For multilines events description lines will be merged by default. Please change to $false if you would not like this behaviour, than only first line can be handled.

### ConcatenatedLinesSeparator
A char used to separated merged multilines event description. By default "^" is used due that is not usually used in events descriptions.

### MessageCharsAmount
The number of chars which will be returned from event description.

 
##EXAMPLES

###EXAMPLE 1
Get-EventsBySource -ComputerName localhost -LogName application -ProviderName SecurityCenter -EventID 1,16 -ForLastTimeSpan 160 -ForLastTimeUnit minutes

ComputerName  : COMPUTERNAME.wojteks.lab
Source: SecurityCenter
EventID   : 16
TimeGenerated : 10/19/2015 10:48:26 PM
Message   : The Windows Security Center Service could not stop Windows Defender

ComputerName  : COMPUTERNAME.wojteks.lab
Source: SecurityCenter
EventID   : 1
TimeGenerated : 10/19/2015 10:48:23 PM
Message   : The Windows Security Center Service has started

## Base repository
https://github.com/it-praktyk/Get-EvenstBySource
  
##NOTES
   
AUTHOR: Wojciech Sciesinski, wojciech[at]sciesinski[dot]net
		Parameters description partially based on Get-WinEvent help from PowerShell 3.0
AUTHOR's PROFILE: https://www.linkedin.com/in/sciesinskiwojciech

KEYWORDS: Windows, Event logs, PowerShell

##VERSION HISTORY
0.3.1 - 2015-07-03 - Support for time span corrected, the first version published on GitHub
0.3.2 - 2015-07-05 - Help updated, function corrected
0.3.3 - 2015-08-25 - Help updated, to do updated
0.4.0 - 2015-09-08 - Code reformated, Added support for more than one event id, minor update
0.5.0 - 2015-10-19 - Code corrected based on PSScriptAnalyzer 1.1.0 output, support for more than logs (by name) added, help partially updated
 

##TODO
- handle situation like

PS > [Array]$FilterHashTable = @{ "Logname" = "Application"; "Id" = 900; "ProviderName" = "Microsoft-Windows-Security-SPP" }
PS > Get-WinEvent -FilterHashtable $FilterHashTable

PS > Get-WinEvent -FilterHashtable $FilterHashTable
Get-WinEvent : The specified providers do not write events to any of the specified logs.
At line:1 char:1
+ Get-WinEvent -FilterHashtable $FilterHashTable
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo  : InvalidArgument: (:) [Get-WinEvent], Exception
+ FullyQualifiedErrorId : LogsAndProvidersDontOverlap,Microsoft.PowerShell.Commands.GetWinEventCommand


##LICENSE
Copyright (C) 2015 Wojciech Sciesinski
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>