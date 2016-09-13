Function Get-EventsBySource {
<#
    .SYNOPSIS
    Function intended to gather data from Windows events logs - the function Get-EventsBySource is wrapper for Get-WinEvent function
    
    .DESCRIPTION
    Function intended to gather data from Windows events logs - the function Get-EventsBySource is wrapper for Get-WinEvent function. Generally
    the HashQuerySet parameter set is used but time span can be constructed based not only on start/end time but also 
    
    Function offer additional capabilities to merge multilines event description (using defined char as a lines separator)
    and can limit amount of returned 
         
    .PARAMETER LogName
    Gets events from the specified event logs. Enter the event log names in a comma-separated list.
    
    .PARAMETER ProviderName
    Gets events written by the specified event log providers. Enter the provider names in a comma-separated list, or use wildcard characters to create provider name patterns.
    An event log provider is a program or service that writes events to the event log. It is not a Windows PowerShell provider.
    Please remember that ProviderName is usually not equal with a source for event - please check an event XML to check used provider.
    
    .PARAMETER EventID
    Number of event what need to be returned.
    
    .PARAMETER EventSeverity
    Severity of events. Severity can be the names
    
    .PARAMETER ComputerName
    Gets events from the event logs on the specified computer. Type the NetBIOS name, an Internet Protocol (IP) address,
    or the fully qualified domain name of the computer. The default value is the local computer.  
    
    .PARAMETER StartTime
    Date and time which will be used as the begining of a time period to query
    
    .PARAMETER EndTime
    Date and time which will be used as the end of a time period to query
    
    .PARAMETER ForLastTimeSpan
    Use number for which logs need to be queried - please select also correct "ForLastTimeUnit" value
    
    .PARAMETER ForLastTimeUnit
    Use the name of units for construct query.
    
    .PARAMETER ConcatenateMessageLines
    For multilines events description lines will be merged by default. Please change to $false if you would not like this behaviour, than only first line can be handled.
    
    .PARAMETER ConcatenatedLinesSeparator
    A char used to separated merged multilines event description. By default "^" is used due that is not usually used in events descriptions.
    
    .PARAMETER MessageCharsAmount
    The number of chars which will be returned from event description.
     
    .EXAMPLE
    Get-EventsBySource -ComputerName localhost -LogName application -ProviderName SecurityCenter -EventID 1,16 -ForLastTimeSpan 160 -ForLastTimeUnit minutes

    ComputerName  : COMPUTERNAME.wojteks.lab
    Source        : SecurityCenter
    EventID       : 16
    Severity      : Verbose
    TimeGenerated : 10/19/2015 10:48:26 PM
    Message       : The Windows Security Center Service could not stop Windows Defender

    ComputerName  : COMPUTERNAME.wojteks.lab
    Source        : SecurityCenter
    EventID       : 1
    Severity      : Verbose
    TimeGenerated : 10/19/2015 10:48:23 PM
    Message       : The Windows Security Center Service has started
    
    .EXAMPLE
    Get-EventsBySource -ComputerName X2-REM-23 -LogName System -ProviderName Microsoft-Windows-DNS-Client -Severity Information,3
    
    
    
    
    .LINK
    https://github.com/it-praktyk/Get-EvenstBySource
    
    .LINK
    https://www.linkedin.com/in/sciesinskiwojciech
          
    .NOTES
   
    AUTHOR: Wojciech Sciesinski, wojciech[at]sciesinski[dot]net
            Parameters description partially based on Get-WinEvent help from PowerShell 3.0
    
    KEYWORDS: Windows, Event logs, PowerShell
    
    VERSION HISTORY
    - 0.3.1 - 2015-07-03 - Support for time span corrected, the first version published on GitHub
    - 0.3.2 - 2015-07-05 - Help updated, function corrected
    - 0.3.3 - 2015-08-25 - Help updated, to do updated
    - 0.4.0 - 2015-09-08 - Code reformated, Added support for more than one event id, minor update
    - 0.5.0 - 2015-10-19 - Code corrected based on PSScriptAnalyzer 1.1.0 output, support for more than logs (by name) added, help partially updated
	- 0.6.0 - 2016-09-13 - Added support to get logs by event level/severity, the license changed to MIT
                         

    TODO
    - update help
    - rewrite section for creating filter hashtable
    - handle situation like
        
    PS > [Array]$FilterHashTable = @{ "Logname" = "Application"; "Id" = 900; "ProviderName" = "Microsoft-Windows-Security-SPP" }
    PS > Get-WinEvent -FilterHashtable $FilterHashTable
    
    PS > Get-WinEvent -FilterHashtable $FilterHashTable
    Get-WinEvent : The specified providers do not write events to any of the specified logs.
    At line:1 char:1
    + Get-WinEvent -FilterHashtable $FilterHashTable
    + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (:) [Get-WinEvent], Exception
    + FullyQualifiedErrorId : LogsAndProvidersDontOverlap,Microsoft.PowerShell.Commands.GetWinEventCommand
    
        
    LICENSE  
    Copyright (c) 2016 Wojciech Sciesinski  
    This function is licensed under The MIT License (MIT)  
    Full license text: https://opensource.org/licenses/MIT  
   
#>
    
    [CmdletBinding(DefaultParameterSetName = "ByEventID")]
    [OutputType("System.Object[]")]
    param (
        [parameter(mandatory = $true)]
        [String[]]$LogName,
        [parameter(mandatory = $true)]
        [String]$ProviderName,
        [parameter(mandatory = $true, ParameterSetName = "ByEventID")]
        [alias("ID")]
        [Int[]]$EventID,
        [Parameter(Mandatory = $true, ParameterSetName = "ByEventSeverity")]
        [alias("Severity", "Level", "LevelDisplayName")]
        [ValidateSet("Information", "0", "Critical", "1", "Error", "2", "Warning", "3", "Verbose","4")]
        [String[]]$EventSeverity,
        [parameter(mandatory = $false)]
        [String]$ComputerName = "localhost",
        [parameter(mandatory = $false, ParameterSetName = "StartEndTime")]
        [parameter(mandatory = $false, ParameterSetName = "ByEventID")]
        [Parameter(Mandatory = $false, ParameterSetName = "ByEventSeverity")]
        [Nullable[DateTime]]$StartTime = $null,
        [parameter(mandatory = $false, ParameterSetName = "StartEndTime")]
        [parameter(mandatory = $false, ParameterSetName = "ByEventID")]
        [Parameter(Mandatory = $false, ParameterSetName = "ByEventSeverity")]
        [Nullable[DateTime]]$EndTime = $null,
        [parameter(mandatory = $false, ParameterSetName = "ForLast")]
        [parameter(mandatory = $false, ParameterSetName = "ByEventID")]
        [Parameter(Mandatory = $false, ParameterSetName = "ByEventSeverity")]
        [int]$ForLastTimeSpan = 24,
        [parameter(mandatory = $false, ParameterSetName = "ForLast")]
        [parameter(mandatory = $false, ParameterSetName = "ByEventID")]
        [Parameter(Mandatory = $false, ParameterSetName = "ByEventSeverity")]
        [ValidateSet("minutes", "hours", "days")]
        [string]$ForLastTimeUnit = "hours",
        [parameter(mandatory = $false)]
        [Switch]$ConcatenateMessageLines,
        [parameter(mandatory = $false)]
        [String]$ConcatenatedLinesSeparator = "^",
        [parameter(mandatory = $false)]
        [Int]$MessageCharsAmount = -1
        
    )
    
    BEGIN {
        
        $Results = New-Object System.Collections.ArrayList
        
    }
    
    PROCESS {
        
        Try {
            
            Write-Verbose -Message "Checking logs on the server $ComputerName"
            
            switch ($PsCmdlet.ParameterSetName) {
                
                "ByEventID" {
                    
                    
                    If ($null -ne $StartTime -or $EndTime -ne $null) {
                        
                        If ($StartTime -and $EndTime) {
                            
                            [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName; "StartTime" = $StartTime; "EndTime" = $EndTime }
                            
                        }
                        Elseif ($EndTime) {
                            
                            [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName; "EndTime" = $EndTime }
                            
                        }
                        Else {
                            
                            [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName; "StartTime" = $StartTime }
                            
                        }
                        
                    }
                    
                    elseif ($null -ne $ForLastTimeSpan -or $null -ne $ForLastTimeUnit) {
                        
                        $EndTime = Get-Date
                        
                        switch ($ForLastTimeUnit) {
                            "minutes" {
                                
                                $StartTime = $EndTime.AddMinutes(- $ForLastTimeSpan)
                                
                            }
                            "hours" {
                                
                                $StartTime = $EndTime.AddHours(- $ForLastTimeSpan)
                                
                            }
                            "days" {
                                
                                $StartTime = $EndTime.AddDays(- $ForLastTimeSpan)
                                
                            }
                            
                        }
                        
                        [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName; "StartTime" = $StartTime; "EndTime" = $EndTime }
                        
                        
                    }
                    
                    Else {
                        
                        [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName }
                        
                    }
                    
                }
                
                "ByEventSeverity" {
                    
                    
                    #Replace severity descriptions with level numbers
                    
                    $EventLevels = @()
                    
                    ForEach ($EventSeverity1 in $EventSeverity) {
                        
                        $EventLevels += ((((($EventSeverity1).Replace("Information", 0)).Replace("Critical", 1)).Replace("Error", 2)).Replace("Warning", 3)).Replace("Verbose", 4)
                        
                    }
                    
                    If ($null -ne $StartTime -or $null -ne $EndTime) {
                        
                        If ($StartTime -and $EndTime) {
                            
                            [Array]$FilterHashTable = @{ "Logname" = $LogName; "Level" = $EventLevels; "ProviderName" = $ProviderName; "StartTime" = $StartTime; "EndTime" = $EndTime }
                            
                        }
                        Elseif ($EndTime) {
                            
                            [Array]$FilterHashTable = @{ "Logname" = $LogName; "Level" = $EventLevels; "ProviderName" = $ProviderName; "EndTime" = $EndTime }
                            
                        }
                        Else {
                            
                            [Array]$FilterHashTable = @{ "Logname" = $LogName; "Level" = $EventLevels; "ProviderName" = $ProviderName; "StartTime" = $StartTime }
                            
                        }
                        
                    }
                    
                    elseif ($null -ne $ForLastTimeSpan -or $null -ne $ForLastTimeUnit) {
                        
                        $EndTime = Get-Date
                        
                        switch ($ForLastTimeUnit) {
                            "minutes" {
                                
                                $StartTime = $EndTime.AddMinutes(- $ForLastTimeSpan)
                                
                            }
                            "hours" {
                                
                                $StartTime = $EndTime.AddHours(- $ForLastTimeSpan)
                                
                            }
                            "days" {
                                
                                $StartTime = $EndTime.AddDays(- $ForLastTimeSpan)
                                
                            }
                            
                        }
                        
                        [Array]$FilterHashTable = @{ "Logname" = $LogName; "Level" = $EventLevels; "ProviderName" = $ProviderName; "StartTime" = $StartTime; "EndTime" = $EndTime }
                        
                        
                    }
                    
                    Else {
                        
                        [Array]$FilterHashTable = @{ "Logname" = $LogName; "Level" = $EventLevels; "ProviderName" = $ProviderName }
                        
                    }
                    
                }
                
                
            }
            
            
            $Events = $(Get-WinEvent -ComputerName $ComputerName -FilterHashtable $FilterHashTable -ErrorAction 'SilentlyContinue' | Select-Object -Property MachineName, Providername, ID, TimeCreated, Message, LevelDisplayName)
            
        }
        
        Catch {
            
            Write-Verbose -Message "Computer $ComputerName not accessible or error with access to $LogName event log."
            
            Continue
            
        }
        
        Finally {
            
            $Found = $($Events | Measure-Object).Count
            
            If ($Found -ne 0) {
                
                [String]$MessageText = "For the computer $ComputerName events $Found found"
                
                Write-Verbose -Message $MessageText
                
                $Events | ForEach-Object -Process {
                    
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -type NoteProperty -name ComputerName -value $_.MachineName
                    $Result | Add-Member -type NoteProperty -name Source -value $_.Providername
                    $Result | Add-Member -type NoteProperty -name EventID -Value $_.ID
                    $Result | Add-Member -Type NoteProperty -Name Severity -Value $_.LevelDisplayName
                    $Result | Add-Member -type NoteProperty -name TimeGenerated -Value $_.TimeCreated
                    
                    $MessageLength = $($_.Message).Length
                    
                    If (($MessageCharsAmount -eq -1) -or $MessageCharsAmount -gt $MessageLength) {
                        
                        $MessageCharsAmount = $MessageLength
                        
                    }
                    
                    if ($ConcatenateMessageLines.IsPresent) {
                        
                        $MessageFields = $_.Message.Substring(0, $MessageCharsAmount - 1).Replace("`r`n", $ConcatenatedLinesSeparator)
                        
                        $Result | Add-Member -type NoteProperty -name Message -Value $MessageFields
                        
                    }
                    else {
                        
                        $Result | Add-Member -type NoteProperty -name Message -Value $_.Message.Substring(0, $MessageCharsAmount - 1)
                        
                    }
                    
                    $Results.Add($Result) | Out-Null
                    
                }
                
            }
            
        }
        
    }
    
    
    END {
        
        Return $Results
        
    }
    
}