Function Get-EventsBySource {
<#
	.SYNOPSIS
	Function intended for remote gathering events data
    
    .DESCRIPTION
    Function intended to gather data from Windows events logs - Get-WinEvent is used
  
	.PARAMETER ComputerName
   
	.PARAMETER LogName
	
	.PARAMETER ProviderName
	
	.PARAMETER EventID
    
    .PARAMETER StartTime
    
    .PARAMETER EndTime
    
    .PARAMETER ForLastTimeSpan
    
    .PARAMETER ForLastTimeUnit
	
	.PARAMETER ConcatenateMessageLines
	
	.PARAMETER ConcatenatedLinesSeparator
	
	.PARAMETER MessageCharsAmount
	 
    .EXAMPLE
    Get-EventsBySource
         
    .LINK
    https://github.com/it-praktyk/Get-EvenstBySource
    
    .LINK
    https://www.linkedin.com/in/sciesinskiwojciech
          
    .NOTES
   
    AUTHOR: Wojciech Sciesinski, wojciech.sciesinski@atos.net
    KEYWORDS: Windows, Event logs
    VERSION HISTORY
    0.3.1 - 2015-07-03 - Support for time span corrected, the first version published on GitHub
    0.3.2 - 2015-07-05 - Help updated, function corrected
    0.3.3 - 2015-08-25 - Help updated, to do updated
    

    TODO
    - help update needed
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
   
#>

[CmdletBinding()] 

param(
	[parameter(mandatory=$true)]
	[String]$ComputerName,
	
	[parameter(mandatory=$true)]
	[String]$LogName,
	
	[parameter(mandatory=$true)]
	[String]$ProviderName,
	
	[parameter(mandatory=$true)]
	[Int]$EventID,
	
	[parameter(mandatory=$false,ParameterSetName="StartEndTime")]
	[DateTime]$StartTime,
	
	[parameter(mandatory=$false,ParameterSetName="StartEndTime")]
	[DateTime]$EndTime,
	
	[parameter(mandatory=$false,ParameterSetName="ForLast")]
	[int]$ForLastTimeSpan=24,
	
	[parameter(mandatory=$false,ParameterSetName="ForLast")]
	[ValidateSet("minutes","hours","days")]
	[string]$ForLastTimeUnit="hours",

    [parameter(mandatory=$false)]
    [Bool]$ConcatenateMessageLines=$true,

    [parameter(mandatory=$false)]
    [String]$ConcatenatedLinesSeparator="^",

    [parameter(mandatory=$false)]
    [Int]$MessageCharsAmount=-1

)

BEGIN {

    $Results=@()

}

PROCESS {

        $SkipServer = $false
        
        Try {

            Write-Verbose -Message "Checking logs on the server $ComputerName"
            
            If ($StartTime -ne $null -or $EndTime -ne $null) {
                
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
            
            elseif ($ForLastTimeSpan -ne $null -or $ForLastTimeSpan -ne $null) {
                
                $EndTime = Get-Date
                
                switch ($ForLastTimeUnit) {
                    "minutes" {
                        
                        $StartTime = $EndTime.AddMinutes(-$ForLastTimeSpan)
                        
                    }
                    "hours" {
                        
                        $StartTime = $EndTime.AddHours(-$ForLastTimeSpan)
                        
                    }
                    "days" {
                        
                        $StartTime = $EndTime.AddDays(-$ForLastTimeSpan)
                        
                    }
                    
                }
                
                [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName; "StartTime" = $StartTime; "EndTime" = $EndTime }
            
            
            }
            
            Else {
                
                [Array]$FilterHashTable = @{ "Logname" = $LogName; "Id" = $EventID; "ProviderName" = $ProviderName }
                
            }
            
            $Events = $(Get-WinEvent -ComputerName $ComputerName -FilterHashtable $FilterHashTable -ErrorAction 'SilentlyContinue' | Select-Object -Property MachineName,Providername,ID,TimeCreated,Message)

        }

        Catch {

            Write-Verbose -Message "Computer $ComputerName not accessible or error with access to $LogName event log."

			[Bool]$SkipServer = $true

		}

        Finally {


			If ( -not $SkipServer ) {
            

				$Found = $( $Events | Measure-Object).Count
                
                If ($Found -ne 0) {
                    
                    [String]$MessageText = "For the computer $ComputerName events $Found found"

					Write-Verbose -Message $MessageText

					$Events | ForEach  { 
	
						$Result = New-Object -TypeName PSObject		
						$Result | Add-Member -type NoteProperty -name ComputerName -value $_.MachineName
						$Result | Add-Member -type NoteProperty -name Source -value $_.Providername
						$Result | Add-Member -type NoteProperty -name EventID -Value $_.ID
						$Result | Add-Member -type NoteProperty -name TimeGenerated -Value $_.TimeCreated
         
						$MessageLength = $($_.Message).Length
	
						If ( ($MessageCharsAmount -eq -1) -or $MessageCharsAmount -gt $MessageLength ) {

							$MessageCharsAmount = $MessageLength

						}
 	
						if ( $ConcatenateMessageLines ) {
						
							$MessageFields = $_.Message.Substring(0,$MessageCharsAmount-1).Replace("`r`n",$ConcatenatedLinesSeparator)

							$Result | Add-Member -type NoteProperty -name Message -Value $MessageFields

						}
 						else {

							$Result | Add-Member -type NoteProperty -name Message -Value $_.Message.Substring(0,$MessageCharsAmount-1)

						}

						$Results+=$Result

					}
			
				}
	    
			}

        }

}


END {

    Return $Results

    }

}