#Requires -Version 4.0
#Resuires -Module ActiveDirectory
#Requires -Module DnsServer

#region help text

<#
.SYNOPSIS
	Sets a DNS Scavenging server for all AD-Integrated Zones, except Trust Anchors.
.DESCRIPTION
	Sets a DNS Scavenging server for all AD-Integrated Zones, except Trust Anchors.

	To run the script from a workstation, RSAT is required.
	
	Remote Server Administration Tools for Windows 8 
		http://www.microsoft.com/en-us/download/details.aspx?id=28972
		
	Remote Server Administration Tools for Windows 8.1 
		http://www.microsoft.com/en-us/download/details.aspx?id=39296
		
	Remote Server Administration Tools for Windows 10
		http://www.microsoft.com/en-us/download/details.aspx?id=45520
		
.PARAMETER ComputerName
	Specifies a computer to use to run the script against and to use as the Scavenging 
	server.
	
	ComputerName can be entered as the NetBIOS name, FQDN, localhost, or IP Address.
	
	If entered as localhost, the actual computer name is determined and used.
	
	If entered as an IP address, an attempt is made to determine and use the actual 
	computer name.
	
	If the name entered is not a Windows DNS server, the domain controller that holds 
	the PDCe FSMO role is found and used if it is also a Windows DNS server.
	
	Once a Windows DNS server is found, its IP address is retrieved. If the selected 
	Windows DNS Server is configured to use both IPv4 and IPv6, the first address in 
	the array is used. Only the Windows servers running Windows DNS care whether an 
	IPv6 or an IPv4 address is used.
	
	The default is localhost.
.PARAMETER Dev
	Clears errors at the beginning of the script.
	Outputs all errors to a text file at the end of the script.
	
	This parameter is used when the script developer requests more troubleshooting data.
	The text file is placed in the same folder from where the script is run.
	
	This parameter is disabled by default.
.PARAMETER Folder
	Specifies the optional output folder to save the output report. 
.PARAMETER Log
	Generates a log file for troubleshooting.
.PARAMETER ScriptInfo
	Outputs information about the script to a text file.
	The text file is placed in the same folder from where the script is run.
	
	This parameter is disabled by default.
	This parameter has an alias of SI.
.EXAMPLE
	PS C:\PSScript > .\Set-DNSScavengeServer.ps1
	
	Tests to see if the computer, localhost, is a DNS server. 
	If it is, the script runs. If not, the script finds the domain controller that has the 
	PDCe FSMO role and uses it, if it is a valid Microsoft DNS server.
.EXAMPLE
	PS C:\PSScript > .\Set-DNSScavengeServer.ps1 -ComputerName DNS01
	
	Runs the script against the DNS server named DNS01, if it is a valid Microsoft DNS server.
.EXAMPLE
	PS C:\PSScript > .\Set-DNSScavengeServer.ps1 -Folder \\FileServer\ShareName
	
	Tests to see if the computer, localhost, is a DNS server. 
	If it is, the script runs. If not, the script finds the domain controller that has the 
	PDCe FSMO role and uses it, if it is a valid Microsoft DNS server.

	Output file is saved in the path \\FileServer\ShareName
.INPUTS
	None.  You cannot pipe objects to this script.
.OUTPUTS
	No objects are output from this script.  
	This script creates a Text file that shows the Before and After of any changes made.
.NOTES
	NAME: Set-DNSScavengeServer.ps1
	VERSION: 1.00
	AUTHOR: Carl Webster with a code review by Michael B. Smith
	LASTEDIT: November 1, 2019
#>

#endregion

#region script parameters
[CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = "Medium", DefaultParameterSetName = "") ]

Param(
	[parameter(Mandatory=$False)] 
	[string]$ComputerName="LocalHost",

	[parameter(Mandatory=$False)] 
	[Switch]$Dev=$False,
	
	[parameter(Mandatory=$False)] 
	[string]$Folder="",
	
	[parameter(Mandatory=$False)] 
	[Switch]$Log=$False,
	
	[parameter(Mandatory=$False)] 
	[Alias("SI")]
	[Switch]$ScriptInfo=$False
	
	)
#endregion

#region script change log	
#Created by Carl Webster with a code review by Michael B. Smith
#webster@carlwebster.com
#@carlwebster on Twitter
#https://www.CarlWebster.com
#
#michael@smithcons.com
#@essentialexch on Twitter
#https://www.essential.exchange/blog/
#
#Created on October 5, 2019
#Version 1.00 released to the community on 1-Nov-2019
#endregion

#region initial variable testing and setup
Set-StrictMode -Version Latest

#force on
$PSDefaultParameterValues = @{"*:Verbose"=$True}
$SaveEAPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$ConfirmPreference = "High"

If($Folder -ne "")
{
	Write-Verbose "$(Get-Date): Testing folder path"
	#does it exist
	If(Test-Path $Folder -EA 0)
	{
		#it exists, now check to see if it is a folder and not a file
		If(Test-Path $Folder -pathType Container -EA 0)
		{
			#it exists and it is a folder
			Write-Verbose "$(Get-Date): Folder path $Folder exists and is a folder"
		}
		Else
		{
			#it exists but it is a file not a folder
			Write-Error "
			`n`n
			`tFolder $Folder is a file, not a folder.
			`n`n
			`tScript cannot continue.
			`n`n"
			Exit
		}
	}
	Else
	{
		#does not exist
		Write-Error "
		`n`n
		`tFolder $Folder does not exist.
		`n`n
		`tScript cannot continue.
		`n`n"
		Exit
	}
	$Script:pwdpath = $Folder
}
Else
{
	$Script:pwdpath = $pwd.Path
}

If($Log) 
{
	#start transcript logging
	$Script:LogPath = Join-Path $Script:pwdpath "DNSScavengeScriptTranscript_$(Get-Date -f yyyy-MM-dd_HHmm).txt"
	
	try 
	{
		Start-Transcript -Path $Script:LogPath -Force -Verbose:$false | Out-Null
		Write-Verbose "$(Get-Date): Transcript/log started at $Script:LogPath"
		$Script:StartLog = $true
	} 
	catch 
	{
		Write-Verbose "$(Get-Date): Transcript/log failed at $Script:LogPath"
		$Script:StartLog = $false
	}
}

If($Dev)
{
	$Error.Clear()
	$Script:DevErrorFile = Join-Path $Script:pwdpath "DNSScavengeScriptErrors_$(Get-Date -f yyyy-MM-dd_HHmm).txt"
}

Function TestComputerName
{
	Param([string]$Cname)

	#if computer name is localhost, get actual computer name
	If($CName -eq "localhost")
	{
		$CName = $env:ComputerName
		Write-Verbose "$(Get-Date): Computer name has been changed from localhost to $CName"
	}

	#if computer name is an IP address, get host name from DNS
	#http://blogs.technet.com/b/gary/archive/2009/08/29/resolve-ip-addresses-to-hostname-using-powershell.aspx
	#help from Michael B. Smith
	$ip = $CName -as [System.Net.IpAddress]
	If($ip)
	{
		$Result = [System.Net.Dns]::gethostentry($ip).AddressList.IPAddressToString
		
		If($? -and $Null -ne $Result)
		{
			$CName = $Result.HostName
			Write-Verbose "$(Get-Date): Computer name has been changed from $($ip) to $CName"
		}
		Else
		{
			Write-Warning "Unable to resolve $CName to a hostname"
			$CName = $Null
		}
	}
	Else
	{
		#computer is online but for some reason $ComputerName cannot be converted to a System.Net.IpAddress
	}

	If([String]::IsNullOrEmpty($CName))
	{
		$ErrorActionPreference = $SaveEAPreference
		Write-Error "
		`n`n
		`t`t
		Unable to determine the Computer Name parameter.
		`n`n
		`t`t
		Rerun the script using -ComputerName with a valid DNS server name.
		`n`n
		`t`t
		Script cannot continue.
		`n`n"
		Exit
	}

	#get computer name
	#first test to make sure the computer is reachable
	Write-Verbose "$(Get-Date): Testing to see if $CName is online and a DNS Server"
	If(Test-NetConnection -ComputerName $CName -InformationLevel Quiet -Port 53 -ea 0 3>$Null)
	{
		Write-Verbose "$(Get-Date): Server $CName is online and a DNS Server."
	}
	Else
	{
		Write-Verbose "$(Get-Date): Computer $CName is either offline or not a DNS Server"
		Write-Verbose "$(Get-Date): Finding the Domain Controller with the PDCe FSMO role"
		$Results = Get-ADDomain -EA 0 3>$Null
		
		If(-Not $? -or $Null -eq $Results)
		{
			$ErrorActionPreference = $SaveEAPreference
			Write-Error "
			`n`n
			`t`t
			Unable to find the PDCe domain controller.
			`n`n
			`t`t
			Rerun the script using -ComputerName with a valid DNS server name.
			`n`n
			`t`t
			Script cannot continue.
			`n`n"
			Exit
		}
		
		$CName = $results.PDCEmulator

		Write-Verbose "$(Get-Date): Testing to see if $CName is online and a DNS Server"
		If(Test-NetConnection -ComputerName $CName -InformationLevel Quiet -Port 53 -ea 0 3>$Null)
		{
			Write-Verbose "$(Get-Date): Server $CName is online and a DNS Server."
		}
		Else
		{
			Write-Verbose "$(Get-Date): Computer $CName is either offline or not a DNS Server"
			$ErrorActionPreference = $SaveEAPreference
			Write-Error "
			`n`n
			`t`t
			Rerun the script using -ComputerName with a valid DNS server name.
			`n`n
			`t`t
			Script cannot continue.
			`n`n"
			Exit
		}
	}

	Write-Verbose "$(Get-Date): Retrieving DNS data from $CName"
	$Results = Get-DNSServer -ComputerName $CName -EA 0 3>$Null
		
	If(-Not $? -or $Null -eq $results)
	{
		Write-Error "
		`n`n
		`t`t
		Can't get DNS info for script
		`n`n
		`t`t
		Script cannot continue.
		`n`n"
		Exit
	}
	Else
	{
		$Script:DNSResults = $Results
	}

	Return $CName
}

Function ShowScriptOptions
{
	Write-Verbose "$(Get-Date): "
	Write-Verbose "$(Get-Date): "
	Write-Verbose "$(Get-Date): ComputerName       : $($ComputerName)"
	Write-Verbose "$(Get-Date): Dev                : $($Dev)"
	If($Dev)
	{
		Write-Verbose "$(Get-Date): DevErrorFile       : $($Script:DevErrorFile)"
	}
	Write-Verbose "$(Get-Date): Folder             : $($Script:pwdpath)"
	Write-Verbose "$(Get-Date): Log                : $($Log)"
	Write-Verbose "$(Get-Date): ScriptInfo         : $($ScriptInfo)"
	Write-Verbose "$(Get-Date): "
	Write-Verbose "$(Get-Date): OS Detected        : $($Script:RunningOS)"
	Write-Verbose "$(Get-Date): PoSH version       : $($Host.Version)"
	Write-Verbose "$(Get-Date): PSCulture          : $($PSCulture)"
	Write-Verbose "$(Get-Date): PSUICulture        : $($PSUICulture)"
	Write-Verbose "$(Get-Date): "
	Write-Verbose "$(Get-Date): Script start       : $($Script:StartTime)"
	Write-Verbose "$(Get-Date): "
	Write-Verbose "$(Get-Date): "
}

Function ProcessScriptEnd
{
	Write-Verbose "$(Get-Date): Script has completed"
	Write-Verbose "$(Get-Date): "

	#http://poshtips.com/measuring-elapsed-time-in-powershell/
	Write-Verbose "$(Get-Date): Script started: $($Script:StartTime)"
	Write-Verbose "$(Get-Date): Script ended: $(Get-Date)"
	$runtime = $(Get-Date) - $Script:StartTime
	$Str = [string]::format("{0} days, {1} hours, {2} minutes, {3}.{4} seconds",
		$runtime.Days,
		$runtime.Hours,
		$runtime.Minutes,
		$runtime.Seconds,
		$runtime.Milliseconds)
	Write-Verbose "$(Get-Date): Elapsed time: $($Str)"

	If($Dev)
	{
		If($SmtpServer -eq "")
		{
			Out-File -FilePath $Script:DevErrorFile -InputObject $error 4>$Null
		}
		Else
		{
			Out-File -FilePath $Script:DevErrorFile -InputObject $error -Append 4>$Null
		}
		Write-Verbose "$(Get-Date): $Script:DevErrorFile is ready for use"
	}

	If($ScriptInfo)
	{
		$SIFile = "$($pwd.Path)\DNSScavengeScriptInfo_$(Get-Date -f yyyy-MM-dd_HHmm).txt"
		Out-File -FilePath $SIFile -InputObject "" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "ComputerName       : $($ComputerName)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "Dev                : $($Dev)" 4>$Null
		If($Dev)
		{
			Out-File -FilePath $SIFile -Append -InputObject "DevErrorFile       : $($Script:DevErrorFile)" 4>$Null
		}
		Out-File -FilePath $SIFile -Append -InputObject "Folder             : $($Script:pwdpath)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "Log                : $($Log)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "Script Info        : $($ScriptInfo)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "OS Detected        : $($Script:RunningOS)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "PoSH version       : $($Host.Version)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "PSCulture          : $($PSCulture)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "PSUICulture        : $($PSUICulture)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "Script start       : $($Script:StartTime)" 4>$Null
		Out-File -FilePath $SIFile -Append -InputObject "Elapsed time       : $($Str)" 4>$Null
		Write-Verbose "$(Get-Date): $SIFile is ready for use"
	}

	#stop transcript logging
	If($Log -eq $True) 
	{
		If($Script:StartLog -eq $true) 
		{
			try 
			{
				Stop-Transcript | Out-Null
				Write-Verbose "$(Get-Date): $Script:LogPath is ready for use"
			} 
			catch 
			{
				Write-Verbose "$(Get-Date): Transcript/log stop failed"
			}
		}
	}
	$ErrorActionPreference = $SaveEAPreference
}

$script:startTime = Get-Date
[string]$Script:RunningOS = (Get-WmiObject -class Win32_OperatingSystem -EA 0).Caption

ShowScriptOptions

$ScavengingResults = New-Object System.Collections.ArrayList
$ScavengingServer = TestComputerName $ComputerName
$ScavengingServerIP = ([System.Net.Dns]::gethostentry($ScavengingServer)).AddressList.IPAddressToString

#Get only AD_Integrated zones, but not the one name TrustAnchors
Write-Verbose "$(Get-Date): Retrieving AD-Integrated DNS Zones"
$ADZones = $Script:DNSResults.ServerZone | Where-Object {$_.IsDsIntegrated -and $_.ZoneName -ne "TrustAnchors"}

#Sort by zone name
$ADZones = $ADZones | Sort-Object $ADZones.ZoneName

#clear the error stack
$error.Clear()

ForEach($ADZone in $ADZones)
{
	Write-Verbose "$(Get-Date): Processing DNS Zone $($ADZone.ZoneName)"
	
	#Get current scavenging information
	$Results = Get-DnsServerZoneAging -ComputerName $ScavengingServer -Name $ADZone.ZoneName -EA 0 4> $Null

	If($?)
	{
		$obj = [PSCustomObject] @{
			BeforeAfter     = "Before Change"
			ZoneName        = $ADZone.ZoneName
			AgingEnabled    = $Results.AgingEnabled
			ScavengeServers = $Results.ScavengeServers
		}
		$null = $ScavengingResults.Add($obj)
	}
	Else
	{
		$obj = [PSCustomObject] @{
			BeforeAfter     = "Before Change"
			ZoneName        = $ADZone.ZoneName
			AgingEnabled    = "Failed to retrieve data"
			ScavengeServers = "Failed to retrieve data - check $error"
		}
		$null = $ScavengingResults.Add($obj)
	}
	
	If($PSCmdlet.ShouldProcess($ADZone.ZoneName,'Set Scavenging Server'))
	{
		Try
		{
			$Results = Set-DnsServerZoneAging -Aging $True -ComputerName $ScavengingServer -Name $ADZone.ZoneName -PassThru -ScavengeServers $ScavengingServerIP -EA 0 4> $Null

			#worked
			Write-Verbose "$(Get-Date): `tZone $($ADZone.ZoneName) was successfully configured for Scavenging"

			$obj = [PSCustomObject] @{
				BeforeAfter     = "After Change"
				ZoneName        = $ADZone.ZoneName
				AgingEnabled    = $Results.AgingEnabled
				ScavengeServers = $Results.ScavengeServers
			}
			$null = $ScavengingResults.Add($obj)
		}
		
		Catch
		{
			#oops
			Write-Verbose "$(Get-Date): `tZone $($ADZone.ZoneName) was not configured for Scavenging"

			$obj = [PSCustomObject] @{
				BeforeAfter     = "After Change"
				ZoneName        = $ADZone.ZoneName
				AgingEnabled    = "Failed"
				ScavengeServers = "Failed- check $error"
			}
			$null = $ScavengingResults.Add($obj)
		}
	}
}

$File = Join-Path $Script:pwdpath "DNSScavengeScriptResults.txt"
Out-File -FilePath $File -Encoding ASCII -Force -InputObject $ScavengingResults *>$Null
Write-Verbose "$(Get-Date): $File is ready for use"

ProcessScriptEnd
