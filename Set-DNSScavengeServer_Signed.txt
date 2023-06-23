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

# SIG # Begin signature block
# MIIf8QYJKoZIhvcNAQcCoIIf4jCCH94CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjdaWg6Uqns/aoDpm/Gjl1xXR
# bdOgghtYMIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0B
# AQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg
# +XESpa7cJpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lT
# XDGEKvYPmDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5
# a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g
# 0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1
# roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whf
# GHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3
# cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmr
# EthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+
# fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5Q
# Z7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu
# 838fYxAe+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw
# 8jCCBSYwggQOoAMCAQICEAZY+tvHeDVvdG/HsafuSKwwDQYJKoZIhvcNAQELBQAw
# cjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVk
# IElEIENvZGUgU2lnbmluZyBDQTAeFw0xOTEwMTUwMDAwMDBaFw0yMDEyMDQxMjAw
# MDBaMGMxCzAJBgNVBAYTAlVTMRIwEAYDVQQIEwlUZW5uZXNzZWUxEjAQBgNVBAcT
# CVR1bGxhaG9tYTEVMBMGA1UEChMMQ2FybCBXZWJzdGVyMRUwEwYDVQQDEwxDYXJs
# IFdlYnN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCib5DeGTG
# 3J70a2CA8i9n+dPsDklvWpkUTAuZesMTdgYYYKJTsaaNY/UEAHlJukWzaoFQUJc8
# cf5mUa48zGHKjIsFRJtv1YjaeoJzdLBWiqSaI6m3Ttkj8YqvAVj7U3wDNc30gWgU
# eJwPQs2+Ge6tVHRx7/Knzu12RkJ/fEUwoqwHyL5ezfBHfIf3AiukAxRMKrsqGMPI
# 20y/mc8oiwTuyCG9vieR9+V+iq+ATGgxxb+TOzRoxyFsYOcqnGv3iHqNr74y+rfC
# /HfkieCRmkwh0ss4EVnKIJMefWIlkH3HPirYn+4wmeTKQZmtIq0oEbJlXsSryOXW
# i/NjGfe2xXENAgMBAAGjggHFMIIBwTAfBgNVHSMEGDAWgBRaxLl7KgqjpepxA8Bg
# +S32ZXUOWDAdBgNVHQ4EFgQUqRd4UyWyhbxwBUPJhcJf/q5IdaQwDgYDVR0PAQH/
# BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGA1UdHwRwMG4wNaAzoDGGL2h0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMDWg
# M6Axhi9odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcx
# LmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRw
# czovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAEEATCBhAYIKwYBBQUHAQEE
# eDB2MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTgYIKwYB
# BQUHMAKGQmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJB
# c3N1cmVkSURDb2RlU2lnbmluZ0NBLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3
# DQEBCwUAA4IBAQBMkLEdY3RRV97ghwUHUZlBdZ9dFFjBx6WB3rAGTeS2UaGlZuwj
# 2zigbOf8TAJGXiT4pBIZ17X01rpbopIeGGW6pNEUIQQlqaXHQUsY8kbjwVVSdQki
# c1ZwNJoGdgsE50yxPYq687+LR1rgViKuhkTN79ffM5kuqofxoGByxgbinRbC3PQp
# H3U6c1UhBRYAku/l7ev0dFvibUlRgV4B6RjQBylZ09+rcXeT+GKib13Ma6bjcKTq
# qsf9PgQ6P5/JNnWdy19r10SFlsReHElnnSJeRLAptk9P7CRU5/cMkI7CYAR0GWdn
# e1/Kdz6FwvSJl0DYr1p0utdyLRVpgHKG30bTMIIFMDCCBBigAwIBAgIQBAkYG1/V
# u2Z1U0O1b5VQCDANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYD
# VQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAw
# WhcNMjgxMDIyMTIwMDAwWjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdp
# Q2VydCBTSEEyIEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA+NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/
# 5aid2zLXcep2nQUut4/6kkPApfmJ1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH
# 03sjlOSRI5aQd4L5oYQjZhJUM1B0sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxK
# hwjfDPXiTWAYvqrEsq5wMWYzcT6scKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr
# /mzLfnQ5Ng2Q7+S1TqSp6moKq4TzrGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi
# 6CxR93O8vYWxYoNzQYIH5DiLanMg0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCC
# AckwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAww
# CgYIKwYBBQUHAwMweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6
# MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1s
# AAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw
# CgYIYIZIAYb9bAMwHQYDVR0OBBYEFFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1Ud
# IwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+
# 7A1aJLPzItEVyCx8JSl2qB1dHC06GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbR
# knUPUbRupY5a4l4kgU4QpO4/cY5jDhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7
# uq+1UcKNJK4kxscnKqEpKBo6cSgCPC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7
# qPjFEmifz0DLQESlE/DmZAwlCEIysjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPa
# s7CM1ekN3fYBIM6ZMWM9CBoYs4GbT8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR
# 6mhsRDKyZqHnGKSaZFHvMIIGajCCBVKgAwIBAgIQAwGaAjr/WLFr1tXq5hfwZjAN
# BgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBBc3N1cmVkIElEIENBLTEwHhcNMTQxMDIyMDAwMDAwWhcNMjQxMDIyMDAwMDAw
# WjBHMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQxJTAjBgNVBAMTHERp
# Z2lDZXJ0IFRpbWVzdGFtcCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQCjZF38fLPggjXg4PbGKuZJdTvMbuBTqZ8fZFnmfGt/a4ydVfiS
# 457VWmNbAklQ2YPOb2bu3cuF6V+l+dSHdIhEOxnJ5fWRn8YUOawk6qhLLJGJzF4o
# 9GS2ULf1ErNzlgpno75hn67z/RJ4dQ6mWxT9RSOOhkRVfRiGBYxVh3lIRvfKDo2n
# 3k5f4qi2LVkCYYhhchhoubh87ubnNC8xd4EwH7s2AY3vJ+P3mvBMMWSN4+v6GYeo
# fs/sjAw2W3rBerh4x8kGLkYQyI3oBGDbvHN0+k7Y/qpA8bLOcEaD6dpAoVk62RUJ
# V5lWMJPzyWHM0AjMa+xiQpGsAsDvpPCJEY93AgMBAAGjggM1MIIDMTAOBgNVHQ8B
# Af8EBAMCB4AwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCC
# Ab8GA1UdIASCAbYwggGyMIIBoQYJYIZIAYb9bAcBMIIBkjAoBggrBgEFBQcCARYc
# aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwICMIIBVh6C
# AVIAQQBuAHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBp
# AGMAYQB0AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABh
# AG4AYwBlACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBD
# AFAAUwAgAGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5
# ACAAQQBnAHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABs
# AGkAYQBiAGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABv
# AHIAYQB0AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBj
# AGUALjALBglghkgBhv1sAxUwHwYDVR0jBBgwFoAUFQASKxOYspkH7R7for5XDStn
# As0wHQYDVR0OBBYEFGFaTSS2STKdSip5GoNL9B6Jwcp9MH0GA1UdHwR2MHQwOKA2
# oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENB
# LTEuY3JsMDigNqA0hjJodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRB
# c3N1cmVkSURDQS0xLmNybDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcnQwDQYJKoZI
# hvcNAQEFBQADggEBAJ0lfhszTbImgVybhs4jIA+Ah+WI//+x1GosMe06FxlxF82p
# G7xaFjkAneNshORaQPveBgGMN/qbsZ0kfv4gpFetW7easGAm6mlXIV00Lx9xsIOU
# GQVrNZAQoHuXx/Y/5+IRQaa9YtnwJz04HShvOlIJ8OxwYtNiS7Dgc6aSwNOOMdgv
# 420XEwbu5AO2FKvzj0OncZ0h3RTKFV2SQdr5D4HRmXQNJsQOfxu19aDxxncGKBXp
# 2JPlVRbwuwqrHNtcSCdmyKOLChzlldquxC5ZoGHd2vNtomHpigtt7BIYvfdVVEAD
# kitrwlHCCkivsNRu4PQUCjob4489yq9qjXvc2EQwggbNMIIFtaADAgECAhAG/fkD
# lgOt6gAK6z8nu7obMA0GCSqGSIb3DQEBBQUAMGUxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAi
# BgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0wNjExMTAwMDAw
# MDBaFw0yMTExMTAwMDAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERp
# Z2lDZXJ0IEFzc3VyZWQgSUQgQ0EtMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAOiCLZn5ysJClaWAc0Bw0p5WVFypxNJBBo/JM/xNRZFcgZ/tLJz4Flnf
# nrUkFcKYubR3SdyJxArar8tea+2tsHEx6886QAxGTZPsi3o2CAOrDDT+GEmC/sfH
# MUiAfB6iD5IOUMnGh+s2P9gww/+m9/uizW9zI/6sVgWQ8DIhFonGcIj5BZd9o8dD
# 3QLoOz3tsUGj7T++25VIxO4es/K8DCuZ0MZdEkKB4YNugnM/JksUkK5ZZgrEjb7S
# zgaurYRvSISbT0C58Uzyr5j79s5AXVz2qPEvr+yJIvJrGGWxwXOt1/HYzx4KdFxC
# uGh+t9V3CidWfA9ipD8yFGCV/QcEogkCAwEAAaOCA3owggN2MA4GA1UdDwEB/wQE
# AwIBhjA7BgNVHSUENDAyBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMDBggr
# BgEFBQcDBAYIKwYBBQUHAwgwggHSBgNVHSAEggHJMIIBxTCCAbQGCmCGSAGG/WwA
# AQQwggGkMDoGCCsGAQUFBwIBFi5odHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9zc2wt
# Y3BzLXJlcG9zaXRvcnkuaHRtMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAg
# AHUAcwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAg
# AGMAbwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABv
# AGYAIAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBu
# AGQAIAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBl
# AGUAbQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBs
# AGkAdAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBk
# ACAAaABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCG
# SAGG/WwDFTASBgNVHRMBAf8ECDAGAQH/AgEAMHkGCCsGAQUFBwEBBG0wazAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290
# Q0EuY3J0MIGBBgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMB0GA1Ud
# DgQWBBQVABIrE5iymQftHt+ivlcNK2cCzTAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEARlA+ybcoJKc4HbZbKa9Sz1Lp
# MUerVlx71Q0LQbPv7HUfdDjyslxhopyVw1Dkgrkj0bo6hnKtOHisdV0XFzRyR4WU
# VtHruzaEd8wkpfMEGVWp5+Pnq2LN+4stkMLA0rWUvV5PsQXSDj0aqRRbpoYxYqio
# M+SbOafE9c4deHaUJXPkKqvPnHZL7V/CSxbkS3BMAIke/MV5vEwSV/5f4R68Al2o
# /vsHOE8Nxl2RuQ9nRc3Wg+3nkg2NsWmMT/tZ4CMP0qquAHzunEIOz5HXJ7cW7g/D
# vXwKoO4sCFWFIrjrGBpN/CohrUkxg0eVd3HcsRtLSxwQnHcUwZ1PL1qVCCkQJjGC
# BAMwggP/AgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0
# IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0ECEAZY+tvHeDVvdG/Hsafu
# SKwwCQYFKw4DAhoFAKBAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMCMGCSqG
# SIb3DQEJBDEWBBSCi1r169IpEOp2sXNQijBc79A94DANBgkqhkiG9w0BAQEFAASC
# AQAhWYEav9RStFncn8ovRosIDua/Q3+KQcyPpYdm4QWeTNtCzJ9dmukrO3ep3GyU
# SAzQmoveCWtQsuhUM1d5cSQjvBhv6p8j4JDyFcj+UgJ6dG4O1m1BDnnEGBIQU7s6
# e/9jn7U3JuPAzXXUJ5AKmVYNyTq3IVUPkvmC+/IDmamDxOgpq1f+uU3RTrNmS+3y
# K878qS3cGE/iEyWkPpBg3DHSvQhFs1r+AcmK9rVv7FIENzet1hcyxZWPHnSR/WCM
# FZ5podUYPRJAjhl55Kpbrripx4RL9IiMgfqf9FHE+LqT4xGFDGICQR4jslfQDhCL
# 4xfj7KhU4dHwTygJYbrA5xvkoYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4AgEB
# MHYwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBDQS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMDEwMzExMzU1NTVaMCMG
# CSqGSIb3DQEJBDEWBBSBrnizuTbNM4EWgUWvlRNvVISTtDANBgkqhkiG9w0BAQEF
# AASCAQAcfgzVc+Eu4OOdJgiN3XJwv07URCE7tv84Ls76BupEiKNhT3V7Diyvrh/D
# b6MYL4fB3mTD1ov6fS5UqRl8LvoDs2J6quXJKP3PAW0zghl4EWVCWKaEUIi4oodN
# bgNXywKYq8ZDzLv6FE5uXo9/RqY4w8OOPWTFMkePjY4Nah05xtTA5x8vaD0vDGuG
# OPFV2uNjjM0KjkqxxtoS2//jrITgc4DanvHDfiQflgdynvXOhSz02oVSSlkNfqES
# l6Y9aQWbX5NAh49wNO3OkUSuhd+EzbkG4nM82ejpxCekwRsH2q9VOGnjRkO05dnA
# tD87h1SMMC+ZNlHFYd0SXQjq+w+X
# SIG # End signature block
