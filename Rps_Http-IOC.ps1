# Rps_Http ClientInfo IOC search
#
# Credits: CrowdStrike, Inc. (Erik Iker, Sean Palka, Brian Pitchford, Nicolas Zilio)
#
# Summary: Analysis of ClientInfo value in Rps_Http logs indicated that attempted 
# exploitation via proxied requests would result in an entry with the TA UserAgent for the
# ClientInfo value. Normal usage would have predictable ClientInfo value of '',
# 'Microsoft WinRM Client', or 'Exchange BackEnd Probes'. 
# The original external IP is often included in this log entry, and so the script will 
# identify the network path from original source and subsequent proxied hosts used
# to target the vulnerability.
#
# This script assumes the column headers for the Rpc_Http logs have not been modified from their
# original order/format.
#
# Usage: powershell .\Rps_Http-IOC.ps1 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\CmdletInfra\Powershell-Proxy\Http'


#Read path to files
$path = $args[0];
if($path -eq $null){
	write-host "Usage: powershell .\Rps_Http-IOC.ps1 <PATH TO DIRECTORY WITH RPS_HTTP LOGS>"
	write-host "Example: powershell .\Rps_Http-IOC.ps1 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\CmdletInfra\Powershell-Proxy\Http'"
	exit;
}	
if (-Not (Test-Path -Path $path)) {
	write-host "Usage: powershell .\Rps_Http-IOC.ps1 <PATH TO EXCHANGE LOGGING DIRECTORIES>"
	write-host "Example: powershell .\Rps_Http-IOC.ps1 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\CmdletInfra\Powershell-Proxy\Http'"
	exit;
}
#Header info for Rps_Http logs
$headers = 'DateTime','StartTime','RequestId','MajorVersion','MinorVersion','BuildVersion','RevisionVersion','ClientRequestId','UrlHost','UrlStem','AuthenticationType','IsAuthenticated','AuthenticatedUser','Organization','ManagedOrganization','ClientIpAddress','ServerHostName','FrontEndServer','HttpStatus','SubStatus','ErrorCode','Action','CommandId','CommandName','SessionId','ShellId','FailFast','ContributeToFailFast','RequestBytes','ClientInfo','CPU','Memory','ActivityContextLifeTime','TotalTime','UrlQuery','GenericLatency','GenericInfo','GenericErrors'

#Tracking variables
$success = 0;
$fail = 0;
$logs = @();
$paths = @();
$users = @();

#Recurse through directory, only look at Rps_Http logs
write-host "Finding Rps_Http logs in $path..."
$files = Get-ChildItem $path -Filter "*Rps_Http_20*" -Recurse 
Foreach ($file in $files)
{
	Import-Csv -Path $file.FullName -Header $headers -Delimiter ","| Foreach-Object {
		#Get the ClientInfo column
		$ua = $_.PSObject.Properties["ClientInfo"].Value
		#Detect entries that aren't headers, empty, 'Microsoft WinRM Client' or 'Exchange BackEnd Probes'
		if(($ua -ne "ClientInfo") -and ($ua -ne "Microsoft WinRM Client") -and ($ua -ne "Exchange BackEnd Probes") -and ($ua -match '\w')){
			#Get other column details for lines matching the IOC
			$time = $_.PSObject.Properties["DateTime"].Value
			$src = $_.PSObject.Properties["ClientIPAddress"].Value
			$src = $src.replace(' ' , ' -> ')
			$server = $_.PSObject.Properties["ServerHostName"].Value
			$frontend = $_.PSObject.Properties["FrontEndServer"].Value
			$status = $_.PSObject.Properties["HttpStatus"].Value
			$user = $_.PSObject.Properties["AuthenticatedUser"].Value
			#Check status, 200 indicates possible successful RCE, otherwise attempt was made but failed
			if($status -ne 200){
				write-host "$time [FAILURE: $status] Path: $src -> $frontend -> $server as User: [$user]"
				$fail++
			} else {
				write-host "$time [SUCCESS: $status] Path: $src -> $frontend -> $server as User: [$user] "
				$success++
			}
			$paths += "$src -> $frontend -> $server"
			if($user -match '\w'){
				$users += $user
			}
			$logs += $file.FullName
		}
	}
}
$paths = $paths | sort -unique
$users = $users | sort -unique
$logs = $logs | sort -unique

#Print results
if(($success -gt 0) -or ($fail -gt 0)){
	write-host "#######################################################"
	write-host "Summary:"
	write-host "   $success instances of possible successful proxied exploitation found using UA indicator"
	write-host "   $fail instances of failed proxied exploitation attempts found using UA indicator"
	write-host "#######################################################"
	write-host "Network paths used for exploitation attempts:"
	Foreach ($path in $paths)
	{	
		write-host "   "$path
	}
	write-host "#######################################################"
	write-host "Compromised users:"
	Foreach ($user in $users)
	{	
		write-host "   "$user
	}
	write-host "#######################################################"
	write-host "The following files contained relevant information:"
	Foreach ($log in $logs)
	{	
		write-host "   "$log
	}
} else {
	write-host "No proxied UA indicators found"
}
