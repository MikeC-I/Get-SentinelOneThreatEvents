<#
.SYNOPSIS
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident and audit events from the Canary API and sending the logs as webhooks to a listener.
.DESCRIPTION
    Get-CanaryLogs.ps1 is a PowerShell script for retrieving Canary incident and audit events from the Canary API and sending the logs as webhooks to a listener.
    Global configuration parameters are stored as JSON in Get-CanaryLogs_config.json (or whatever you want to name it, see line 21 below).
.PARAMETER IgnoreCertErrors
    (Switch) Will ignore certificate errors.  Useful in environments with proxies or other HTTPS intermediaries.
.EXAMPLE
    Get-CanaryLogs.ps1 -IgnoreCertErrors
.NOTES
    
    Change Log:
        2022/05/04 - Initial Commit
 #>

[CmdletBinding()]
param(
    [switch]$IgnoreCertErrors
)

### Global Variables - yeah I know they're bad, don't @ me ###

$configfile = "C:\LogRhythm\LogScripts\Get-SentinelOneThreatEvents\Get-SentinelOneThreatEvents_config.json"
$config = Get-Content -Raw $configfile | ConvertFrom-Json
$logfile = $config.logfile
$globalloglevel = $config.loglevel
$statefile = $config.statefile
$s1domain = $config.s1domain
$apitoken = $config.apitoken
$minutesago = $config.minutesago
$outputfile = $config.outputfile
$proxy = $config.proxy
$auditfetcherror = ""
$incidentfetcherror = ""

### Goofy certificate stuff ###

if ($IgnoreCertErrors.IsPresent) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
$certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback += 
                    delegate
                    (
                        Object obj, 
                        X509Certificate certificate, 
                        X509Chain chain, 
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
 }
[ServerCertificateValidationCallback]::Ignore()
}
Else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

 Function Write-Log {  

    # This function provides logging functionality.  It writes to a log file provided by the $logfile variable, prepending the date and hostname to each line
    # Currently implemented 4 logging levels.  1 = DEBUG / VERBOSE, 2 = INFO, 3 = ERROR / WARNING, 4 = CRITICAL
    # Must use the variable $globalloglevel to define what logs will be written.  1 = All logs, 2 = Info and above, 3 = Warning and above, 4 = Only critical.  If no $globalloglevel is defined, defaults to 2
    # Must use the variable $logfile to define the filename (full path or relative path) of the log file to be written to
               
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)] [string]$logdetail,
        [Parameter(Mandatory = $false)] [int32]$loglevel = 2
    )
    if (($globalloglevel -ne 1) -and ($globalloglevel -ne 2) -and ($globalloglevel -ne 3) -and ($globalloglevel -ne 4)) {
        $globalloglevel = 2
    }

    if ($loglevel -ge $globalloglevel) {
        try {
            $logfile_exists = Test-Path -Path $logfile
            if ($logfile_exists -eq 1) {
                if ((Get-Item $logfile).length/1MB -ge 10) {
                    $logfilename = [io.path]::GetFileNameWithoutExtension($logfile)
                    $newfilename = "$($logfilename)"+ (Get-Date -Format "yyyyMMddhhmmss").ToString() + ".log"
                    Rename-Item -Path $logfile -NewName $newfilename
                    New-Item $logfile -ItemType File
                    $this_Date = Get-Date -Format "MM\/dd\/yyyy hh:mm:ss tt"
                    Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
                }
                else {
                    $this_Date = Get-Date -Format "MM\/dd\/yyyy hh:mm:ss tt"
                    Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
                }
            }
            else {
                New-Item $logfile -ItemType File
                $this_Date = Get-Date -Format "MM\/dd\/yyyy hh:mm:ss tt"
                Add-Content -Path $logfile -Value "$this_Date [$env:COMPUTERNAME] $logdetail"
            }
        }
        catch {
            Write-Error "***ERROR*** An error occured writing to the log file: $_"
        }
    }
}

Function Write-OutputLog($logstring) {
    $old_logfile = $logfile
    $logfile = $outputfile
    Write-Log -loglevel 4 -logdetail $logstring
    $logfile = $old_logfile
}

### Sweet Functions ###

Function Get-State {
    $statefile_exists = Test-Path -Path $statefile
    if ($statefile_exists -eq $false) {
        Write-Log -loglevel 2 -logdetail "State file does not exist. Script will proceed with last updated_id = 0"
        $threat_state = 0        
    }
    Else{
        Try {
            Write-Log -loglevel 1 -logdetail "Reading state from state file $($statefile)"
            $state = Get-Content $statefile -Raw | ConvertFrom-Json
            [int64]$threat_state = $state.threatstate -as[int64]
            Write-Log -loglevel 1 -logdetail "Retrieved threat state: $($threat_state) from $($statefile)"        
        }
        Catch {
            Write-Log -loglevel 3 -logdetail "***WARNING*** Could not read $($statefile). Script will proceed with activity state = 0: $_"
            $threat_state = 0
                    
        }
    }
    $statearray = New-Object PSObject -Property @{
        "threatstate" = $threat_state
        
    }
    Return $statearray
}

Function Write-State {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int64]$threat_state
        
    )
    $threat_string = $threat_state.ToString()
    $stateJson = New-Object PSObject -Property @{
            "threatstate" = $threat_state        
    }
    
    try {
        $state_exists = Test-Path -Path $statefile
        if ($state_exists -eq $true) {
            Write-Log -loglevel 1 -logdetail "Writing last threat state of $($threat_state) to $($statefile)"
            $stateJson | ConvertTo-Json | Out-File -FilePath $statefile
        }
        else {
            Write-Log -loglevel 1 -logdetail "State file does not exist. Creating $($statefile)"
            Write-Log -loglevel 1 -logdetail "Writing last threat state of $($threat_state) to state file $($statefile)"
            $stateJson | ConvertTo-Json | Out-File -FilePath $statefile
        }
    }
    catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured writing to the state file: $_"
    }

}

Function Get-ThreatEvents {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int64]$LastUpdateID
    )
    $lastcreateddate = (get-date).AddMinutes(-($minutesago)).ToString("yyyy-MM-ddThh:mm:ss.ffffffZ")
    $uri = $s1domain + "/web/api/v2.1/threats?createdAt__gte=$($lastcreateddate)&limit=1000"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "ApiToken $($apitoken)")
    Write-Log -loglevel 1 -logdetail "Querying API for new incident events (last ID = $($LastUpdateID))..."
    Try {
        if (($proxy -ne $null) -and ($proxy -ne "")) {
            $querytime = Measure-Command {
                $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -Proxy $proxy
            }
        }
        else {
            $querytime = Measure-Command {
                $result = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET 
            }
        }
    }
    Catch {
        Write-Log -loglevel 3 -logdetail "***ERROR*** An error occured retreiving events from API: $_"
        $incidentfetcherror = $_
    }
    Write-Log -loglevel 1 -logdetail "API query completed succesfully in $querytime."
    [int64]$max_id = $LastUpdateID
    $total_incidents = 0
    $new_events = @() 
    ForEach ($i in $result.data) {
        $total_incidents += 1
        if ($i.id -gt $max_id) {
            $max_id = $i.id
            $new_events += $i
        }
    }
    Write-Log -loglevel 2 -logdetail "Retrieved $($total_incidents) total events, $($new_events.Count) new events. Last update_id = $($max_id)"
    $returnresult = New-Object PSObject -Property @{
        "results" = $new_events
        "last_id" = $max_id
    }
    Return $returnresult 
}

Function Write-ThreatEvents ($threat_results) {
    Write-Log -loglevel 2 -logdetail "Writing Threat events to file $($outputfile)..."
    if ($threat_results.Count -eq 0) {
        Write-Log -loglevel 2 -logdetail "No new Threat events."
    }
    else {
        $counter = 0
        foreach ($a in $threat_results) {
            $logmessage = "agentNetworkStatus=$($a.agentRealtimeInfo.agentNetworkStatus)|agentVersion=$($a.agentRealtimeInfo.agentVersion)|agentcomputername=$($a.agentRealtimeInfo.agentComputerName)|agentInfected=$($a.agentRealtimeInfo.agentInfected)|agentOsType=$($a.agentRealtimeInfo.agentOsType)|agentUuid=$($a.agentRealtimeInfo.agentUuid)|isValidCertificate=$($a.threatInfo.isValidCertificate)|processUser=$($a.threatInfo.processUser)|fileVerificationType=$($a.threatInfo.fileVerificationType)|publisherName=$($a.threatInfo.publisherName)|filePath=$($a.threatInfo.filePath)|fileExtensionType=$($a.threatInfo.fileExternsionType)|analysisVerdictDescription=$($a.threatInfo.analysisVerdictDescription)|detectionType=$($a.threatInfo.detectionType)|mitigationStatus=$($a.threatInfo.mitigationSatus)|md5=$($a.threatInfo.md5)|incidentStatusDescription=$($a.threatInfo.incidentStatusDescription)|mitigationStatusDescription=$($a.threatInfo.mitigationStatusDescription)|initatingUsername=$($a.threatInfo.initatingUsername)|detectionEngines=$($a.threatInfo.detectionEngines[0].title)|maliciousProcessArgument=$($a.threatInfo.maliciousProcessArguments)|fileExtension=$($a.threatInfo.fileExtenstion)|sha1=$($a.threatInfo.sha1)|isFileless=$($a.threatInfo.isFileless)|confidenceLevel=$($a.threatInfo.confidenceLevel)|initiatedByDescription=$($a.threatInfo.initiatedByDescription)|initiatedBy=$($a.threatInfo.initiatedBy)|certificateId=$($a.threatInfo.certificateId)|threatId=$($a.threatInfo.threatId)|sha256=$($a.threatInfo.sha256)|classification=$($a.threatInfo.classification)|engines=$($a.threatInfo.engines)|incidentStatus=$($a.threatInfo.incidentStatus)|analysisVerdict=$($a.threatInfo.analysisVerdict)|classificationSource=$($a.threatInfo.classificationSource)|identifiedAt=$($a.threatInfo.identifiedAt)|originatorProcess=$($a.threatInfo.originatorProcess)|threatName=$($a.threatInfo.threatName)|cloudFileHashVerdict=$($a.threatInfo.cloudFileHashVerdict)|mitigationAction=$($a.mitigationStatus.action)|mitigationStatus=$($a.mitigationStatus.status)|agentIpV4=$($a.agentDetectionInfo.agentIpV4)|agentOsName=$($a.agentDetectionInfo.agentOsName)|siteName=$($a.agentDetectionInfo.siteName)|agentDetectionState=$($a.agentDetectionInfo.agentDetectionState)|agentOsRevision=$($a.agentDetectionInfo.agentOsRevision)|agentVersion=$($a.agentDetectionInfo.agentVersion)|externalIp=$($a.agentDetectionInfo.externalIp)|agentLastLoggedInUserName=$($a.agentDetectionInfo.agentLastLoggedInUserName)|groupName=$($a.agentDetectionInfo.groupName)|agentDomain=$($a.agentDetectionInfo.agentDoman)|agentIpV6=$($a.agentDetectionInfo.agentIpV6)|agentUuid=$($a.agentDetectionInfo.agentUuid)"
            # $logmessage = "accountId=$($a.accountId)|accountName=$($a.accountName)|activityType=$($a.activityType)|agentId=$($a.agentId)|agentUpdatedVersion=$($a.agentUpdatedVersion)|comments=$($a.comments)|createdAt=$($a.createdAt)|computername=$($a.data.computerName)|confidenceLevel=$($a.data.confidentLevel)|fileContentHash=$($a.data.fileContentHash)|fileDisplayName=$($a.data.fileDisplayName)|filePath=$($a.data.filePath)|groupName=$($a.data.groupName)|siteName=$($a.data.siteName)|threatClassification=$($a.data.threatClassification)|threatClassificationSource=$($a.data.threatClassificationSource)|username=$($a.data.username)|description=$($a.description)|groupId=$($a.groupId)|hash=$($a.hash)|id=$($a.id)|osFamily=$($a.osFamilty)|primaryDescription=$($a.primaryDescription)|secondaryDescription=$($a.secondaryDescription)|siteId=$($a.siteId)|siteName=$($a.siteName)|threatId=$($a.threatId)|updatedAt=$($a.updatedAt)|userId=$($a.userId)"
            Write-OutputLog $logmessage
            $counter = $counter + 1
        }
        Write-Log -loglevel 2 -logdetail "Wrote $counter total logs to $($outputfile)"
    }
}


### MAIN ###
Write-Log -loglevel 4 -logdetail "Script initatied..."
if ($IgnoreCertErrors.IsPresent) {
    Write-Log -loglevel 3 -logdetail "***WARNING*** Script invoked with IgnoreCertErrors. Certificate errors will be ignored"
}
if (($proxy -ne $null) -and ($proxy -ne "")) {
    Write-Log -loglevel 3 -logdetail "Using proxy $($proxy)"
}
$last_state = Get-State
$threatresults = Get-ThreatEvents -LastUpdateID $last_state.threatstate
Write-ThreatEvents $threatresults.results
Write-State $threatresults.last_id
Write-Log -loglevel 4 -logdetail "Script complete."