<#   
    .SYNOPSIS
    Monitors Citrix ADC (Netscaler)

    .DESCRIPTION
    Using Powershell Nitro Module to monitor Citrix ADC

    Copy this script to the PRTG probe EXEXML scripts folder (${env:ProgramFiles(x86)}\PRTG Network Monitor\Custom Sensors\EXEXML)
    and create a "EXE/Script Advanced. Choose this script from the dropdown and set at least:

    + Parameters: Hostname, Username, Password
    + Scanning Interval: minimum 15 minutes

    .PARAMETER Hostname
    Netscaler/ADC Hostname or IP

    .PARAMETER Username
    Monitoring User Login

    .PARAMETER Password
    Monitoring User Password

    .PARAMETER https
    default is http, user this Parameter to use https
    if needed combine with -IgnoreCert

    .PARAMETER IgnoreCert
    if using https this paramter ignores unvalid or selfsigned certs when connecting to ADC

    .PARAMETER vServer
    Enables vServer Monitoring
    Channels: vServer least LB Health, vServer down, vServer up & vServer Out of Service

    .PARAMETER vServerStats
    Enables vServer Stat Monitoring
    shows Hits/s and Bytes/s for each vServer
    Type include/exclude not working

    .PARAMETER vServerHealth
    Enables vServer Health Monitoring
    shows channels with % health from all LB vServer
    combine it with vServerHealthWarLimit and vServerHealthErrLimit

    .PARAMETER vServerState
    Enables state monitoring for each vServer
    combine it with -IncludevServerName, -ExcludevServerName, -IncludevServerType or -ExcludevServerType
    
    .PARAMETER IncludevServerName
    Use Regual Expression to filter for vServer names
    -IncludevServerName '^(test.*)$' = only monitor all vServers starting with test.

    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ExcludevServerName
    Use Regual Expression to filter for vServer names
    -ExcludevServerName '^(test.*)$' = excludes all vServers starting with test.

    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER IncludevServerType
    Use Regual Expression to filter for vServer Types
    -ExcludevServerName '^(LBvServer)$' = just LBvServer

    possibilities "CSvServer", "LBvServer", "VPNvServer", "AAAvServer"

    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ExcludevServerType
    Use Regual Expression to filter for vServer Types
    -ExcludevServerName '^(LBvServer)$' = all vServer but LBvServer

    possibilities "CSvServer", "LBvServer", "VPNvServer", "AAAvServer"

    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ConfigSaved
    Enables last ConfigSaved Monitoring

    .PARAMETER CertExpiration
    Enables certificate expiration Monitoring
    combine it with IncludeCerts, ExcludeCerts or CertDetails
    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER IncludeCerts
    Use Regual Expression to filter for Cert names
    -IncludeCerts '^(test.contoso.*)$' = just certs starting with test.contoso

    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER ExcludeCerts
    Use Regual Expression to filter for Cert names
    -ExcludeCerts '^(test.contoso.*)$' = all certs but certs starting with test.contoso

    Regular Expression: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_regular_expressions?view=powershell-7.1

    .PARAMETER CertDetails
    combine with -CertExpiration to show every cert as unique channel

    .PARAMETER System
    Enables System Monitoring

    .PARAMETER HA
    Enables High Availibility Monitoring

    .PARAMETER Interface
    Enables Interface Monitoring

    .EXAMPLE
    Sample call from PRTG EXE/Script Advanced

    -Hostname '%host' -Username '%linuxuser' -Password '%linuxpassword' -System -https

    Changelog:
    21.09.2022 - fix ADC 13.0 CPU usage bug


    Author:  Jannos-443
    https://github.com/Jannos-443/PRTG-CitrixADC
#>
param(
    [string]$Hostname,
    [string]$Username,
    [string]$Password,
    [switch]$https = $false,
    [switch]$IgnoreCert = $false,
    [switch]$vServer = $false,
    [switch]$vServerState = $false,
    [switch]$vServerStats = $false,
    [switch]$vServerHealth = $false,
    [int]$vServerHealthErrLimit = "",
    [int]$vServerHealthWarLimit = "",
    [string]$IncludevServerName = "",
    [string]$ExcludevServerName = "",
    [string]$IncludevServerType = "",
    [string]$ExcludevServerType = "",
    [switch]$ConfigSaved = $false,
    [switch]$CertExpiration = $false,
    [switch]$CertDetails = $false,
    [string]$IncludeCerts = "",
    [string]$ExcludeCerts = "",
    [switch]$System = $false,
    [switch]$HA = $false,
    [switch]$Interface = $false
)

#Catch all unhandled Errors
trap {
    if ($session) {
        $null = Disconnect-Netscaler -Session $session -ErrorAction SilentlyContinue
    }
    $Output = "line:$($_.InvocationInfo.ScriptLineNumber.ToString()) char:$($_.InvocationInfo.OffsetInLine.ToString()) --- message: $($_.Exception.Message.ToString()) --- line: $($_.InvocationInfo.Line.ToString()) "
    $Output = $Output.Replace("<", "")
    $Output = $Output.Replace(">", "")
    $Output = $Output.Replace("#", "")
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>$($Output)</text>"
    Write-Output "</prtg>"
    Exit
}

# Error if there's anything going on
$ErrorActionPreference = "Stop"

if ($Hostname -eq "") {
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>You must provide a Hostname (-Hostname)</text>"
    Write-Output "</prtg>"
    Exit
}

if ($UserName -eq "" -or $Password -eq "") {
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>You must provide Username and Password (-Username and -Password)</text>"
    Write-Output "</prtg>"
    Exit
}

if (-not ($vServer -or $vServerStats -or $vServerState -or $vServerHealth -or $ConfigSaved -or $CertExpiration -or $System -or $HA -or $Interface)) {
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>You must select at least one Monitoring section (-vServer, -ConfigSaved, -CertExpiration, -System, -HA or -Interface</text>"
    Write-Output "</prtg>"
    Exit
}

# Import Module
try {
    Import-Module -Name "Netscaler" -ErrorAction Stop
}
catch {
    Write-Output "<prtg>"
    Write-Output "<error>1</error>"
    Write-Output "<text>Error Loading NetScaler Powershell Module ($($_.Exception.Message))</text>"
    Write-Output "</prtg>"
    Exit
}

try {
    $SecPasswd = ConvertTo-SecureString $Password -AsPlainText -Force
    $Credentials = New-Object System.Management.Automation.PSCredential ($UserName, $SecPasswd)
}
catch {
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>Error Parsing Credentials ($($_.Exception.Message))</text>"
    Write-Output "</prtg>"
    Exit
}


try {
    if ($https) {
        if ($IgnoreCert) {
            add-type @"
    			using System.Net;
				using System.Security.Cryptography.X509Certificates;
				public class TrustAllCertsPolicy : ICertificatePolicy {
				public bool CheckValidationResult(
				ServicePoint srvPoint, X509Certificate certificate,
				WebRequest request, int certificateProblem) {
				return true;
        }
    }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        $Session = Connect-Netscaler -Hostname $Hostname -Credential $Credentials -PassThru -Https
    }
    else {
        $Session = Connect-Netscaler -Hostname $Hostname -Credential $Credentials -PassThru
    }
}
catch {
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>Error connecting to $Hostname ($($_.Exception.Message))</text>"
    Write-Output "</prtg>"
    Exit
}

$xmlOutput = '<prtg>'
$OutputText = ""

#region: vServer

#vServer Stats
if ($vServerStats) {
    $lbServerStats = Get-NSStat -Session $Session -Type lbvserver

    if ($IncludevServerName -ne "") {
        $lbServerStats = $lbServerStats | Where-Object { $_.Name -match $IncludevServerName }
    }
    if ($ExcludevServerName -ne "") {
        $lbServerStats = $lbServerStats | Where-Object { $_.Name -notmatch $ExcludevServerName }
    }

    foreach ($lbServerStat in $lbServerStats) {
        $xmlOutput += "<result>
        <channel>$($lbServerStat.name) hits/s</channel>
        <value>$($lbServerStat.hitsrate)</value>
        <unit>count</unit>
        </result>"

        [double]$TotalBandwidth = $lbServerStat.requestbytesrate + $lbServerStat.responsebytesrate

        $xmlOutput += "<result>
        <channel>$($lbServerStat.name) bytes/s</channel>
        <value>$([math]::truncate($TotalBandwidth/125000))</value>
        <unit>Custom</unit>
        <CustomUnit>MBits</CustomUnit>
        </result>"
    }               
}

if ($vServerState -or $vServerHealth -or $vServer) {
    $vServerUp = 0
    $vServerDown = 0
    $vServerOutofService = 0
    $vServerDownTXT = ""
    $vServerLBHealthMin = 100

    $Types = @("CSvServer"; "LBvServer"; "VPNvServer"; "AAAvServer")

    if ($IncludevServerType -ne "") {
        $Types = $Types | Where-Object { $_ -match $IncludevServerType }
    }
    if ($ExcludevServerType -ne "") {
        $Types = $Types | Where-Object { $_ -notmatch $ExcludevServerType }
    }

    #CSvServer
    if ("CSvServer" -in $Types) {
        $CSvServerResults = Get-NSCSVirtualServer -session $Session

        if ($IncludevServerName -ne "") {
            $CSvServerResults = $CSvServerResults | Where-Object { $_.Name -match $IncludevServerName }
        }
        if ($ExcludevServerName -ne "") {
            $CSvServerResults = $CSvServerResults | Where-Object { $_.Name -notmatch $ExcludevServerName }
        }

        foreach ($Result in $CSvServerResults) {
            switch ($Result.curstate) {
                "UP" {
                    $CurState = 1 
                    $vServerUp ++
                }
                "DOWN" { 
                    $CurState = 2 
                    $vServerDown ++
                    $vServerDownTXT += "$($Result.name); "
                }
                "OUT OF SERVICE" {
                    $CurState = 3 
                    $vServerOutofService ++
                }
            }

            if ($vServerState) {
                $xmlOutput += "<result>
                <channel>State CS: $($Result.name)</channel>
                <value>$($CurState)</value>
                <unit>Custom</unit>
                <CustomUnit>Status</CustomUnit>
                <valuelookup>prtg.citrix.adc.vserverstatus</valuelookup>
                </result>"
            }
        }
    }

    #LBvServer
    if ("LBvServer" -in $Types) {
        $LBvServerResults = Get-NSLBVirtualServer -session $Session

        if ($IncludevServerName -ne "") {
            $LBvServerResults = $LBvServerResults | Where-Object { $_.Name -match $IncludevServerName }
        }
        if ($ExcludevServerName -ne "") {
            $LBvServerResults = $LBvServerResults | Where-Object { $_.Name -notmatch $ExcludevServerName }
        }

        foreach ($Result in $LBvServerResults) {
            switch ($Result.curstate) {
                "UP" {
                    $CurState = 1 
                    $vServerUp ++
                }
                "DOWN" { 
                    $CurState = 2 
                    $vServerDown ++
                    $vServerDownTXT += "$($Result.name); "
                }
                "OUT OF SERVICE" {
                    $CurState = 3 
                    $vServerOutofService ++
                }
            }
            if($Result.curstate -ne "OUT OF SERVICE")
                {
                if ($Result.health -le $vServerLBHealthMin) {
                    $vServerLBHealthMin = $Result.health
                    }
                }

            if ($vServerState) {
                $xmlOutput += "<result>
                <channel>State LB: $($Result.name)</channel>
                <value>$($CurState)</value>
                <unit>Custom</unit>
                <CustomUnit>Status</CustomUnit>
                <valuelookup>prtg.citrix.adc.vserverstatus</valuelookup>
                </result>"
            }

            if ($vServerHealth) {
                $xmlOutput += "<result>
                <channel>Health LB: $($Result.name)</channel>
                <value>$($Result.health)</value>
                <unit>Percent</unit>"

                if (($vServerHealthWarLimit) -or ($vServerHealthErrLimit)) {
                    $xmlOutput += "<limitmode>1</limitmode>"   
                    if ($vServerHealthErrLimit) {
                        $xmlOutput += "<LimitMinError>$($vServerHealthErrLimit)</LimitMinError>"
                    }
                    if ($vServerHealthErrLimit) {
                        $xmlOutput += "<LimitMinWarning>$($vServerHealthWarLimit)</LimitMinWarning>"
                    }
                }
                $xmlOutput += "</result>"
            }
        }

        if ($vServer) {
            $xmlOutput += "<result>
            <channel>vServer least LB Health</channel>
            <value>$($vServerLBHealthMin)</value>
            <unit>Percent</unit>
            <limitmode>1</limitmode>
            <LimitMinError>50</LimitMinError>
            </result>"
        }
    }

    #VPNvServer
    if ("VPNvServer" -in $Types) {
        $VPNvServerResults = Get-NSVPNVirtualServer -session $Session

        if ($IncludevServerName -ne "") {
            $VPNvServerResults = $VPNvServerResults | Where-Object { $_.Name -match $IncludevServerName }
        }
        if ($ExcludevServerName -ne "") {
            $VPNvServerResults = $VPNvServerResults | Where-Object { $_.Name -notmatch $ExcludevServerName }
        }

        foreach ($Result in $VPNvServerResults) {
            switch ($Result.curstate) {
                "UP" {
                    $CurState = 1 
                    $vServerUp ++
                }
                "DOWN" { 
                    $CurState = 2 
                    $vServerDown ++
                    $vServerDownTXT += "$($Result.name); "
                }
                "OUT OF SERVICE" {
                    $CurState = 3 
                    $vServerOutofService ++
                }
            }
            if ($vServerState) {
                $xmlOutput += "<result>
                <channel>State VPN: $($Result.name)</channel>
                <value>$($CurState)</value>
                <unit>Custom</unit>
                <CustomUnit>Status</CustomUnit>
                <valuelookup>prtg.citrix.adc.vserverstatus</valuelookup>
                </result>"
            }
        }
    }

    #AAAvServer
    if ("AAAvServer" -in $Types) {
        $AAAvServerResults = Get-NSAAAVirtualServer -session $Session

        if ($IncludevServerName -ne "") {
            $AAAvServerResults = $AAAvServerResults | Where-Object { $_.Name -match $IncludevServerName }
        }
        if ($ExcludevServerName -ne "") {
            $AAAvServerResults = $AAAvServerResults | Where-Object { $_.Name -notmatch $ExcludevServerName }
        }

        foreach ($Result in $AAAvServerResults) {
            switch ($Result.curstate) {
                "UP" {
                    $CurState = 1 
                    $vServerUp ++
                }
                "DOWN" { 
                    $CurState = 2 
                    $vServerDown ++
                    $vServerDownTXT += "$($Result.name); "
                }
                "OUT OF SERVICE" {
                    $CurState = 3 
                    $vServerOutofService ++
                }
            }
            if ($vServerState) {
                $xmlOutput += "<result>
                <channel>State AAA: $($Result.name)</channel>
                <value>$($CurState)</value>
                <unit>Custom</unit>
                <CustomUnit>Status</CustomUnit>
                <valuelookup>prtg.citrix.adc.vserverstatus</valuelookup>
                </result>"
            }
        }
    }
    #vServer down text
    if ($vServer) {
        if ($vServerDown -ne 0) {
            $OutputText += "vServer down: $($vServerDownTXT)"
        }
        $xmlOutput += "<result>
        <channel>vServer Up</channel>
        <value>$($vServerUp)</value>
        <unit>Count</unit>
        </result>
        <result>
        <channel>vServer down</channel>
        <value>$($vServerDown)</value>
        <unit>Count</unit>
        <limitmode>1</limitmode>
        <LimitMaxError>0</LimitMaxError>
        </result>
        <result>
        <channel>vServer Out of Service</channel>
        <value>$($vServerOutofService)</value>
        <unit>Count</unit>
        </result>"
    } 
}
#endregion vServer

#region: ConfigSavedState
if ($ConfigSaved) {
    $ConfigResults = Invoke-Nitro -Session $Session -Method GET -Type nsconfig

    if ($ConfigResults.nsconfig.configchanged -eq $False) {
        $MinAgo = 0
        $HourAgo = 0
        $DaysAgo = 0
    }
    else {
        $LastConfigChangedTime = $ConfigResults.nsconfig.lastconfigchangedtime.Replace("  ", " 0")
        $LastConfigChangedTime = [datetime]::ParseExact($LastConfigChangedTime, "ddd MMM d HH:mm:ss yyyy", [cultureinfo]'en-US')

        $LastConfigSaveTime = $ConfigResults.nsconfig.lastconfigsavetime.Replace("  ", " 0")
        $LastConfigSaveTime = [datetime]::ParseExact($LastConfigSaveTime, "ddd MMM d HH:mm:ss yyyy", [cultureinfo]'en-US')

        $CurrentSytemTime = $ConfigResults.nsconfig.currentsytemtime.Replace("  ", " 0")
        $CurrentSytemTime = [datetime]::ParseExact($CurrentSytemTime, "ddd MMM d HH:mm:ss yyyy", [cultureinfo]'en-US')

        #$Culture = [System.Globalization.CultureInfo]::InvariantCulture
        #$LastConfigChangedTime = [datetime]::ParseExact($LastConfigChangedTime, “ddd MMM d HH:mm:ss yyyy”, $Culture)

        $MinAgo = [math]::truncate(($CurrentSytemTime - $LastConfigChangedTime).TotalMinutes)
        $HourAgo = [math]::truncate(($CurrentSytemTime - $LastConfigChangedTime).TotalHours)
        $DaysAgo = [math]::truncate(($CurrentSytemTime - $LastConfigChangedTime).TotalDays)
    }

    $xmlOutput += "<result>
	<channel>Config Unsaved Minutes</channel>
	<value>$($MinAgo)</value>
	<unit>Count</unit>
	</result>
	<result>
	<channel>Config Unsaved Hours</channel>
	<value>$($HourAgo)</value>
	<unit>Count</unit>
	</result>
	<result>
	<channel>Config Unsaved Days</channel>
	<value>$($DaysAgo)</value>
	<unit>Count</unit>
	<limitmode>1</limitmode>
	<LimitMaxError>0</LimitMaxError>
	</result>"
}
#endregion ConfigSavedState

#region: CertExpiration
if ($CertExpiration) {
    $CertResults = Get-NSSSLCertificate -session $Session

    if ($ExcludeCerts -ne "") {
        $CertResults = $CertResults | Where-Object { $_.certkey -notmatch $ExcludeCerts }
    }

    if ($IncludeCerts -ne "") {
        $CertResults = $CertResults | Where-Object { $_.certkey -match $IncludeCerts }
    }

    $CertResults = $CertResults | Sort-Object daystoexpiration

    $FirstExpiration = ($CertResults | Select-Object -First 1).daystoexpiration
    if (($CertResults | Measure-Object).count -eq 0) {
        $FirstExpiration = 2000
    }
    
    $Top5 = $CertResults | Select-Object -First 5
    $OutputTextCert = "next to expire: "
    foreach ($Top in $Top5) {
        $OutputTextCert += "`"$($Top.certkey)`" expires in $($Top.daystoexpiration)d; "
    }

    $xmlOutput += "<result>
    <channel>Next Cert Expiration</channel>
    <value>$($FirstExpiration)</value>
    <unit>Custom</unit>
    <CustomUnit>Days</CustomUnit>
    <LimitMode>1</LimitMode>
    <LimitMinWarning>30</LimitMinWarning>
    <LimitMinError>10</LimitMinError>
    </result>"

    if ($CertDetails) {
        foreach ($Result in $CertResults) {
            $xmlOutput += "<result>
            <channel>$($Result.certkey)</channel>
            <value>$($Result.daystoexpiration)</value>
            <unit>Custom</unit>
            <CustomUnit>Days</CustomUnit>
            <LimitMode>1</LimitMode>
            <LimitMinWarning>30</LimitMinWarning>
            <LimitMinError>10</LimitMinError>
            </result>"
        }
    }

    $OutputText += $OutputTextCert
}
#endregion CertExpiration

#region: System
if ($System) {
    $ResultSystem = Get-NSStat -session $Session -Type 'system'
    $ResultProtocolTCP = Get-NSStat -session $Session -Type 'protocoltcp'
    $ResultNS = Get-NSStat -Session $Session -Type 'ns'
    $ResultCurrentTime = Get-NSCurrentTime -session $Session
    $ResultSystemCPU = Get-NSStat -session $session -Type systemcpu

    #CPU Result in 13.0 invalid
    if($ResultSystem.cpuusagepcnt -eq 4294967295)
        {
        $OutputCPU = ($ResultSystemCPU.percpuuse | Measure-Object -Average).Average
        }
    else
        {
        $OutputCPU = $ResultSystem.cpuusagepcnt
        }

    $xmlOutput += "<result>
			<channel>CPU Usage</channel>
			<value>$([math]::Round($OutputCPU))</value>
			<unit>Percent</unit>
			<limitmode>1</limitmode>
			<LimitMaxWarning>90</LimitMaxWarning>
			<LimitMaxError>95</LimitMaxError>
			</result>"

    $xmlOutput += "<result>
			<channel>Packet CPU Usage</channel>
			<value>$([math]::Round($ResultSystem.pktcpuusagepcnt))</value>
			<unit>Percent</unit>
			<limitmode>1</limitmode>
			<LimitMaxWarning>90</LimitMaxWarning>
			<LimitMaxError>95</LimitMaxError>
			</result>"

    $xmlOutput += "<result>
			<channel>Management CPU Usage</channel>
			<value>$([math]::Round($ResultSystem.mgmtcpuusagepcnt))</value>
			<unit>Percent</unit>
			<limitmode>1</limitmode>
			<LimitMaxWarning>90</LimitMaxWarning>
			<LimitMaxError>95</LimitMaxError>
			</result>"

    $xmlOutput += "<result>
			<channel>Memory Usage</channel>
			<value>$([math]::Round($ResultSystem.memusagepcnt))</value>
			<unit>Percent</unit>
			<limitmode>1</limitmode>
			<LimitMaxWarning>90</LimitMaxWarning>
			<LimitMaxError>95</LimitMaxError>
			</result>"

    $xmlOutput += "<result>
			<channel>Memory MB Usage</channel>
			<value>$((([int]$ResultSystem.memuseinmb) * 1024) * 1024)</value>
			<unit>BytesMemory</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>Disk 0 Usage</channel>
			<value>$([math]::truncate(($ResultSystem.disk0used / $ResultSystem.disk0size) * 100))</value>
			<unit>Percent</unit>
			<limitmode>1</limitmode>
			<LimitMaxWarning>90</LimitMaxWarning>
			<LimitMaxError>95</LimitMaxError>
			</result>"

    $xmlOutput += "<result>
			<channel>Disk 1 Usage</channel>
			<value>$([math]::truncate(($ResultSystem.disk1used / $ResultSystem.disk1size) * 100))</value>
			<unit>Percent</unit>
			<limitmode>1</limitmode>
			<LimitMaxWarning>90</LimitMaxWarning>
			<LimitMaxError>95</LimitMaxError>
			</result>"

    $xmlOutput += "<result>
			<channel>SSL Transactions/sec</channel>
			<value>$($ResultNS.ssltransactionsrate)</value>
			<unit>count</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>tcpActiveServerConn</channel>
			<value>$($ResultProtocolTCP.tcpactiveserverconn)</value>
			<unit>count</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>tcpCurrentServerConn</channel>
			<value>$($ResultProtocolTCP.tcpcurserverconn)</value>
			<unit>count</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>tcpCurrentClientConn</channel>
			<value>$($ResultProtocolTCP.tcpcurclientconn)</value>
			<unit>count</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>httpResponses/sec</channel>
			<value>$($ResultNS.httpresponsesrate)</value>
			<unit>count</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>httpRequests/sec</channel>
			<value>$($ResultNS.httprequestsrate)</value>
			<unit>count</unit>
			</result>"

    $xmlOutput += "<result>
			<channel>Total mbits RX/sec</channel>
            <value>$([math]::truncate($ResultNS.rxmbitsrate))</value>
			<unit>Custom</unit>
			<CustomUnit>MBits</CustomUnit>
			</result>"
    
    $xmlOutput += "<result>
			<channel>Total mbits TX/sec</channel>
            <value>$([math]::truncate($ResultNS.txmbitsrate))</value>
			<unit>Custom</unit>
			<CustomUnit>MBits</CustomUnit>
			</result>"

    [double]$Totalmbits = $ResultNS.txmbitsrate + $ResultNS.rxmbitsrate
    $xmlOutput += "<result>
			<channel>Total mbits/sec</channel>
			<value>$([math]::truncate($Totalmbits))</value>
			<unit>Custom</unit>
			<CustomUnit>MBits</CustomUnit>
			</result>"

    $StartTimeLocal = $ResultSystem.StartTimeLocal.Replace("  ", " 0")
    $StartTimeLocal = [datetime]::ParseExact($StartTimeLocal, "ddd MMM d HH:mm:ss yyyy", [cultureinfo]'en-US')
    $Uptime = [math]::truncate(($ResultCurrentTime - $StartTimeLocal).TotalDays)

    $xmlOutput += "<result>
			<channel>Uptime</channel>
			<value>$($Uptime)</value>
			<unit>Custom</unit>
			<CustomUnit>days</CustomUnit>
			</result>"
}
#endregion System

#region: High Availability
if ($HA) {
    $ResultHaNode = Get-NSStat -session $Session -Type hanode
    $ResultCurrentTime = Get-NSCurrentTime -session $Session

    switch ($ResultHaNode.hacurstatus) {
        'NO' { $HaCurStatus = 0 }
        'YES' { $HaCurStatus = 1 }
        default { $HaCurStatus = -1 }
    }

    $xmlOutput += "<result>
	<channel>HA Status</channel>
	<value>$($HaCurStatus)</value>
	<ValueLookup>prtg.citrix.adc.hacurstatus</ValueLookup>
	</result>"

    if ($ResultHaNode.hacurstatus -eq "YES") {
        switch ($ResultHaNode.hacurstate) {
            'UP' { $HaCurState = 0 }
            'DISABLED' { $HaCurState = 1 }
            'INIT' { $HaCurState = 2 }
            'PARTIALFAIL' { $HaCurState = 3 }
            'COMPLETEFAIL ' { $HaCurState = 4 }
            'DUMB' { $HaCurState = 5 }
            'PARTIALFAILSSL' { $HaCurState = 6 }
            'ROUTEMONITORFAIL ' { $HaCurState = 7 }
            default { $HaCurState = -1 }
        }

        switch ($ResultHaNode.hacurmasterstate) {
            'PRIMARY' { $HaCurMasterState = 0 }
            'SECONDARY' { $HaCurMasterState = 1 }
            'STAYSECONDARY' { $HaCurMasterState = 2 }
            'CLAIMING' { $HaCurMasterState = 3 }
            'FORCE CHANGE ' { $HaCurMasterState = 4 }
            default { $HaCurMasterState = -1 }
        }

        $xmlOutput += "<result>
			<channel>HA State</channel>
			<value>$($HaCurState)</value>
			<ValueLookup>prtg.citrix.adc.hacurstate</ValueLookup>
			</result>"

        $xmlOutput += "<result>
			<channel>HA Master State</channel>
			<value>$($HaCurMasterState)</value>
			<ValueLookup>prtg.citrix.adc.hacurmasterstate</ValueLookup>
			</result>"

        $xmlOutput += "<result>
			<channel>HA Sync Failures</channel>
			<value>$($ResultHaNode.haerrsyncfailure )</value>
			<unit>Count</unit>
			</result>"

        $xmlOutput += "<result>
			<channel>HA Prop Timeout</channel>
			<value>$($ResultHaNode.haerrproptimeout )</value>
			<unit>Count</unit>
			</result>"

        $TransTime = $ResultHaNode.transtime.Replace("  ", " 0")
        $TransTime = [datetime]::ParseExact($TransTime, "ddd MMM d HH:mm:ss yyyy", [cultureinfo]'en-US')
        $TransTimeHours = [math]::truncate(($ResultCurrentTime - $TransTime).TotalHours)

        $xmlOutput += "<result>
			<channel>Last Master Transition</channel>
			<value>$($TransTimeHours)</value>
			<unit>Custom</unit>
			<CustomUnit>hours</CustomUnit>
			</result>"
    }

}
#endregion High Availability

#region: Interface
if ($Interface) {
    $ResultInterface = Get-NSStat -session $Session -Type 'interface'

    foreach ($Result in $ResultInterface) {
        [double]$TotalBandwidth = $Result.txbytesrate + $Result.rxbytesrate
        $xmlOutput += "<result>
		<channel>$($Result.id) RX Bandwidth</channel>
        <value>$([math]::truncate($Result.rxbytesrate/125000))</value>
        <unit>Custom</unit>
        <CustomUnit>MBits</CustomUnit>
		</result>
		<result>
		<channel>$($Result.id) TX Bandwidth</channel>
        <value>$([math]::truncate($Result.txbytesrate/125000))</value>
        <unit>Custom</unit>
        <CustomUnit>MBits</CustomUnit>
		</result>
        <result>
		<channel>$($Result.id) Total Bandwidth</channel>
        <value>$([math]::truncate($TotalBandwidth/125000))</value>
        <unit>Custom</unit>
        <CustomUnit>MBits</CustomUnit>
		</result>
        <result>
		<channel>$($Result.id) RX Packets</channel>
		<value>$($Result.rxpktsrate)</value>
		<unit>Custom</unit>
		<CustomUnit>pkts</CustomUnit>
		</result>
		<result>
		<channel>$($Result.id) TX Packets</channel>
		<value>$($Result.txpktsrate)</value>
		<unit>Custom</unit>
		<CustomUnit>pkts</CustomUnit>
		</result>"
    }
}
#endregion Interface

$OutputText = $OutputText.Replace("<", "")
$OutputText = $OutputText.Replace(">", "")
$OutputText = $OutputText.Replace("#", "")
$xmlOutput = $xmlOutput + "<text>$($OutputText)</text>"

$xmlOutput += "</prtg>"

Disconnect-Netscaler -Session $session
$session = $null

#finish Script - Write Output

Write-Output $xmlOutput