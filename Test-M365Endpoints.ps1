# Requires -Version 5.2
# Copyright (c) 2026 Kevin TRELOHAN
# Licensed under the MIT License.
# Project: https://github.com/ktrelohan/Audit_M365_Prerequisites_Networks

<#
.SYNOPSIS
    Tests Microsoft 365 and Microsoft Copilot network prerequisites.

.DESCRIPTION
    Downloads the Microsoft 365 worldwide endpoint feed (or reads a local JSON file),
    tests DNS and TCP connectivity, and adds the Microsoft Copilot endpoints and
    network requirements documented by Microsoft.

    Copilot tests include:
      - *.cloud.microsoft and copilot.cloud.microsoft prerequisites
      - WSS prerequisites for *.office.com, *.cloud.microsoft and
        copilot.cloud.microsoft
      - Copilot update, configuration, download and sign-in endpoints
      - Optional Delivery Optimization allow-list information
      - HTTP/HTTPS application-layer probes

    A WSS preflight validates DNS, TCP 443, TLS and HTTPS reachability. A complete
    WebSocket upgrade can't be tested reliably without the private application path
    and authentication context used by Copilot. Use Microsoft's browser-based test
    for the final WSS validation:
    https://connectivity.m365.cloud.microsoft/copilot

.PARAMETER Service
    All, Teams, Exchange, SharePoint, Common, or Copilot.

.PARAMETER RequiredOnly
    Excludes optional endpoint definitions.

.PARAMETER ExcludeDefault
    For the Microsoft 365 endpoint feed, keeps only Optimize and Allow categories.

.PARAMETER SkipHttpProbe
    Runs DNS and TCP tests only. WSS entries are then reported as TCP prerequisites.

.PARAMETER IncludeDeliveryOptimization
    Includes the optional Delivery Optimization wildcard and inbound TCP 7680
    configuration checks. Inbound TCP 7680 is informational because an outbound
    client test can't prove that the local firewall accepts inbound traffic.

.NOTES
    Microsoft documentation used:
    https://learn.microsoft.com/microsoft-365/copilot/microsoft-copilot-requirements
    https://learn.microsoft.com/microsoft-365/copilot/add-copilot-endpoints-allowlist
#>

[CmdletBinding()]
param(
    [string]$JsonPath,

    [ValidateSet("All", "Teams", "Exchange", "SharePoint", "Common", "Copilot")]
    [string]$Service = "All",

    [switch]$RequiredOnly,

    [switch]$ExcludeDefault,

    [switch]$SkipHttpProbe,

    [switch]$IncludeDeliveryOptimization,

    [string]$OutputPath = ".\M365-NetworkTests",

    [ValidateRange(250, 120000)]
    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = "Stop"
$ClientRequestId = [guid]::NewGuid().Guid
$EndpointUrl = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$ClientRequestId"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$CopilotRequirementsUrl = "https://learn.microsoft.com/microsoft-365/copilot/microsoft-copilot-requirements"
$CopilotAllowListUrl = "https://learn.microsoft.com/microsoft-365/copilot/add-copilot-endpoints-allowlist"
$CopilotConnectivityTestUrl = "https://connectivity.m365.cloud.microsoft/copilot"

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$CsvAll = Join-Path $OutputPath "M365_NetworkTests_$Timestamp.csv"
$CsvFailed = Join-Path $OutputPath "M365_NetworkFailures_$Timestamp.csv"
$Results = New-Object System.Collections.Generic.List[object]

function Resolve-NetworkHost {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    try {
        $Addresses = [System.Net.Dns]::GetHostAddresses($ComputerName)
        $IpList = @($Addresses | ForEach-Object { $_.IPAddressToString })
        [PSCustomObject]@{
            Success   = $true
            Addresses = ($IpList -join ",")
            Error     = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Success   = $false
            Addresses = $null
            Error     = $_.Exception.Message
        }
    }
}

function Test-TcpPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$Timeout = 5000
    )

    $TcpClient = $null
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $ConnectTask = $TcpClient.ConnectAsync($ComputerName, $Port)
        $Completed = $ConnectTask.Wait($Timeout)

        if (-not $Completed) {
            $Stopwatch.Stop()
            return [PSCustomObject]@{
                Success = $false; Status = "TIMEOUT"
                DurationMs = $Stopwatch.ElapsedMilliseconds
                RemoteIP = $null; Error = "Connection timeout"
            }
        }

        if (-not $TcpClient.Connected) {
            $Stopwatch.Stop()
            return [PSCustomObject]@{
                Success = $false; Status = "TCP_FAIL"
                DurationMs = $Stopwatch.ElapsedMilliseconds
                RemoteIP = $null; Error = "TCP connection failed"
            }
        }

        $RemoteEndpoint = $TcpClient.Client.RemoteEndPoint
        $Stopwatch.Stop()
        [PSCustomObject]@{
            Success = $true; Status = "OK"
            DurationMs = $Stopwatch.ElapsedMilliseconds
            RemoteIP = $RemoteEndpoint.Address.IPAddressToString
            Error = $null
        }
    }
    catch {
        $Stopwatch.Stop()
        [PSCustomObject]@{
            Success = $false; Status = "TCP_FAIL"
            DurationMs = $Stopwatch.ElapsedMilliseconds
            RemoteIP = $null; Error = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $TcpClient) { $TcpClient.Dispose() }
    }
}

function Test-HttpEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uri]$Uri,
        [int]$Timeout = 5000
    )

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $TimeoutSeconds = [Math]::Max(1, [Math]::Ceiling($Timeout / 1000))

    try {
        $Response = Invoke-WebRequest -Uri $Uri.AbsoluteUri -Method Head `
            -UseBasicParsing -MaximumRedirection 5 -TimeoutSec $TimeoutSeconds
        $Stopwatch.Stop()

        return [PSCustomObject]@{
            Success = $true
            Status = "HTTP_OK"
            StatusCode = [int]$Response.StatusCode
            FinalUri = if ($Response.BaseResponse.ResponseUri) {
                $Response.BaseResponse.ResponseUri.AbsoluteUri
            } else { $Uri.AbsoluteUri }
            DurationMs = $Stopwatch.ElapsedMilliseconds
            Error = $null
        }
    }
    catch {
        $Response = $_.Exception.Response

        # HTTP 3xx/4xx/5xx still proves DNS, TCP and TLS/application reachability.
        if ($null -ne $Response) {
            $Stopwatch.Stop()
            $StatusCode = $null
            try { $StatusCode = [int]$Response.StatusCode } catch { }
            try { $Response.Close() } catch { }

            return [PSCustomObject]@{
                Success = $true
                Status = "HTTP_REACHABLE"
                StatusCode = $StatusCode
                FinalUri = $Uri.AbsoluteUri
                DurationMs = $Stopwatch.ElapsedMilliseconds
                Error = $_.Exception.Message
            }
        }

        $Stopwatch.Stop()
        [PSCustomObject]@{
            Success = $false
            Status = "HTTP_FAIL"
            StatusCode = $null
            FinalUri = $Uri.AbsoluteUri
            DurationMs = $Stopwatch.ElapsedMilliseconds
            Error = $_.Exception.Message
        }
    }
}

function Add-NetworkResult {
    param(
        [string]$Id,
        [string]$ServiceArea,
        [string]$ServiceName,
        [string]$Category,
        [bool]$Required,
        [string]$Destination,
        [string]$Protocol,
        [Nullable[int]]$Port,
        [object]$Dns,
        [string]$ResolvedIP,
        [string]$RemoteIP,
        [string]$Status,
        [Nullable[long]]$DurationMs,
        [string]$Details,
        [string]$TestType = "Connectivity",
        [string]$Source = "Microsoft 365 endpoint service"
    )

    $Results.Add([PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Id = $Id
        ServiceArea = $ServiceArea
        Service = $ServiceName
        Category = $Category
        Required = $Required
        Destination = $Destination
        Protocol = $Protocol
        Port = $Port
        TestType = $TestType
        DNS = $Dns
        ResolvedIP = $ResolvedIP
        RemoteIP = $RemoteIP
        Status = $Status
        DurationMs = $DurationMs
        Details = $Details
        Source = $Source
    })
}

function Get-CopilotEndpointDefinitions {
    $Definitions = New-Object System.Collections.Generic.List[object]

    function Add-CopilotDefinition {
        param(
            [string]$Id, [string]$Purpose, [string]$HostName,
            [ValidateSet("HTTP", "HTTPS", "WSS", "INFO")][string]$Protocol,
            [Nullable[int]]$Port, [bool]$Required = $true,
            [string]$Category = "Required", [string]$Notes = "",
            [string]$Source = $CopilotAllowListUrl,
            [string]$RequestPath = "/"
        )
        $Definitions.Add([PSCustomObject]@{
            Id = $Id; Purpose = $Purpose; HostName = $HostName
            Protocol = $Protocol; Port = $Port; Required = $Required
            Category = $Category; Notes = $Notes; Source = $Source
            RequestPath = $RequestPath
        })
    }

    # Core Copilot application and the unified cloud.microsoft domain.
    Add-CopilotDefinition "COP-CORE-001" "Copilot application" "copilot.cloud.microsoft" "HTTPS" 443 $true "Required" "Primary Copilot URL; allow the complete *.cloud.microsoft domain." $CopilotRequirementsUrl
    Add-CopilotDefinition "COP-CORE-002" "Microsoft connectivity test" "connectivity.m365.cloud.microsoft" "HTTPS" 443 $true "Diagnostic" "Microsoft browser-based Copilot connectivity test." $CopilotRequirementsUrl "/copilot"

    # WSS prerequisites. These are representative FQDN preflight tests for the
    # documented wildcard domains, not authenticated application WebSocket upgrades.
    Add-CopilotDefinition "COP-WSS-001" "WSS prerequisite for *.office.com" "www.office.com" "WSS" 443 $true "Required" "Representative preflight for the required *.office.com wildcard." $CopilotRequirementsUrl
    Add-CopilotDefinition "COP-WSS-002" "WSS prerequisite for *.cloud.microsoft" "copilot.cloud.microsoft" "WSS" 443 $true "Required" "Representative preflight for the required *.cloud.microsoft wildcard." $CopilotRequirementsUrl
    Add-CopilotDefinition "COP-WSS-003" "WSS prerequisite for Copilot" "copilot.cloud.microsoft" "WSS" 443 $true "Required" "Final WSS validation: $CopilotConnectivityTestUrl" $CopilotRequirementsUrl

    # Update and configuration services.
    Add-CopilotDefinition "COP-UPD-001" "Copilot update service" "msedge.api.cdp.microsoft.com" "HTTPS" 443 $true
    Add-CopilotDefinition "COP-CFG-001" "Experimentation and configuration" "config.edge.skype.com" "HTTPS" 443 $true

    # Download locations.
    foreach ($HostName in @(
        "msedge.f.tlu.dl.delivery.mp.microsoft.com",
        "msedge.f.dl.delivery.mp.microsoft.com",
        "msedge.b.tlu.dl.delivery.mp.microsoft.com",
        "msedge.b.dl.delivery.mp.microsoft.com"
    )) {
        Add-CopilotDefinition "COP-DL-HTTP" "Copilot download" $HostName "HTTP" 80 $true "Required" "Can be simplified in allow lists with *.dl.delivery.mp.microsoft.com."
    }

    foreach ($HostName in @(
        "msedge.sf.tlu.dl.delivery.mp.microsoft.com",
        "msedge.sf.dl.delivery.mp.microsoft.com",
        "msedge.sb.tlu.dl.delivery.mp.microsoft.com",
        "msedge.sb.dl.delivery.mp.microsoft.com"
    )) {
        Add-CopilotDefinition "COP-DL-HTTPS" "Copilot secure download" $HostName "HTTPS" 443 $true "Required" "Can be simplified in allow lists with *.dl.delivery.mp.microsoft.com."
    }

    # Sign-in and Microsoft 365 dependencies listed by Microsoft.
    foreach ($HostName in @(
        "login.live.com",
        "login.microsoftonline.com",
        "login.microsoft.com",
        "login.windows.net",
        "odc.officeapps.live.com",
        "graph.microsoft.com",
        "substrate.office.com",
        "privacy.microsoft.com",
        "cdn.odc.officeapps.live.com",
        "logincdn.msauth.net"
    )) {
        Add-CopilotDefinition "COP-AUTH-001" "Copilot sign-in dependency" $HostName "HTTPS" 443 $true
    }

    if ($IncludeDeliveryOptimization) {
        Add-CopilotDefinition "COP-DO-001" "Delivery Optimization wildcard" "*.do.dsp.mp.microsoft.com" "INFO" $null $false "Optional" "Allow HTTP 80 and HTTPS 443. Wildcard can't be tested directly."
        Add-CopilotDefinition "COP-DO-002" "Delivery Optimization peer traffic" "Local device" "INFO" 7680 $false "Optional" "TCP 7680 must be open inbound. This script can't validate inbound firewall/NAT behavior from the same client."
    }

    # Windows PowerShell 5.1 peut lever Â« Les types des arguments ne correspondent pas Â»
    # lorsque @() est applique directement a une List[object]. On enumere donc
    # explicitement la liste dans le pipeline.
    return $Definitions | ForEach-Object { $_ }
}

function Invoke-EndpointTest {
    param(
        [string]$Id,
        [string]$ServiceArea,
        [string]$ServiceName,
        [string]$Category,
        [bool]$Required,
        [string]$HostName,
        [string]$Protocol,
        [Nullable[int]]$Port,
        [string]$Purpose,
        [string]$Source,
        [string]$RequestPath = "/"
    )

    Write-Host "  $Protocol $HostName$(if ($Port) { ":$Port" })" -ForegroundColor Cyan

    if ($Protocol -eq "INFO" -or $HostName.Contains("*")) {
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $Port -Dns "N/A" -ResolvedIP $null `
            -RemoteIP $null -Status "INFORMATION" -DurationMs $null `
            -Details $Purpose -TestType "Configuration" -Source $Source
        return
    }

    $DnsResult = Resolve-NetworkHost -ComputerName $HostName
    if (-not $DnsResult.Success) {
        Write-Host "       DNS FAIL" -ForegroundColor Red
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $Port -Dns $false -ResolvedIP $null `
            -RemoteIP $null -Status "DNS_FAIL" -DurationMs $null `
            -Details $DnsResult.Error -TestType "DNS" -Source $Source
        return
    }

    if ($null -eq $Port) {
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $null -Dns $true -ResolvedIP $DnsResult.Addresses `
            -RemoteIP $null -Status "DNS_OK" -DurationMs $null `
            -Details $Purpose -TestType "DNS" -Source $Source
        return
    }

    $TcpResult = Test-TcpPort -ComputerName $HostName -Port $Port -Timeout $TimeoutMs
    if (-not $TcpResult.Success) {
        Write-Host "       $($TcpResult.Status)" -ForegroundColor Red
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $Port -Dns $true -ResolvedIP $DnsResult.Addresses `
            -RemoteIP $TcpResult.RemoteIP -Status $TcpResult.Status `
            -DurationMs $TcpResult.DurationMs -Details $TcpResult.Error `
            -TestType "TCP" -Source $Source
        return
    }

    if ($SkipHttpProbe -or $Protocol -notin @("HTTP", "HTTPS", "WSS")) {
        $Status = if ($Protocol -eq "WSS") { "WSS_TCP_PREREQUISITE_OK" } else { "OK" }
        $Details = if ($Protocol -eq "WSS") {
            "DNS and TCP 443 succeeded. HTTPS/WSS application probe skipped. $Purpose"
        } else { $Purpose }

        Write-Host "       $Status" -ForegroundColor Green
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $Port -Dns $true -ResolvedIP $DnsResult.Addresses `
            -RemoteIP $TcpResult.RemoteIP -Status $Status `
            -DurationMs $TcpResult.DurationMs -Details $Details `
            -TestType "TCP" -Source $Source
        return
    }

    $Scheme = if ($Protocol -eq "HTTP") { "http" } else { "https" }
    $Uri = [uri]("{0}://{1}{2}" -f $Scheme, $HostName, $RequestPath)
    $HttpResult = Test-HttpEndpoint -Uri $Uri -Timeout $TimeoutMs

    if ($HttpResult.Success) {
        $Status = if ($Protocol -eq "WSS") { "WSS_PREFLIGHT_OK" } else { $HttpResult.Status }
        $DetailParts = @(
            $Purpose
            "HTTP status: $($HttpResult.StatusCode)"
        )
        if ($Protocol -eq "WSS") {
            $DetailParts += "DNS, TCP 443, TLS and HTTPS succeeded; run $CopilotConnectivityTestUrl for a complete browser WSS validation."
        }
        if ($HttpResult.Error) { $DetailParts += $HttpResult.Error }

        Write-Host "       $Status ($($HttpResult.StatusCode))" -ForegroundColor Green
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $Port -Dns $true -ResolvedIP $DnsResult.Addresses `
            -RemoteIP $TcpResult.RemoteIP -Status $Status `
            -DurationMs ($TcpResult.DurationMs + $HttpResult.DurationMs) `
            -Details ($DetailParts -join " ") -TestType $(if ($Protocol -eq "WSS") { "WSS preflight" } else { "HTTP" }) `
            -Source $Source
    }
    else {
        Write-Host "       HTTP/TLS FAIL" -ForegroundColor Red
        Add-NetworkResult -Id $Id -ServiceArea $ServiceArea -ServiceName $ServiceName `
            -Category $Category -Required $Required -Destination $HostName `
            -Protocol $Protocol -Port $Port -Dns $true -ResolvedIP $DnsResult.Addresses `
            -RemoteIP $TcpResult.RemoteIP -Status "HTTP_FAIL" `
            -DurationMs ($TcpResult.DurationMs + $HttpResult.DurationMs) `
            -Details $HttpResult.Error -TestType $(if ($Protocol -eq "WSS") { "WSS preflight" } else { "HTTP" }) `
            -Source $Source
    }
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host " MICROSOFT 365 AND COPILOT NETWORK CONNECTIVITY TEST" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# Microsoft 365 endpoint feed
$Endpoints = @()
if ($Service -ne "Copilot") {
    try {
        if ($JsonPath) {
            if (-not (Test-Path -LiteralPath $JsonPath)) {
                throw "JSON file not found: $JsonPath"
            }
            Write-Host "Loading local Microsoft 365 endpoint JSON..." -ForegroundColor Cyan
            $EndpointResponse = Get-Content -LiteralPath $JsonPath -Raw | ConvertFrom-Json
        }
        else {
            Write-Host "Downloading Microsoft 365 endpoints..." -ForegroundColor Cyan
            $EndpointResponse = Invoke-RestMethod -Uri $EndpointUrl -Method Get -UseBasicParsing
        }

        # Enumeration explicite pour Windows PowerShell 5.1. Invoke-RestMethod peut
        # sinon conserver le tableau JSON comme un objet unique (Count = 1).
        $Endpoints = @($EndpointResponse | ForEach-Object { $_ })
    }
    catch {
        Write-Host "Unable to load Microsoft 365 endpoints." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        exit 1
    }

    if ($Service -ne "All") {
        $ServiceArea = switch ($Service) {
            "Teams" { "Skype" }
            "Exchange" { "Exchange" }
            "SharePoint" { "SharePoint" }
            "Common" { "Common" }
        }
        $Endpoints = @($Endpoints | Where-Object { $_.serviceArea -eq $ServiceArea })
    }

    if ($RequiredOnly) {
        $Endpoints = @($Endpoints | Where-Object { $_.required -eq $true })
    }

    if ($ExcludeDefault) {
        $Endpoints = @($Endpoints | Where-Object { $_.category -in @("Optimize", "Allow") })
    }

    Write-Host "Microsoft 365 endpoint groups: $($Endpoints.Count)" -ForegroundColor Yellow

    foreach ($Endpoint in $Endpoints) {
        $TcpPorts = @()
        if ($Endpoint.tcpPorts) {
            $TcpPorts = @($Endpoint.tcpPorts.ToString().Split(",") |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^\d+$' } |
                ForEach-Object { [int]$_ } | Sort-Object -Unique)
        }

        $UdpPorts = @()
        if ($Endpoint.udpPorts) {
            $UdpPorts = @($Endpoint.udpPorts.ToString().Split(",") |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^\d+$' } |
                ForEach-Object { [int]$_ } | Sort-Object -Unique)
        }

        foreach ($Url in @($Endpoint.urls)) {
            if ([string]::IsNullOrWhiteSpace($Url)) { continue }

            if ($Url.Contains("*")) {
                Add-NetworkResult -Id $Endpoint.id -ServiceArea $Endpoint.serviceArea `
                    -ServiceName $Endpoint.serviceAreaDisplayName -Category $Endpoint.category `
                    -Required ([bool]$Endpoint.required) -Destination $Url -Protocol "N/A" `
                    -Port $null -Dns "N/A" -ResolvedIP $null -RemoteIP $null `
                    -Status "WILDCARD" -DurationMs $null `
                    -Details "Wildcard must be allowed with its required subdomains; it can't be tested directly." `
                    -TestType "Configuration"
                continue
            }

            if ($TcpPorts.Count -eq 0) {
                $DnsResult = Resolve-NetworkHost -ComputerName $Url
                Add-NetworkResult -Id $Endpoint.id -ServiceArea $Endpoint.serviceArea `
                    -ServiceName $Endpoint.serviceAreaDisplayName -Category $Endpoint.category `
                    -Required ([bool]$Endpoint.required) -Destination $Url -Protocol "N/A" `
                    -Port $null -Dns $DnsResult.Success -ResolvedIP $DnsResult.Addresses `
                    -RemoteIP $null -Status $(if ($DnsResult.Success) { "DNS_OK" } else { "DNS_FAIL" }) `
                    -DurationMs $null -Details $DnsResult.Error -TestType "DNS"
            }
            else {
                foreach ($Port in $TcpPorts) {
                    Invoke-EndpointTest -Id $Endpoint.id -ServiceArea $Endpoint.serviceArea `
                        -ServiceName $Endpoint.serviceAreaDisplayName -Category $Endpoint.category `
                        -Required ([bool]$Endpoint.required) -HostName $Url -Protocol "TCP" `
                        -Port $Port -Purpose "Microsoft 365 endpoint" `
                        -Source "Microsoft 365 endpoint service"
                }
            }

            foreach ($Port in $UdpPorts) {
                Add-NetworkResult -Id $Endpoint.id -ServiceArea $Endpoint.serviceArea `
                    -ServiceName $Endpoint.serviceAreaDisplayName -Category $Endpoint.category `
                    -Required ([bool]$Endpoint.required) -Destination $Url -Protocol "UDP" `
                    -Port $Port -Dns "N/A" -ResolvedIP $null -RemoteIP $null `
                    -Status "NOT_TESTED" -DurationMs $null `
                    -Details "UDP connectivity isn't tested by this script." -TestType "Configuration"
            }
        }

        foreach ($IpRange in @($Endpoint.ips)) {
            if ([string]::IsNullOrWhiteSpace($IpRange)) { continue }
            Add-NetworkResult -Id $Endpoint.id -ServiceArea $Endpoint.serviceArea `
                -ServiceName $Endpoint.serviceAreaDisplayName -Category $Endpoint.category `
                -Required ([bool]$Endpoint.required) -Destination $IpRange -Protocol "N/A" `
                -Port $null -Dns "N/A" -ResolvedIP $null -RemoteIP $null `
                -Status "CIDR_INFO" -DurationMs $null -Details "Microsoft 365 IP range" `
                -TestType "Configuration"
        }
    }
}

# Microsoft Copilot endpoint requirements
if ($Service -in @("All", "Copilot")) {
    Write-Host ""
    Write-Host "Testing Microsoft Copilot requirements..." -ForegroundColor Magenta
    $CopilotDefinitions = @(Get-CopilotEndpointDefinitions)
    if ($RequiredOnly) {
        $CopilotDefinitions = @($CopilotDefinitions | Where-Object { $_.Required })
    }

    foreach ($Definition in $CopilotDefinitions) {
        Invoke-EndpointTest -Id $Definition.Id -ServiceArea "Copilot" `
            -ServiceName "Microsoft Copilot" -Category $Definition.Category `
            -Required $Definition.Required -HostName $Definition.HostName `
            -Protocol $Definition.Protocol -Port $Definition.Port `
            -Purpose $("{0}. {1}" -f $Definition.Purpose, $Definition.Notes) `
            -Source $Definition.Source -RequestPath $Definition.RequestPath
    }
}

# Export
try {
    $Results | Export-Csv -Path $CsvAll -Delimiter ";" -NoTypeInformation -Encoding UTF8

    $FailureStatuses = @("DNS_FAIL", "TCP_FAIL", "TIMEOUT", "HTTP_FAIL")
    $Failures = @($Results | Where-Object { $_.Status -in $FailureStatuses })
    $Failures | Export-Csv -Path $CsvFailed -Delimiter ";" -NoTypeInformation -Encoding UTF8
}
catch {
    Write-Host "Error while exporting report." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

$SuccessStatuses = @("OK", "DNS_OK", "HTTP_OK", "HTTP_REACHABLE", "WSS_PREFLIGHT_OK", "WSS_TCP_PREREQUISITE_OK")
$SuccessCount = @($Results | Where-Object { $_.Status -in $SuccessStatuses }).Count
$FailureCount = $Failures.Count
$InfoCount = @($Results | Where-Object { $_.Status -in @("INFORMATION", "WILDCARD", "CIDR_INFO", "NOT_TESTED") }).Count

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " RESULTS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Successful tests : " -NoNewline; Write-Host $SuccessCount -ForegroundColor Green
Write-Host "Failed tests     : " -NoNewline; Write-Host $FailureCount -ForegroundColor Red
Write-Host "Information only : " -NoNewline; Write-Host $InfoCount -ForegroundColor Yellow

if ($Failures.Count -gt 0) {
    Write-Host ""
    Write-Host "FAILED ENDPOINTS" -ForegroundColor Red
    $Failures | Select-Object Service, Category, Required, Destination, Protocol, Port, TestType, Status, DurationMs |
        Format-Table -AutoSize
}

if ($Service -in @("All", "Copilot")) {
    Write-Host ""
    Write-Host "Complete Copilot WSS validation:" -ForegroundColor Yellow
    Write-Host $CopilotConnectivityTestUrl -ForegroundColor Cyan
    Write-Host "Avoid TLS inspection and aggressive proxy timeouts for Copilot WSS traffic." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Full report     : $CsvAll" -ForegroundColor Cyan
Write-Host "Failures report : $CsvFailed" -ForegroundColor Cyan
Write-Host "Done." -ForegroundColor Green
