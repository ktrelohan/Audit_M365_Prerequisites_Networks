#requires -Version 5.1
# Copyright (c) 2026 Kevin TRELOHAN
# Licensed under the MIT License.
# Project: https://github.com/ktrelohan/Audit_M365_Prerequisites_Networks
# See the LICENSE file in the project repository for full license information.

[CmdletBinding()]
param(
    [string]$JsonPath,

    [ValidateSet("All", "Teams", "Exchange", "SharePoint", "Common")]
    [string]$Service = "All",

    [switch]$RequiredOnly,

    [switch]$ExcludeDefault,

    [string]$OutputPath = ".\M365-NetworkTests",

    [int]$TimeoutMs = 5000
)

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$ClientRequestId = [guid]::NewGuid().Guid

$EndpointUrl = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=$ClientRequestId"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$CsvAll = Join-Path $OutputPath "M365_NetworkTests_$Timestamp.csv"
$CsvFailed = Join-Path $OutputPath "M365_NetworkFailures_$Timestamp.csv"


# ============================================================
# FONCTION DNS
# ============================================================

function Resolve-M365Host {

    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    try {

        $Addresses = [System.Net.Dns]::GetHostAddresses($ComputerName)

        $IpList = @(
            $Addresses |
            ForEach-Object {
                $_.IPAddressToString
            }
        )

        return [PSCustomObject]@{
            Success   = $true
            Addresses = ($IpList -join ",")
            Error     = $null
        }
    }
    catch {

        return [PSCustomObject]@{
            Success   = $false
            Addresses = $null
            Error     = $_.Exception.Message
        }
    }
}


# ============================================================
# FONCTION TEST TCP AVEC TIMEOUT
# ============================================================

function Test-TcpPort {

    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$Timeout = 5000
    )

    $TcpClient = $null
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {

        $TcpClient = New-Object System.Net.Sockets.TcpClient

        $ConnectTask = $TcpClient.ConnectAsync(
            $ComputerName,
            $Port
        )

        $Completed = $ConnectTask.Wait($Timeout)

        if (-not $Completed) {

            $Stopwatch.Stop()

            return [PSCustomObject]@{
                Success    = $false
                Status     = "TIMEOUT"
                DurationMs = $Stopwatch.ElapsedMilliseconds
                RemoteIP   = $null
                Error      = "Connection timeout"
            }
        }

        if (-not $TcpClient.Connected) {

            $Stopwatch.Stop()

            return [PSCustomObject]@{
                Success    = $false
                Status     = "TCP_FAIL"
                DurationMs = $Stopwatch.ElapsedMilliseconds
                RemoteIP   = $null
                Error      = "TCP connection failed"
            }
        }

        $RemoteEndpoint = $TcpClient.Client.RemoteEndPoint

        $Stopwatch.Stop()

        return [PSCustomObject]@{
            Success    = $true
            Status     = "OK"
            DurationMs = $Stopwatch.ElapsedMilliseconds
            RemoteIP   = $RemoteEndpoint.Address.IPAddressToString
            Error      = $null
        }
    }
    catch {

        $Stopwatch.Stop()

        return [PSCustomObject]@{
            Success    = $false
            Status     = "TCP_FAIL"
            DurationMs = $Stopwatch.ElapsedMilliseconds
            RemoteIP   = $null
            Error      = $_.Exception.Message
        }
    }
    finally {

        if ($null -ne $TcpClient) {
            $TcpClient.Dispose()
        }
    }
}


# ============================================================
# CHARGEMENT DU JSON
# ============================================================

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " MICROSOFT 365 NETWORK CONNECTIVITY TEST" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

try {

    if ($JsonPath) {

        if (-not (Test-Path -LiteralPath $JsonPath)) {
            throw "JSON file not found: $JsonPath"
        }

        Write-Host "Loading local JSON..." -ForegroundColor Cyan

        $JsonContent = Get-Content `
            -LiteralPath $JsonPath `
            -Raw

        $Endpoints = $JsonContent | ConvertFrom-Json
    }
    else {

        Write-Host "Downloading Microsoft 365 endpoints..." -ForegroundColor Cyan

        $Endpoints = Invoke-RestMethod `
            -Uri $EndpointUrl `
            -Method Get `
            -UseBasicParsing
    }
}
catch {

    Write-Host ""
    Write-Host "Unable to load Microsoft 365 endpoints." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    exit 1
}

$Endpoints = @($Endpoints)

Write-Host ""
Write-Host "Endpoint groups loaded: $($Endpoints.Count)" -ForegroundColor Green


# ============================================================
# FILTRES
# ============================================================

if ($Service -ne "All") {

    $ServiceArea = switch ($Service) {

        "Teams" {
            "Skype"
        }

        "Exchange" {
            "Exchange"
        }

        "SharePoint" {
            "SharePoint"
        }

        "Common" {
            "Common"
        }
    }

    $Endpoints = @(
        $Endpoints |
        Where-Object {
            $_.serviceArea -eq $ServiceArea
        }
    )
}


if ($RequiredOnly) {

    $Endpoints = @(
        $Endpoints |
        Where-Object {
            $_.required -eq $true
        }
    )
}


if ($ExcludeDefault) {

    $Endpoints = @(
        $Endpoints |
        Where-Object {
            $_.category -in @("Optimize", "Allow")
        }
    )
}


Write-Host "Endpoint groups after filtering: $($Endpoints.Count)" -ForegroundColor Yellow
Write-Host ""


# ============================================================
# RESULTATS
# ============================================================

$Results = New-Object System.Collections.Generic.List[object]


# ============================================================
# PARCOURS DU JSON
# ============================================================

foreach ($Endpoint in $Endpoints) {

    Write-Host ""
    Write-Host "--------------------------------------------" -ForegroundColor DarkGray

    Write-Host "ID       : $($Endpoint.id)"
    Write-Host "Service  : $($Endpoint.serviceAreaDisplayName)"
    Write-Host "Category : $($Endpoint.category)"
    Write-Host "Required : $($Endpoint.required)"


    # --------------------------------------------------------
    # Ports TCP
    # --------------------------------------------------------

    $TcpPorts = @()

    if ($Endpoint.tcpPorts) {

        $TcpPorts = @(
            $Endpoint.tcpPorts.ToString().Split(",") |
            ForEach-Object {
                $_.Trim()
            } |
            Where-Object {
                $_ -match '^\d+$'
            } |
            ForEach-Object {
                [int]$_
            } |
            Sort-Object -Unique
        )
    }


    # --------------------------------------------------------
    # Ports UDP
    # --------------------------------------------------------

    $UdpPorts = @()

    if ($Endpoint.udpPorts) {

        $UdpPorts = @(
            $Endpoint.udpPorts.ToString().Split(",") |
            ForEach-Object {
                $_.Trim()
            } |
            Where-Object {
                $_ -match '^\d+$'
            } |
            ForEach-Object {
                [int]$_
            } |
            Sort-Object -Unique
        )
    }


    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    $Urls = @()

    if ($Endpoint.urls) {
        $Urls = @($Endpoint.urls)
    }


    foreach ($Url in $Urls) {

        if ([string]::IsNullOrWhiteSpace($Url)) {
            continue
        }


        # ====================================================
        # WILDCARD
        # ====================================================

        if ($Url.Contains("*")) {

            Write-Host "  WILDCARD : $Url" -ForegroundColor Yellow

            $Results.Add(
                [PSCustomObject]@{
                    Timestamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Id            = $Endpoint.id
                    ServiceArea   = $Endpoint.serviceArea
                    Service       = $Endpoint.serviceAreaDisplayName
                    Category      = $Endpoint.category
                    Required      = $Endpoint.required
                    Destination   = $Url
                    Protocol      = "N/A"
                    Port          = $null
                    DNS           = "N/A"
                    ResolvedIP    = $null
                    RemoteIP      = $null
                    Status        = "WILDCARD"
                    DurationMs    = $null
                    Details       = "Wildcard cannot be tested directly"
                }
            )

            continue
        }


        # ====================================================
        # DNS
        # ====================================================

        $DnsResult = Resolve-M365Host -ComputerName $Url


        if ($DnsResult.Success) {

            Write-Host "  DNS OK   : " -ForegroundColor Green -NoNewline
            Write-Host "$Url -> $($DnsResult.Addresses)"
        }
        else {

            Write-Host "  DNS FAIL : " -ForegroundColor Red -NoNewline
            Write-Host $Url
        }


        # ====================================================
        # SI DNS EN ECHEC
        # ====================================================

        if (-not $DnsResult.Success) {

            if ($TcpPorts.Count -eq 0) {

                $Results.Add(
                    [PSCustomObject]@{
                        Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Id          = $Endpoint.id
                        ServiceArea = $Endpoint.serviceArea
                        Service     = $Endpoint.serviceAreaDisplayName
                        Category    = $Endpoint.category
                        Required    = $Endpoint.required
                        Destination = $Url
                        Protocol    = "TCP"
                        Port        = $null
                        DNS         = $false
                        ResolvedIP  = $null
                        RemoteIP    = $null
                        Status      = "DNS_FAIL"
                        DurationMs  = $null
                        Details     = $DnsResult.Error
                    }
                )
            }
            else {

                foreach ($Port in $TcpPorts) {

                    $Results.Add(
                        [PSCustomObject]@{
                            Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Id          = $Endpoint.id
                            ServiceArea = $Endpoint.serviceArea
                            Service     = $Endpoint.serviceAreaDisplayName
                            Category    = $Endpoint.category
                            Required    = $Endpoint.required
                            Destination = $Url
                            Protocol    = "TCP"
                            Port        = $Port
                            DNS         = $false
                            ResolvedIP  = $null
                            RemoteIP    = $null
                            Status      = "DNS_FAIL"
                            DurationMs  = $null
                            Details     = $DnsResult.Error
                        }
                    )
                }
            }

            continue
        }


        # ====================================================
        # AUCUN PORT TCP
        # ====================================================

        if ($TcpPorts.Count -eq 0) {

            $Results.Add(
                [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Id          = $Endpoint.id
                    ServiceArea = $Endpoint.serviceArea
                    Service     = $Endpoint.serviceAreaDisplayName
                    Category    = $Endpoint.category
                    Required    = $Endpoint.required
                    Destination = $Url
                    Protocol    = "N/A"
                    Port        = $null
                    DNS         = $true
                    ResolvedIP  = $DnsResult.Addresses
                    RemoteIP    = $null
                    Status      = "NO_TCP_PORT"
                    DurationMs  = $null
                    Details     = "No TCP port specified"
                }
            )

            continue
        }


        # ====================================
        # TEST TCP
        # ====================================================

        foreach ($Port in $TcpPorts) {

            Write-Host "       TCP $Port : " -NoNewline

            $TcpResult = Test-TcpPort `
                -ComputerName $Url `
                -Port $Port `
                -Timeout $TimeoutMs


            if ($TcpResult.Success) {

                Write-Host "OK" -ForegroundColor Green
            }
            elseif ($TcpResult.Status -eq "TIMEOUT") {

                Write-Host "TIMEOUT" -ForegroundColor Yellow
            }
            else {

                Write-Host "FAIL" -ForegroundColor Red
            }


            $Results.Add(
                [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Id          = $Endpoint.id
                    ServiceArea = $Endpoint.serviceArea
                    Service     = $Endpoint.serviceAreaDisplayName
                    Category    = $Endpoint.category
                    Required    = $Endpoint.required
                    Destination = $Url
                    Protocol    = "TCP"
                    Port        = $Port
                    DNS         = $true
                    ResolvedIP  = $DnsResult.Addresses
                    RemoteIP    = $TcpResult.RemoteIP
                    Status      = $TcpResult.Status
                    DurationMs  = $TcpResult.DurationMs
                    Details     = $TcpResult.Error
                }
            )
        }


        # ====================================================
        # INFORMATIONS UDP
        # ====================================================

        foreach ($Port in $UdpPorts) {

            Write-Host "       UDP $Port : NOT TESTED" -ForegroundColor DarkYellow

            $Results.Add(
                [PSCustomObject]@{
                    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Id          = $Endpoint.id
                    ServiceArea = $Endpoint.serviceArea
                    Service     = $Endpoint.serviceAreaDisplayName
                    Category    = $Endpoint.category
                    Required    = $Endpoint.required
                    Destination = $Url
                    Protocol    = "UDP"
                    Port        = $Port
                    DNS         = $true
                    ResolvedIP  = $DnsResult.Addresses
                    RemoteIP    = $null
                    Status      = "NOT_TESTED"
                    DurationMs  = $null
                    Details     = "UDP connectivity not tested"
                }
            )
        }
    }


    # --------------------------------------------------------
    # Plages IP / CIDR
    # --------------------------------------------------------

    foreach ($IpRange in @($Endpoint.ips)) {

        if ([string]::IsNullOrWhiteSpace($IpRange)) {
            continue
        }

        $Results.Add(
            [PSCustomObject]@{
                Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Id          = $Endpoint.id
                ServiceArea = $Endpoint.serviceArea
                Service     = $Endpoint.serviceAreaDisplayName
                Category    = $Endpoint.category
                Required    = $Endpoint.required
                Destination = $IpRange
                Protocol    = "N/A"
                Port        = $null
                DNS         = "N/A"
                ResolvedIP  = $null
                RemoteIP    = $null
                Status      = "CIDR_INFO"
                DurationMs  = $null
                Details     = "Microsoft 365 IP range"
            }
        )
    }
}


# ============================================================
# EXPORT
# ============================================================

try {

    $Results |
        Export-Csv `
            -Path $CsvAll `
            -Delimiter ";" `
            -NoTypeInformation `
            -Encoding UTF8


    $Failures = @(
        $Results |
        Where-Object {
            $_.Status -in @(
                "DNS_FAIL",
                "TCP_FAIL",
                "TIMEOUT"
            )
        }
    )


    $Failures |
        Export-Csv `
            -Path $CsvFailed `
            -Delimiter ";" `
            -NoTypeInformation `
            -Encoding UTF8
}
catch {

    Write-Host ""
    Write-Host "Error while exporting report." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    exit 1
}


# ============================================================
# SYNTHESE
# ============================================================

$SuccessCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "OK"
    }
).Count


$TcpFailCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "TCP_FAIL"
    }
).Count


$TimeoutCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "TIMEOUT"
    }
).Count


$DnsFailCount = @(
    $Results |
    Where-Object {
        $_.Status -eq "DNS_FAIL"
    }
).Count


Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " RESULTS" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

Write-Host ""

Write-Host "TCP OK       : " -NoNewline
Write-Host $SuccessCount -ForegroundColor Green

Write-Host "TCP FAIL     : " -NoNewline
Write-Host $TcpFailCount -ForegroundColor Red

Write-Host "TCP TIMEOUT  : " -NoNewline
Write-Host $TimeoutCount -ForegroundColor Yellow

Write-Host "DNS FAIL     : " -NoNewline
Write-Host $DnsFailCount -ForegroundColor Red


# ============================================================
# ECHECS
# ============================================================

if ($Failures.Count -gt 0) {

    Write-Host ""
    Write-Host "FAILED ENDPOINTS" -ForegroundColor Red
    Write-Host ""

    $Failures |
        Select-Object `
            Service,
            Category,
            Required,
            Destination,
            Protocol,
            Port,
            Status,
            DurationMs |
        Format-Table -AutoSize
}


# ============================================================
# FICHIERS
# ============================================================

Write-Host ""
Write-Host "Full report:"
Write-Host $CsvAll -ForegroundColor Cyan

Write-Host ""
Write-Host "Failures report:"
Write-Host $CsvFailed -ForegroundColor Cyan

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ""