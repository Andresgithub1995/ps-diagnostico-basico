<#
.SYNOPSIS
  Diagnóstico básico (seguro) para PCs de casa en Windows.

.DESCRIPTION
  Recolecta información de sistema, CPU/RAM, disco, red, conectividad,
  DNS, servicios, eventos y drivers. NO cambia configuraciones.
  Puede imprimir en consola y exportar un reporte a JSON/TXT.

.USAGE
  # Ejecutar todo en consola
  .\diagnostico.ps1 -All

  # Solo red
  .\diagnostico.ps1 -Network

  # Exportar reporte completo
  .\diagnostico.ps1 -All -ExportJson -OutPath ".\reporte.json"
  .\diagnostico.ps1 -All -ExportTxt  -OutPath ".\reporte.txt"

  # Abrir menú interactivo
  .\diagnostico.ps1 -Menu

.NOTES
  Autor: Andres
  Requisitos: PowerShell 5.1+ (Windows 10/11). Funciona mejor en PowerShell 7+.
#>

[CmdletBinding()]
param(
  [switch]$All,
  [switch]$System,
  [switch]$Performance,
  [switch]$Disk,
  [switch]$Network,
  [switch]$Connectivity,
  [switch]$Dns,
  [switch]$Services,
  [switch]$Events,
  [switch]$Drivers,
  [switch]$Menu,

  [switch]$ExportJson,
  [switch]$ExportTxt,
  [string]$OutPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Helpers
# ---------------------------

function Write-Section {
  param([Parameter(Mandatory)][string]$Title)
  Write-Host ""
  Write-Host ("=" * 70)
  Write-Host $Title
  Write-Host ("=" * 70)
}

function Safe-Invoke {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Script
  )
  try {
    & $Script
  } catch {
    [pscustomobject]@{
      ErrorSection = $Name
      Message      = $_.Exception.Message
    }
  }
}

function Convert-BytesHuman {
  param([Parameter(Mandatory)][double]$Bytes)
  $sizes = "B","KB","MB","GB","TB","PB"
  $order = 0
  while ($Bytes -ge 1024 -and $order -lt $sizes.Length-1) {
    $order++
    $Bytes = $Bytes / 1024
  }
  "{0:N2} {1}" -f $Bytes, $sizes[$order]
}

function Resolve-OutPath {
  param([string]$OutPath, [string]$DefaultName)
  if ([string]::IsNullOrWhiteSpace($OutPath)) {
    return (Join-Path -Path (Get-Location) -ChildPath $DefaultName)
  }
  return $OutPath
}

# ---------------------------
# 1) Info general del sistema
# ---------------------------

function Get-SystemSummary {
  Safe-Invoke -Name "SystemSummary" -Script {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS

    $uptime = (Get-Date) - $os.LastBootUpTime

    [pscustomobject]@{
      ComputerName   = $env:COMPUTERNAME
      User           = $env:USERNAME
      OS             = $os.Caption
      OSVersion      = $os.Version
      BuildNumber    = $os.BuildNumber
      Architecture   = $os.OSArchitecture
      Manufacturer   = $cs.Manufacturer
      Model          = $cs.Model
      BIOSVersion    = ($bios.SMBIOSBIOSVersion -join ", ")
      BIOSSerial     = $bios.SerialNumber
      LastBoot       = $os.LastBootUpTime
      UptimeHours    = [math]::Round($uptime.TotalHours, 2)
      Timezone       = (Get-TimeZone).Id
    }
  }
}

# ---------------------------
# 2) Estado CPU/RAM + top procesos
# ---------------------------

function Get-PerformanceSnapshot {
  Safe-Invoke -Name "PerformanceSnapshot" -Script {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem

    $totalMem = [double]$cs.TotalPhysicalMemory
    $freeMem  = [double]($os.FreePhysicalMemory * 1024)  # KB -> bytes

    $cpuCounter = Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue
    $cpuPct = if ($cpuCounter) { [math]::Round($cpuCounter.CounterSamples[0].CookedValue, 2) } else { $null }

    $topCpu = Get-Process |
      Sort-Object CPU -Descending |
      Select-Object -First 8 Name, Id, CPU, WorkingSet

    $topMem = Get-Process |
      Sort-Object WorkingSet -Descending |
      Select-Object -First 8 Name, Id, CPU, WorkingSet

    [pscustomobject]@{
      CpuPercent          = $cpuPct
      TotalMemory         = Convert-BytesHuman $totalMem
      FreeMemory          = Convert-BytesHuman $freeMem
      UsedMemoryPercent   = if ($totalMem -gt 0) { [math]::Round((($totalMem - $freeMem) / $totalMem) * 100, 2) } else { $null }
      TopProcessesByCPU   = $topCpu
      TopProcessesByMem   = $topMem
    }
  }
}

# ---------------------------
# 3) Espacio en disco
# ---------------------------

function Get-DiskSummary {
  Safe-Invoke -Name "DiskSummary" -Script {
    $vols = Get-Volume -ErrorAction SilentlyContinue |
      Where-Object DriveLetter |
      Select-Object DriveLetter, FileSystemLabel, FileSystem,
        @{n="Size";e={Convert-BytesHuman $_.Size}},
        @{n="Free";e={Convert-BytesHuman $_.SizeRemaining}},
        @{n="FreePercent";e={ if ($_.Size -gt 0) { [math]::Round(($_.SizeRemaining / $_.Size) * 100, 2) } else { $null } }}

    $drives = Get-PSDrive -PSProvider FileSystem |
      Select-Object Name, Root,
        @{n="Used";e={Convert-BytesHuman (($_.Used))}},
        @{n="Free";e={Convert-BytesHuman (($_.Free))}}

    [pscustomobject]@{
      Volumes = $vols
      Drives  = $drives
    }
  }
}

# ---------------------------
# 4) Red: IP, gateway, DNS, adaptadores
# ---------------------------

function Get-NetworkSummary {
  Safe-Invoke -Name "NetworkSummary" -Script {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
      Sort-Object -Property Status, Name -Descending |
      Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress

    $ipconfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
      Select-Object InterfaceAlias,
        @{n="IPv4";e={($_.IPv4Address.IPAddress -join ", ")}},
        @{n="IPv6";e={($_.IPv6Address.IPAddress -join ", ")}},
        @{n="Gateway";e={($_.IPv4DefaultGateway.NextHop -join ", ")}},
        @{n="DNSServers";e={($_.DnsServer.ServerAddresses -join ", ")}}

    [pscustomobject]@{
      Adapters       = $adapters
      IPConfiguration= $ipconfig
    }
  }
}

# ---------------------------
# 5) Conectividad: ping + test de puerto
# ---------------------------

function Test-Connectivity {
  param(
    [string]$PublicHost = "1.1.1.1",
    [string]$DnsName    = "www.google.com",
    [string]$TcpHost    = "www.google.com",
    [int]$TcpPort       = 443
  )

  Safe-Invoke -Name "Connectivity" -Script {
    # gateway IPv4 (si existe)
    $gw = (Get-NetIPConfiguration -ErrorAction SilentlyContinue |
      Where-Object { $_.IPv4DefaultGateway -and $_.IPv4DefaultGateway.NextHop } |
      Select-Object -First 1).IPv4DefaultGateway.NextHop

    $pingGateway = if ($gw) { Test-Connection -ComputerName $gw -Count 2 -Quiet -ErrorAction SilentlyContinue } else { $null }
    $pingPublic  = Test-Connection -ComputerName $PublicHost -Count 2 -Quiet -ErrorAction SilentlyContinue

    $dnsResolve = $null
    try {
      $dnsResolve = (Resolve-DnsName $DnsName -ErrorAction Stop | Select-Object -First 1 Name, IPAddress, Type)
    } catch {
      $dnsResolve = [pscustomobject]@{ Name=$DnsName; Error=$_.Exception.Message }
    }

    $tcp = Test-NetConnection -ComputerName $TcpHost -Port $TcpPort -WarningAction SilentlyContinue

    [pscustomobject]@{
      GatewayIPv4      = $gw
      PingGatewayOK    = $pingGateway
      PingPublicOK     = $pingPublic
      DnsTest          = $dnsResolve
      TcpTestHost      = $TcpHost
      TcpTestPort      = $TcpPort
      TcpTestSucceeded = $tcp.TcpTestSucceeded
      TcpRemoteAddress = $tcp.RemoteAddress
    }
  }
}

# ---------------------------
# 6) DNS: servidores y resoluciones de ejemplo
# ---------------------------

function Get-DnsDiagnostics {
  param(
    [string[]]$NamesToTest = @("www.microsoft.com","www.cloudflare.com","www.google.com")
  )

  Safe-Invoke -Name "DnsDiagnostics" -Script {
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object InterfaceAlias, ServerAddresses

    $tests = foreach ($n in $NamesToTest) {
      try {
        $r = Resolve-DnsName $n -ErrorAction Stop | Where-Object { $_.Type -in "A","AAAA" } | Select-Object -First 3
        [pscustomobject]@{
          Name   = $n
          Result = ($r.IPAddress -join ", ")
          OK     = $true
        }
      } catch {
        [pscustomobject]@{
          Name   = $n
          Result = $_.Exception.Message
          OK     = $false
        }
      }
    }

    [pscustomobject]@{
      DnsServers = $dnsServers
      Tests      = $tests
    }
  }
}

# ---------------------------
# 7) Servicios clave (estado)
# ---------------------------

function Get-ServiceHealth {
  Safe-Invoke -Name "ServiceHealth" -Script {
    $serviceNames = @(
      "wuauserv",   # Windows Update
      "bits",      # Background Intelligent Transfer
      "Dhcp",      # DHCP Client
      "Dnscache",  # DNS Client
      "Winmgmt",   # WMI
      "EventLog"   # Windows Event Log
    )

    $services = foreach ($s in $serviceNames) {
      $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
      if ($null -eq $svc) {
        [pscustomobject]@{ Name=$s; Status="NotFound"; StartType=$null }
      } else {
        $startType = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).StartMode
        [pscustomobject]@{ Name=$svc.Name; DisplayName=$svc.DisplayName; Status=$svc.Status; StartType=$startType }
      }
    }

    $nonRunningAuto = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
      Where-Object { $_.StartMode -eq "Auto" -and $_.State -ne "Running" } |
      Select-Object -First 25 Name, DisplayName, StartMode, State

    [pscustomobject]@{
      KeyServices          = $services
      AutoButNotRunningTop = $nonRunningAuto
    }
  }
}

# ---------------------------
# 8) Eventos recientes (errores/críticos)
# ---------------------------

function Get-RecentEventErrors {
  param(
    [int]$HoursBack = 24
  )

  Safe-Invoke -Name "RecentEventErrors" -Script {
    $start = (Get-Date).AddHours(-1 * $HoursBack)

    $system = Get-WinEvent -FilterHashtable @{
      LogName   = "System"
      StartTime = $start
      Level     = 1,2,3  # Critical, Error, Warning
    } -ErrorAction SilentlyContinue |
      Select-Object -First 30 TimeCreated, LevelDisplayName, ProviderName, Id, Message

    $app = Get-WinEvent -FilterHashtable @{
      LogName   = "Application"
      StartTime = $start
      Level     = 1,2,3
    } -ErrorAction SilentlyContinue |
      Select-Object -First 30 TimeCreated, LevelDisplayName, ProviderName, Id, Message

    [pscustomobject]@{
      WindowHoursBack = $HoursBack
      SystemTop30     = $system
      ApplicationTop30= $app
    }
  }
}

# ---------------------------
# 9) Drivers / dispositivos con problemas
# ---------------------------

function Get-DriverAndDeviceIssues {
  Safe-Invoke -Name "DriverAndDeviceIssues" -Script {
    $problemDevices = Get-PnpDevice -Status Error,Degraded,Unknown -ErrorAction SilentlyContinue |
      Select-Object -First 50 Class, FriendlyName, InstanceId, Status

    $signedDrivers = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
      Sort-Object DriverDate -Descending |
      Select-Object -First 25 DeviceName, DriverVersion, DriverDate, Manufacturer

    [pscustomobject]@{
      ProblemDevicesTop50 = $problemDevices
      RecentDriversTop25  = $signedDrivers
    }
  }
}

# ---------------------------
# 10) Reporte final exportable
# ---------------------------

function New-FullReport {
  param(
    [switch]$IncludeSystem,
    [switch]$IncludePerformance,
    [switch]$IncludeDisk,
    [switch]$IncludeNetwork,
    [switch]$IncludeConnectivity,
    [switch]$IncludeDns,
    [switch]$IncludeServices,
    [switch]$IncludeEvents,
    [switch]$IncludeDrivers
  )

  $report = [ordered]@{
    GeneratedAt = (Get-Date).ToString("s")
    Sections    = [ordered]@{}
  }

  if ($IncludeSystem)       { $report.Sections.System        = Get-SystemSummary }
  if ($IncludePerformance)  { $report.Sections.Performance   = Get-PerformanceSnapshot }
  if ($IncludeDisk)         { $report.Sections.Disk          = Get-DiskSummary }
  if ($IncludeNetwork)      { $report.Sections.Network       = Get-NetworkSummary }
  if ($IncludeConnectivity) { $report.Sections.Connectivity  = Test-Connectivity }
  if ($IncludeDns)          { $report.Sections.Dns           = Get-DnsDiagnostics }
  if ($IncludeServices)     { $report.Sections.Services      = Get-ServiceHealth }
  if ($IncludeEvents)       { $report.Sections.Events        = Get-RecentEventErrors }
  if ($IncludeDrivers)      { $report.Sections.Drivers       = Get-DriverAndDeviceIssues }

  [pscustomobject]$report
}

function Export-ReportJson {
  param(
    [Parameter(Mandatory)]$Report,
    [Parameter(Mandatory)][string]$Path
  )
  $Report | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding UTF8
  $Path
}

function Export-ReportTxt {
  param(
    [Parameter(Mandatory)]$Report,
    [Parameter(Mandatory)][string]$Path
  )
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("GeneratedAt: $($Report.GeneratedAt)")
  $lines.Add("")

  foreach ($key in $Report.Sections.Keys) {
    $lines.Add(("="*70))
    $lines.Add("SECTION: $key")
    $lines.Add(("="*70))
    $lines.Add(($Report.Sections[$key] | Out-String).TrimEnd())
    $lines.Add("")
  }

  $lines -join "`r`n" | Out-File -FilePath $Path -Encoding UTF8
  $Path
}

# ---------------------------
# Menú interactivo (opcional)
# ---------------------------

function Show-Menu {
  Write-Host ""
  Write-Host "Diagnostico.ps1 - Menu"
  Write-Host "1) Sistema"
  Write-Host "2) Performance (CPU/RAM + procesos)"
  Write-Host "3) Disco"
  Write-Host "4) Red"
  Write-Host "5) Conectividad (ping/DNS/puerto)"
  Write-Host "6) DNS"
  Write-Host "7) Servicios"
  Write-Host "8) Eventos recientes"
  Write-Host "9) Drivers/Dispositivos con problemas"
  Write-Host "A) Todo"
  Write-Host "Q) Salir"
  $choice = Read-Host "Elige una opcion"

  switch ($choice.ToUpper()) {
    "1" { Write-Section "Sistema"; (Get-SystemSummary | Format-List | Out-String) | Write-Host }
    "2" { Write-Section "Performance"; (Get-PerformanceSnapshot | Out-String) | Write-Host }
    "3" { Write-Section "Disco"; (Get-DiskSummary | Out-String) | Write-Host }
    "4" { Write-Section "Red"; (Get-NetworkSummary | Out-String) | Write-Host }
    "5" { Write-Section "Conectividad"; (Test-Connectivity | Out-String) | Write-Host }
    "6" { Write-Section "DNS"; (Get-DnsDiagnostics | Out-String) | Write-Host }
    "7" { Write-Section "Servicios"; (Get-ServiceHealth | Out-String) | Write-Host }
    "8" { Write-Section "Eventos"; (Get-RecentEventErrors | Out-String) | Write-Host }
    "9" { Write-Section "Drivers"; (Get-DriverAndDeviceIssues | Out-String) | Write-Host }
    "A" {
      Write-Section "Reporte completo"
      $r = New-FullReport -IncludeSystem -IncludePerformance -IncludeDisk -IncludeNetwork -IncludeConnectivity -IncludeDns -IncludeServices -IncludeEvents -IncludeDrivers
      ($r | Out-String) | Write-Host
    }
    "Q" { return }
    default { Write-Host "Opcion invalida." }
  }
}

# ---------------------------
# Ejecución según parámetros
# ---------------------------

if ($Menu) {
  Show-Menu
  return
}

# Si el usuario no indicó nada, damos una pista.
if (-not ($All -or $System -or $Performance -or $Disk -or $Network -or $Connectivity -or $Dns -or $Services -or $Events -or $Drivers)) {
  Write-Host "No indicaste secciones. Prueba:"
  Write-Host "  .\diagnostico.ps1 -All"
  Write-Host "  .\diagnostico.ps1 -Menu"
  Write-Host "  .\diagnostico.ps1 -Network"
  return
}

# Si -All, activamos todas
if ($All) {
  $System = $Performance = $Disk = $Network = $Connectivity = $Dns = $Services = $Events = $Drivers = $true
}

# Construir reporte (objeto)
$report = New-FullReport `
  -IncludeSystem:$System `
  -IncludePerformance:$Performance `
  -IncludeDisk:$Disk `
  -IncludeNetwork:$Network `
  -IncludeConnectivity:$Connectivity `
  -IncludeDns:$Dns `
  -IncludeServices:$Services `
  -IncludeEvents:$Events `
  -IncludeDrivers:$Drivers

# Mostrar en consola por secciones (bonito)
foreach ($key in $report.Sections.Keys) {
  Write-Section $key
  $report.Sections[$key] | Out-String | Write-Host
}

# Exportar si se pidió
if ($ExportJson) {
  $path = Resolve-OutPath -OutPath $OutPath -DefaultName "reporte_diagnostico.json"
  $saved = Export-ReportJson -Report $report -Path $path
  Write-Host ""
  Write-Host "Reporte JSON guardado en: $saved"
}

if ($ExportTxt) {
  $path = Resolve-OutPath -OutPath $OutPath -DefaultName "reporte_diagnostico.txt"
  $saved = Export-ReportTxt -Report $report -Path $path
  Write-Host ""
  Write-Host "Reporte TXT guardado en: $saved"
}
