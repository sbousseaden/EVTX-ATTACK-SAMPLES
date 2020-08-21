<#
.SYNOPSIS
PowerShell loop to read local .evtx files into Elastic's winlogbeat agent.

.DESCRIPTION
PowerShell loop to read local .evtx files into Elastic's winlogbeat agent.
Use winlogbeat.yml to customize your configuration of winlogbeat including output.
This script will attempt to use winlogbeat.yml which is ignored in .gitignore but
if this file is not found, it will fall back to using the example that will output
logs to .\winlogbeat\events.json. Once an EVTX file has been read winlogbeat will
store the file path in winlogbeat.registry_file to prevent reading the same logs.
Remove this file to replay already read files.

Author: Grant Sales
Date: 2020.08.20

.PARAMETER Source
Path to recurse read through to find EVTX files.

.PARAMETER Exe
Path to the winlogbeat.exe binary, when not provided, will look in $path.

.PARAMETER Append
When using the example config, will also output events to bulk_events.json.

.PARAMETER Test
Test winlogbeat config and exit, will only run a max of 10 times within the loop.

.PARAMETER Reset
Reset flag will delete the registry file allowing replay of evtx files that have
already been read once. By default, winlogbeat will read all the files but will not
generate output from an already read file due to bookmarks set in the registry file.

.PARAMETER Verbose
Verbose output, this will output file names as they are read and could help in 
finding any possible errors.

.EXAMPLE
.\Winlogbeat-Bulk-Read.ps1

.EXAMPLE
.\Winlogbeat-Bulk-Read.ps1 -Exe $env:USERPROFILE\Downloads\winlogbeat\winlogbeat-7.8.1-windows-x86_64\winlogbeat.exe -Source "..\EVTX-ATTACK-SAMPLES\"

.EXAMPLE
.\Winlogbeat-Bulk-Read.ps1 -Exe $env:USERPROFILE\Downloads\winlogbeat\winlogbeat-7.8.1-windows-x86_64\winlogbeat.exe

.EXAMPLE
.\Winlogbeat-Bulk-Read.ps1 -Exe $env:USERPROFILE\Downloads\winlogbeat\winlogbeat-7.8.1-windows-x86_64\winlogbeat.exe -Append

.EXAMPLE
.\Winlogbeat-Bulk-Read.ps1 -Exe "C:\Program Files\winlogbeat\winlogbeat.exe" -Reset -Verbose

.EXAMPLE
.\Winlogbeat-Bulk-Read.ps1 -Help
#>

param(
  [string]$Source = "$PSScriptRoot",
  [string]$Exe,
  [switch]$Append,
  [switch]$Test,
  [switch]$Reset,
  [switch]$Verbose,
  [switch]$Help
)

## Check if -Help
If ($Help) {get-help $PSScriptRoot\Winlogbeat-Bulk-Read.ps1 -Detailed; exit}

## winlogbeat.exe path
if ($Exe){
  ## Exe set, make sure it is valid
  if (!(Test-Path -Path $Exe)) {
    Write-Error -Message "Unable to find winlogbeat.exe at $Exe" -ErrorAction Stop
  }
}
else {
  ## Exe not set, look for it in path
  if (!(Get-Command "winlogbeat.exe").Path) {
    write-Error "Unable to find winlogbeat.exe in path. Use -Exe to specify a path." -ErrorAction Stop
  }
  else {
    $Exe = (Get-Command winlogbeat.exe).Path
  }
}

Write-Host "Using $Exe"

## winlogbeat.yml is ignored in .gitignore

$winlogbeat_config = "$PSScriptRoot\winlogbeat.yml"
$winlogbeat_example_config = "$PSScriptRoot\winlogbeat_example.yml"

$winlogbeat_log = "$PSScriptRoot\winlogbeat\log"
if (!(Test-Path -Path "$PSScriptRoot\winlogbeat")) {
  New-Item -Path "$PSScriptRoot\winlogbeat" -ItemType Directory
}
else {
  if ($Reset -and (Test-Path -Path "$PSScriptRoot\winlogbeat\evtx-registry.yml")) {
    Remove-Item -Path "$PSScriptRoot\winlogbeat\evtx-registry.yml"
  }
}

if (Test-Path -Path $winlogbeat_config) {
  ## Use custom config
  Write-Host "Using config: $winlogbeat_config."
  $config = $winlogbeat_config
}
else {
  Write-Host "Using example config: $winlogbeat_example_config."
  $example_config = $true
  $config = $winlogbeat_example_config
}

## Get input evtx files
Write-Host "Source: $Source"
$evtx_files = Get-ChildItem -Path $Source -Filter "*.evtx" -Recurse

$evtx_count = $evtx_files.count

if ($evtx_count -eq 0){
  Write-Error -Message "No EVTX files found at $Source" -ErrorAction Stop
}

#Write-Host "Processing $evtx_count evtx files."
$i=0

foreach ($evtx in $evtx_files) {
  #.\winlogbeat.exe -e -c .\winlogbeat-evtx.yml -E EVTX_FILE=c:\backup\Security-2019.01.evtx
  $evtx_path = $evtx.FullName
  if ($Verbose) {
    Write-Host "Reading $evtx_path"
  }
  Write-Progress -Id 1 -Activity "Reading $evtx_count EVTX files" -Status "Reading $evtx_path" -PercentComplete (($i / $evtx_count) * 100)

  if ($Test){
    & $Exe test config -c $config -e --path.data "$PSScriptRoot\winlogbeat" -E "CWD=$PSScriptRoot" -E "EVTX_FILE=$evtx_path"
  }
  else {
    & $Exe -c $config -e --path.data "$PSScriptRoot\winlogbeat" -E "CWD=$PSScriptRoot" -E "EVTX_FILE=$evtx_path" 2>&1 >> "$winlogbeat_log"
  }

  if ($Test){
    if ($i -ge 5){
      Write-Error -Message "Stopping due to -Test" -ErrorAction Stop
    }
  }
  else {
    if ($Append -and $example_config) {
      #Start-Sleep -Seconds 1
      if (Test-Path "$PSScriptRoot\winlogbeat\events.json"){
        $raw = Get-Content "$PSScriptRoot\winlogbeat\events.json"
        Add-Content -Path "$PSScriptRoot\winlogbeat\bulk_events.json" -Value $raw
      }
    }
  }

  $i++
}
Write-Progress -Id 1 -Activity "Reading EVTX files" -Status "Reading $i" -PercentComplete (($i / $evtx_count) * 100)
Write-Host "Bulk read complete"