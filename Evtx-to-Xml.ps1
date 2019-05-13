﻿<#
.SYNOPSIS
Tool to convert a local .evtx file into a xml file using wevtutil.

.DESCRIPTION
Evtx-to-Xml converts a local directroy of evtx files, strips out
non-printable characters, and saves it in an xml format.
This script will only process files that do not already havea an xml file.
To force an overwrite, either delete or use the force.

Author: Grant Sales
Date: 2019.05.13

.PARAMETER Debug
When this switch is provided, it will output to screen and not save xml to disk

.PARAMETER Force
When this switch is provided, it will process all files and overwrite existing xml files.

.EXAMPLE
.\Evtx-to-Xml.ps1

.EXAMPLE
.\Evtx-to-Xml.ps1 -Debug
#>

param(
  [switch]$Debug,
  [switch]$Force
)

## Get input evtx files
$evtx_files = Get-ChildItem -Path ./ -Filter "*.evtx"

## Create output directory
$output_dir = ".\xml_files\"
if (!(Test-Path $output_dir)){
  New-Item -ItemType Directory -Force -Path $output_dir | Out-Null
}

foreach ($evtx in $evtx_files){
  $xml_file_path = ($evtx.Directory.FullName + "\xml_files\" + $evtx.BaseName + ".xml")

  if (!(Test-Path $xml_file_path) -or $Force) {
    ## XML File doesn't Exist, Export it
    write-host "Converting $evtx to $xml_file_path"
    $evtx_file = $evtx.FullName
    ## Cannot convert value "System.Object[]" to type "System.Xml.XmlDocument". Error: "'', hexadecimal value 0x01, is an invalid character. Line 35, position 75."
    ## Cannot convert value "System.Object[]" to type "System.Xml.XmlDocument". Error: "'', hexadecimal value 0x0F, is an invalid character. Line 35, position 75."
    ## Cannot convert value "System.Object[]" to type "System.Xml.XmlDocument". Error: "'', hexadecimal value 0x02, is an invalid character. Line 35, position 75."
    $xml = [xml]((wevtutil query-events "$evtx_file" /logfile /element:root) -replace "\x01","" -replace "\x0f","" -replace "\x02","")
    if ($Debug){
      ## If -Debug pretty print to screen
      $xml.Save([Console]::Out)
    }
    else {
      $xml.Save($xml_file_path)
    }
  }
}
