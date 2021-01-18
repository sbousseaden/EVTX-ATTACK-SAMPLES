# Windows EVTX Samples [200 EVTX examples]:

![alt text](https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/AIEvent.jpg)

This is a container for windows events samples associated to specific attack and post-exploitation techniques. 
Can be useful for:

- Testing your detection scripts based on EVTX parsing

- Training on DFIR and threat hunting using event logs

- Designing detection use cases using Windows and Sysmon event logs

- Avoid/Bypass the noisy techniques if you are a redteamer

N.B: Mapping has been done to the level of ATT&CK technique (not procedure).

Details of the EVTX content mapped to MITRE tactics can be found [here](http://bit.ly/2WpzQM4), stats summary:

![alt text](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/EVTX_DataSet_Stats.PNG)

![alt text](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/HeatMap.PNG)

Overview of the covered TTPs using attack-navigator:

![alt text](https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/mitre_evtx_repo_map.png)

# Winlogbeat-Bulk-Read
Included is a PowerShell script that can loop through, parse, and replay evtx files with [winlogbeat](https://www.elastic.co/downloads/beats/winlogbeat). 
This can be useful to replay logs into an ELK stack or to a local file. By default this script will
output logs to .\winlogbeat\events.json as configured in the winlogbeat_example.yml file, 
you can configure any of your own destinations in winlogbeat.yml (excluded from git) and the
example config file will be ignored if winlogbeat.yml is found.

Winlogbeat-Bulk-Read Usage:
```
## Display help along with examples:
.\Winlogbeat-Bulk-Read.ps1 -Help

## Run with defaults (read ./ recursively and look for winlogbeat.exe in your path):
.\Winlogbeat-Bulk-Read.ps1

## If you want to point this script at another directory with evtx files and specify a path to the winlogbeat.exe binary:
.\Winlogbeat-Bulk-Read.ps1 -Exe ~\Downloads\winlogbeat\winlogbeat.exe -Source "..\EVTX-ATTACK-SAMPLES\"
```

# License:

EVTX_ATT&CK's [GNU General Public License](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/LICENSE.GPL)
