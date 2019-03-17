# Windows EVTX Samples:

This is a container for windows events samples associated to specific attack and post-exploitation techniques. 
Can be useful for:

- Testing your detection scripts based on EVTX parsing

- Training on detection and threat hunting using event logs

- Designing detection use cases using Windows and Sysmon event logs

## Reconnaissance:
1. PsLoggedOn.exe traces on the destination host
2. BloodHoundAD\SharpHound (with default scan options) traces on one target host

## Credential Access:
1. Memory dump of lsass.exe using procdump.exe and taskmgr.exe (sysmon 10 & 11)
2. Mimikatz sekurlsa::logonpasswords (sysmon 10)

## Lateral Movement:
1. RemCom (open source psexec) traces on target host eventid 5145
2. PsExec traces on target host - 5145 - (psexec -r "renamed psexec service name")
3. New Share object created - 5142 (net share print=c:\windows\system32 grant:...)

## Defense Evasion:
1. RDP Tunneling via SSH - eventid 4624 - Logon Type 10 and Source IP eq to loopback IP address
2. RDP Tunneling via SSH - eventid 1149 - TerminalServices-RemoteConnectionManagerOperational - RDP source IP loopback IP address
3. RDP Tunneling via SSH - Sysmon eventid 3 - local port forwarding to/from loopback IP (svchost.exe <-> plink.exe)
4. RDP Tunneling via SSH - eventid 5156 - local port forwarding to/from loopback IP to 3389 rdp port
