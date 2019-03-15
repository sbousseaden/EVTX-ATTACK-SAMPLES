# Windows EVTX Samples:

This is a container for windows events samples associated to specific attack techniques. 
Can be useful for:

- Testing your detection scripts based on EVTX parsing

- Training on detection and threat hunting using event logs

- Designing detection use cases

## Reconnaissance:
1. PsLoggedOn.exe traces on the destination host
2. BloodHoundAD\SharpHound (with default scan options) traces on one target host

## Lateral Movement:
1. RemCom (open source psexec) traces on target host eventid 5145
2. PsExec traces on target host - 5145 - (psexec -r "renamed psexec service name")  

## Defense Evasion:
1. RDP Tunneling via SSH - eventid 4624 - Logon Type 10 and Source IP eq to loopback IP address
2. RDP Tunneling via SSH - eventid 1149 - TerminalServices-RemoteConnectionManagerOperational - RDP source IP loopback IP address
3. RDP Tunneling via SSH - Sysmon eventid 3 - local port forwarding to/from loopback IP (svchost.exe <-> plink.exe)

## Persistence:
1. 
