# Windows EVTX Samples:

This is a container for windows events samples associated to specific attack and post-exploitation techniques. 
Can be useful for:

- Testing your detection scripts based on EVTX parsing

- Training on DFIR and threat hunting using event logs

- Designing detection use cases using Windows and Sysmon event logs

## Execution:
1. Short time living scheduled task (4698 followed by 4699 in less than 1 min time window)

## Reconnaissance:
1. PsLoggedOn.exe traces on the destination host
2. BloodHoundAD\SharpHound (with default scan options) traces on one target host
3. "Domain Admins" Group enumeration - 4661 (SAM_GROUP, S-1-5-21-domain-512) - DC logs

# Persistence:
1. Application Shimming: sysmon (1, 13, 11) and windowd native event 500 "Microsoft-Windows-Application-Experience\Program-Telemetry"
2. Assigning required DCSync AD extended rights to a backdoor regular account (PowerView DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl) - EventIDs 5136 & 4662

## Credential Access:
1. Memory dump of lsass.exe using procdump.exe and taskmgr.exe (sysmon 10 & 11)
2. Mimikatz sekurlsa::logonpasswords (sysmon 10)
3. Traces of a KeyLogger using DirectInput (sysmon 13)
4. Browser's saved credentials - 4663 - test conducted for Opera, Chrome and FireFox
5. Assining "SPN" to regular user account as a prep step for kerberoasting (ACL_ForcePwd_SPNAdd_User_Computer_Accounts)

## Lateral Movement:
1. RemCom (open source psexec) traces on target host eventid 5145
2. PsExec traces on target host - 5145 - (psexec -r "renamed psexec service name")
3. New Share object created - 5142 (net share print=c:\windows\system32 grant:...) 
4. Pass the hash using Mimikatz's sekurlsa::pth - 4624 from source machine (logon type=9, logonproc=seclogon)
5. WMI - 4648 with AI attribute pointing to WMIC process - source machine
6. WMI - 4624 (logon type =3) followed by 2x 4688 (wmiprvse.exe -> calc.exe) - target machine 
7. RPC over TCP/IP - 4648 with AI attribute pointing to RPCSS SPN - source machine
8. Remote File Write/Copy - 5145 [Accesses: WriteData (or AddFile)]
9. Remote Scheduled Task Creation via ATSVC named pipe - 5145 (ShareName:IPC$, RTN: atsvc) on target host
10. Remote Service Creation - 5145 (IPC$, svcctl, WriteData), 7045 (SystemEvent with svc details) - both from target host

## Defense Evasion:
1. RDP Tunneling via SSH - eventid 4624 - Logon Type 10 and Source IP eq to loopback IP address
2. RDP Tunneling via SSH - eventid 1149 - TerminalServices-RemoteConnectionManagerOperational - RDP source IP loopback IP address
3. RDP Tunneling via SSH - Sysmon eventid 3 - local port forwarding to/from loopback IP (svchost.exe <-> plink.exe)
4. RDP Tunneling via SSH - eventid 5156 - local port forwarding to/from loopback IP to 3389 rdp port
5. RDP Service settings's tampering - RDPWrap, UniversalTermsrvPatch, WinFW RDP FW rule and RDP-TCP port
6. System and Security Log cleared: 104 System, 1102 Security
