# Windows EVTX Samples:

This is a container for windows events samples associated to specific attack and post-exploitation techniques. 
Can be useful for:

- Testing your detection scripts based on EVTX parsing

- Training on DFIR and threat hunting using event logs

- Designing detection use cases using Windows and Sysmon event logs

## Execution:
1. Short time living scheduled task (4698 followed by 4699 in less than 1 min time window)
2. Sysmon 1 - wmighost_sysmon_20_21_1.evtx (scrcons.exe)
3. MSI Package Exec - Meterpreter Reverse TCP - Sysmon Exec - Exec_sysmon_meterpreter_reversetcp_msipackage.evtx

## Reconnaissance:
1. PsLoggedOn.exe traces on the destination host
2. BloodHoundAD\SharpHound (with default scan options) traces on one target host
3. "Domain Admins" Group enumeration - 4661 (SAM_GROUP, S-1-5-21-domain-512) - DC logs
4. Process Listing via meterpreter "ps" command - meterpreter_ps_cmd_process_listing_sysmon_10.evtx (more than 10 of sysmon 10 events from same src process and twoard different target images and with same calltrace and granted access)

## Persistence:
1. Application Shimming: sysmon (1, 13, 11) and windowd native event 500 "Microsoft-Windows-Application-Experience\Program-Telemetry"
2. Assigning required DCSync AD extended rights to a backdoor regular account (PowerView DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl) - EventIDs 5136 & 4662
3. WMIGhost malwr, sysmon 20, 21 and 1 (ActiveScriptEventConsumer) - wmighost_sysmon_20_21_1.evtx

## Privilege Escalation:
1. Via Named Pipe Impersonation - sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx (.\\pipe\random present in sysmon 1 cmdline and in service registry)

## Credential Access:
1. Memory dump of lsass.exe using procdump.exe and taskmgr.exe (sysmon 10 & 11)
2. Mimikatz sekurlsa::logonpasswords (sysmon 10)
3. Traces of a KeyLogger using DirectInput (sysmon 13)
4. Browser's saved credentials - 4663 - test conducted for Opera, Chrome and FireFox
5. Assining "SPN" to regular user account as a prep step for kerberoasting (ACL_ForcePwd_SPNAdd_User_Computer_Accounts)
6. BabyShark Mimikatz via PowerShell - sysmon 7 and 10 (babyshark_mimikatz_powershell.evtx)
7. Keefarce HKTL - dump credentials from keepass pwd mgmt solution (CA_keefarce_keepass_credump.evtx) - Sysmon 8, 7 (CreateRemoteThread, ImageLoad)
8. KeeThief - Keepass MasterDB pwd dumper (CA_keepass_KeeThief_Get-KeePassDatabaseKey.evtx) - sysmon CreateRemoteThread 
9. Lazagne.exe - Browsers Saved Credentials access - 4663 (CA_chrome_firefox_opera_4663.evtx) 
10. Meterpreter - HashDump command
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
11. Remote Shell over namedpipe - Sysmon 18 (Image:System) and 3 (SourcePort:445) -> lm_sysmon_18_remshell_over_namedpipe.evtx 
12. DCOM via MMC20.APPLICATION COM Object - Sysmon Process Create and NetConnect -> LM_impacket_docmexec_mmc_sysmon_01.evtx
13. WMIEXEC - Process Creation - Sysmon - LM_wmiexec_impacket_sysmon_whoami.evtx
14. PSEXEC - Sysmon - LM_sysmon_psexec_smb_meterpreter.evtx

## Defense Evasion:
1. RDP Tunneling via SSH - eventid 4624 - Logon Type 10 and Source IP eq to loopback IP address
2. RDP Tunneling via SSH - eventid 1149 - TerminalServices-RemoteConnectionManagerOperational - RDP source IP loopback IP address
3. RDP Tunneling via SSH - Sysmon eventid 3 - local port forwarding to/from loopback IP (svchost.exe <-> plink.exe)
4. RDP Tunneling via SSH - eventid 5156 - local port forwarding to/from loopback IP to 3389 rdp port
5. RDP Service settings's tampering - RDPWrap, UniversalTermsrvPatch, WinFW RDP FW rule and RDP-TCP port
6. System and Security Log cleared: 104 System, 1102 Security
7. Time stomping and DLL Side Loading "NvSmartMax.dll" (DE_timestomp_and_dll_sideloading_and_RunPersist.evtx)
8. Process Suspended - ProcessAccess with GrantedAccess eq to 0x800 - process_suspend_sysmon_10_ga_800.evtx
9. Meterpreter Migrate cmd from untrusted process to a trusted one (explorer.exe) - meterpreter_migrate_to_explorer_sysmon_8.evtx
10. Timestomp MACE attributes - sysmon 2 (filecreatetime) and 11 (file creation) - sysmon_2_11_evasion_timestomp_MACE.evtx
