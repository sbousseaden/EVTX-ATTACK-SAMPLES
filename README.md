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
4. WMI CommandLineConsumer -> sysmon_20_21_1_CommandLineEventConsumer.evtx
5. Execution as System via a local temp scheduled task creation that runs as system -> sysmon_1_11_exec_as_system_via_schedtask.evtx
6. Execution via Rundll32.exe (url.dll,ieframe.dll)|OpenURL,FileProtocolHandler]-> exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.evtx
7. Launch an executable by calling OpenURL in shdocvw.dll -> exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.evtx
8. Launch an executable payload by calling RouteTheCall in zipfldr.dll -> exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.evtx
9. Launch an executable by calling the RegisterOCX function in Advpack.dll -> exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx
10. Executes payload using the Program Compatibility Assistant (pcalua.exe) -> exec_sysmon_1_lolbin_pcalua.evtx
11. Execute payload by calling pcwutl.dll,LaunchApplication function -> exec_sysmon_1_rundll32_pcwutl_launchapplication.evtx
12. Execute payload using "ftp.exe -s:ftp_cmd.txt" binary -> sysmon_1_ftp.evtx
13. Execute sct stuff using regsvr32\scrobj.dll from pastebin (both ms binaries renamed and normal ones captured) -> exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.evtx & exec_sysmon_lobin_regsvr32_sct.evtx
12. AMSI bypass via jscript9.dll (not instrumented by AMSI) -> exec_sysmon_1_7_jscript9_defense_evasion.evtx
13. rundll32 (mshtml,RunHTMLApplication)-> mshta -> schtasks.exe -> exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx
14. Exec via Drive-by "Adobe Flash CVE-2018-15982" -> exec_driveby_cve-2018-15982_sysmon_1_10.evtx (SrcImg=iexplorer.exe and CallTrace contains "UNKNOWN")	
15. Exec of cmds/code via XSL (Extensible Markup Language) and WMIC & MSXSL -> exec_wmic_xsl_internet_sysmon_3_1_11.evtx & exec_msxsl_xsl_sysmon_1_7.evtx
16. Exec & Persist from Volume Shadow Copy -> sysmon_exec_from_vss_persistence.evtx
17. Lol-bin exec stuff via vshadow.exe (external MS SDK utility) -> sysmon_lolbin_bohops_vshadow_exec.evtx	 

## Reconnaissance:
1. PsLoggedOn.exe traces on the destination host
2. BloodHoundAD\SharpHound (with default scan options) traces on one target host
3. "Domain Admins" Group enumeration - 4661 (SAM_GROUP, S-1-5-21-domain-512) - DC logs
4. Process Listing via meterpreter "ps" command - meterpreter_ps_cmd_process_listing_sysmon_10.evtx (more than 10 of sysmon 10 events from same src process and twoard different target images and with same calltrace and granted access)
5. Invoke-UserHunter traces on the source machine --> Recon_Sysmon_3_Invoke_UserHunter_SourceMachine.evtx
6. Traces of  shares enumeration using "net view \\target /all" on a target host using sysmon -> enum_shares_target_sysmon_3_18.evtx
7. Discovery of sensitive IIS config files and saved passwords using IIS appcmd.exe utility -> sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx

## Persistence:
1. Application Shimming: sysmon (1, 13, 11) and windowd native event 500 "Microsoft-Windows-Application-Experience\Program-Telemetry"
2. Assigning required DCSync AD extended rights to a backdoor regular account (PowerView DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl) - EventIDs 5136 & 4662
3. WMIGhost malwr, sysmon 20, 21 and 1 (ActiveScriptEventConsumer) - wmighost_sysmon_20_21_1.evtx
4. DCShadow - 4742 Computer Account changed - SPN contains "GC\" and "HOST\" - persistence_security_dcshadow_4742.evtx
5. Bitsadminexec - sysmon_1_persist_bitsjob_SetNotifyCmdLine.evtx (runtime traces)	& persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx (creation and runtime traces)
6. Persistent System Access via replacing onscreenkeyboard PE with cmd.exe -> persistence_accessibility_features_osk_sysmon1.evtx
7. Persistence via COM hijack of : {BCDE0395-E52F-467C-8E3D-C4579291692E} - CLSID_MMDeviceEnumerator (used i.e. by Firefox) -> persist_firefox_comhijack_sysmon_11_13_7_1.evtx
8. Persistence via COM hijack of "Outlook Protocol Manager" using TreatAs key for clsid lookup redirection (Turla APT Outlook backdoor) -> persist_turla_outlook_backdoor_comhijack.evtx

## Privilege Escalation:
1. Via Named Pipe Impersonation - sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx (.\\pipe\random present in sysmon 1 cmdline and in service registry) and System_7045_namedpipe_privesc.evtx for default windows system event 7045 (service creation)
2. UAC Bypass via EventViewer (mscfile\shell\open set to a cmd) - Sysmon 13 and 1 -> Sysmon_13_1_UAC_Bypass_EventVwrBypass.evtx
3. UAC Bypass via hijacking the "IsolatedCommand" value in "shell\runas\command" - Sysmon 13 and 1 -> Sysmon_13_1_UACBypass_SDCLTBypass.evtx
4. UAC Bypass via rogue WScript.exe manifest -> sysmon_11_1_15_WScriptBypassUAC.evtx
5. UAC Bypass via App Path Control.exe Hijack -> sysmon_1_13_UACBypass_AppPath_Control.evtx
6. UAC Bypass using perfmon and registry key manipulation -> sysmon_13_1_12_11_perfmonUACBypass.evtx
7. UAC Bypass using compmgmtlauncher and registry key manip -> sysmon_13_1_compmgmtlauncherUACBypass.evtx
8. UAC Bypass using cliconfg (DLL - NTWDBLIB.dll) -> sysmon_11_1_7_uacbypass_cliconfg.evtx
9. UAC Bypass using using mcx2prov.exe (CRYPTBASE DLL) -> sysmon_1_7_11_mcx2prov_uacbypass.evtx
10. UAC Bypass using migwiz.exe (CRYPTBASE DLL) -> sysmon_1_7_11_migwiz.evtx
11. UAC Bypass using sysprep.exe (CRYPTBASE DLL) -> sysmon_1_7_11_sysprep_uacbypass.evtx
12. UAC Bypass using token manipulation -> security_4624_4673_token_manip.evtx (LT=9 and SeTcbPrivilege use)
13. UAC Bypass using using cmstp and ini file -> sysmon_1_13_11_cmstp_ini_uacbypass.evtx (dllhost.exe {3E5FC7F9-9A51-4367-9063-A120244FBEC7} hosting CMSTPLUA and spawning desired elevated process)
14. Elevate from administrator to NT AUTHORITY SYSTEM using handle inheritance (lsass.exe spawn process) -> sysmon_privesc_from_admin_to_system_handle_inheritance.evtx
15. Rotten Potato exploit to esc from service account to local system via impersonation (bits COM fetch, RPC rogue server, NTLM MITM)-> privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.evtx	


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
11. Invoke-Mimikatz from Github: sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx
12. DCSync traces on a Domain Controller - Security 4662 - CA_DCSync_4662.evtx [Properties: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
or Replicating Directory Changes All” extended right]

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
15. LM via DCOM ShellBrowserWindow or ShellWindows COM classes - explorer.exe with internal IP addresses network connections over RPC high port numbers -> LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx
16. LM via DCOM MSHTA (known as LethalHTA) -> LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx
17. LM via writing to the startup folder exposed via tsclient (RDP local resources default share, sysmon 11) -> LM_tsclient_startup_folder.evtx
18. Remote execution via WinRM from target host (sysmon process create winrshost.exe) -> LM_winrm_exec_sysmon_1_winrshost.evtx
19. Remote PowerShell Session (sysmon process create wsmprovhost.exe) -> LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx
20. LM via InternetExplorer.Application COM object -> LM_dcom_InternetExplorer.Application_sysmon_1.evtx
21. LM via WebShell (w3wp.exe -> cmd.exe -> whoami.exe) -> LM_typical_IIS_webshell_sysmon_1_10_traces.evtx


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
11. Office VBA Sensitive Security Setting Changed ->  de_sysmon_13_VBA_Security_AccessVBOM.evtx
12. PowerShell CLM local machine environment variable "__PSLockdownPolicy" removed-> DE_Powershell_CLM_Disabled_Sysmon_12.evtx
13. User Account Control Disabled - Sysmon EID 12/12 -> DE_UAC_Disabled_Sysmon_12_13.evtx
14. Unmanaged PowerShell via PSInject -> de_unmanagedpowershell_psinject_sysmon_7_8_10.evtx
15. PowerShell scriptblock logging deleted or disbaled -> de_PsScriptBlockLogging_disabled_sysmon12_13.evtx
16. RDP Port forwarding via netsh  portproxy cmd -> de_portforward_netsh_rdp_sysmon_13_1.evtx
17. PowerShell Execution Policy Changed - de_powershell_execpolicy_changed_sysmon_13.evtx
18. APT10 DLL side loading "jli.dll via jjs.exe", ProcessHollowing masqurading as svchost.exe -> apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx	
 
