1. PsLoggedOn.exe traces on the destination host
2. BloodHoundAD\SharpHound (with default scan options) traces on one target host
3. "Domain Admins" Group enumeration - 4661 (SAM_GROUP, S-1-5-21-domain-512) - DC logs
4. Process Listing via meterpreter "ps" command - meterpreter_ps_cmd_process_listing_sysmon_10.evtx (more than 10 of sysmon 10 events from same src process and twoard different target images and with same calltrace and granted access)
