Connection Proxy:
1. RDP Tunneling via SSH - eventid 4624 - Logon Type 10 and Source IP eq to loopback IP address
2. RDP Tunneling via SSH - eventid 1149 - TerminalServices-RemoteConnectionManagerOperational - RDP source IP loopback IP address
3. RDP Tunneling via SSH - Sysmon eventid 3 - local port forwarding to/from loopback IP (svchost.exe <-> plink.exe)
4. RDP Tunneling via SSH - eventid 5156 - local port forwarding to/from loopback IP to 3389 rdp port
5. RDP & SMB Tunneling using SECFORCE/Tunna aspx webshell on an IIS server: sysmon 3 with w3wp.exe as procname and destinationport eq 3389 or 445 & destinationip is localhost (optional), IIS W3SVC Logs - contains traces of HTTP GET with string "proxy&port=*&ip=*".  
