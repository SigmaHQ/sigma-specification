# Sigma Taxonomy <!-- omit in toc -->

* Version 1.1.0
* Release date 2022/10/19

This page defines field names and log sources that should be used to ensure sharable rules.

# Summary
- [Summary](#summary)
- [Log Sources](#log-sources)
  - [Application folder](#application-folder)
  - [Cloud folder](#cloud-folder)
  - [Linux folder](#linux-folder)
  - [Macos folder](#macos-folder)
  - [Network folder](#network-folder)
  - [Windows folder](#windows-folder)
- [Fields](#fields)
  - [Generic](#generic)
    - [Process Creation Events](#process-creation-events)
    - [Other Generic Rule Categories](#other-generic-rule-categories)
  - [Specific](#specific)

# Log Sources

For a better comprehension, they are organized by the name of the rules directory

## Application folder

| Product       | Logsource                                       | Event                                                      |
| ------------- | ----------------------------------------------- | ---------------------------------------------------------- |
|               | category: antivirus                             | antivirus detection message (format depends on the editor) |
| django        | category: application<br>product: django        |
| python        | category: application<br>product: python        |
| rpc_firewall  | product: rpc_firewall<br>category: application  |
| ruby_on_rails | category: application<br>product: ruby_on_rails |
| spring        | category: application<br>product: spring        |
| sql           | category: application<br>product: sql           |

## Cloud folder

| Product    | Logsource                                                    | Event |
| ---------- | ------------------------------------------------------------ | ----- |
| Aws        | product: aws<br>service: cloudtrail                          |
| Azure      | product: azure<br>service: activitylogs                      |
| Azure      | product: azure<br>service: signinlogs                        |
| Gcp        | product: gcp<br>service: gcp.audit                           |
| Gworkspace | product: google_workspace<br>service: google_workspace.admin |
| M365       | product: m365<br>service: threat_management                  |
| Okta       | product: okta<br>service: okta                               |
| Onelogin   | product: onelogin<br>service: onelogin.events                |

## Linux folder

| Product | Logsource                                      | Event                         |
| ------- | ---------------------------------------------- | ----------------------------- |
| Linux   | category: file_create<br>product: linux        |
| Linux   | category: network_connection<br>product: linux | EventID: 3<br>service: sysmon |
| Linux   | category: process_creation<br>product: linux   | EventID: 1<br>service: sysmon |
| Linux   | product:linux                                  | any logs                      |
| Linux   | product: linux<br>service: auditd              | auditd.log                    |
| Linux   | product: linux<br>service: auth                | auth.log                      |
| Linux   | product: linux<br>service: clamav              |
| Linux   | product: linux<br>service: cron                |
| Linux   | product: linux<br>service: guacamole           |
| Linux   | product: linux<br>service: modsecurity         |
| Linux   | product: linux<br>service: sudo                |
| Linux   | product: linux<br>service: sshd                |
| Linux   | product: linux<br>service: syslog              |
| Linux   | product: linux<br>service: vsftpd              |

## Macos folder

| Product | Logsource                                    | Event |
| ------- | -------------------------------------------- | ----- |
| Macos   | category: file_event<br>product: macos       |
| Macos   | category: process_creation<br>product: macos |

## Network folder

| Product | Logsource                                              | Event |
| ------- | ------------------------------------------------------ | ----- |
| Cisco   | product: cisco<br>service: aaa<br>category: accounting |
|         | category: dns                                          |
|         | category: firewall                                     |
| Zeek    | product: zeek<br>service: dce_rpc                      |
| Zeek    | product: zeek<br>service: dns                          |
| Zeek    | product: zeek<br>service: http                         |
| Zeek    | product: zeek<br>service: kerberos                     |
| Zeek    | product: zeek<br>service: rdp                          |
| Zeek    | product: zeek<br>service: smb_files                    |
| Zeek    | product: zeek<br>service: x509                         |
|         | category: proxy                                        |
|         | category: webserver                                    |

## Windows folder

| Product | Logsource                                                         | Event                                                                                                                                                                                                                      |
| ------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| windows | category: clipboard_capture<br>product: windows                   | EventID: 24<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: create_remote_thread<br>product: windows                | EventID: 8<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: create_stream_hash<br>product: windows                  | EventID: 15<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: dns_query<br>product: windows                           | EventID: 22<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: driver_load<br>product: windows                         | EventID: 6<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: file_change<br>product: windows                         | EventID: 2<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: file_delete<br>product: windows                         | EventID:<br> - 23<br> - 26<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                |
| windows | category: file_event<br>product: windows                          | EventID: 11<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: image_load<br>product: windows                          | EventID: 7<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: network_connection<br>product: windows                  | EventID: 3<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: pipe_created<br>product: windows                        | EventID:<br> - 17<br> - 18<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                |
| windows | category: process_access<br>product: windows                      | EventID: 10<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: process_creation<br>product: windows                    | EventID: 1<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: process_tampering<br>product: windows                   | EventID: 25<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: process_termination<br>product: windows                 | EventID: 5<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: ps_classic_provider_start<br>product: windows           | EventID: 600<br>Channel: Windows PowerShell                                                                                                                                                                                |
| windows | category: ps_classic_script<br>product: windows                   | EventID: 800<br>Channel: Windows PowerShell                                                                                                                                                                                |
| windows | category: ps_classic_start<br>product: windows                    | EventID: 400<br>Channel: Windows PowerShell                                                                                                                                                                                |
| windows | category: ps_module<br>product: windows                           | EventID: 4103<br>Channel:<br> - Microsoft-Windows-PowerShell/Operational<br> - PowerShellCore/Operational                                                                                                                                                         |
| windows | category: ps_script<br>product: windows                           | EventID: 4104<br>Channel:<br> - Microsoft-Windows-PowerShell/Operational<br> - PowerShellCore/Operational                                                                                                                                                         |
| windows | category: raw_access_thread<br>product: windows                   | EventID: 9<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | category: registry_add<br>product: windows                        | EventID: 12<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: registry_delete<br>product: windows                     | EventID: 12<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: registry_event<br>product: windows                      | EventID: <br> - 12<br> - 13<br> - 14<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                      |
| windows | category: registry_rename<br>product: windows                     | EventID: 14<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: registry_set<br>product: windows                        | EventID: 13<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | category: sysmon_error<br>product: windows                        | EventID: 255<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                              |
| windows | category: sysmon_status<br>product: windows                       | EventID: <br> - 4<br> - 16<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                |
| windows | category: wmi_event<br>product: windows                           | EventID: <br>- 19<br> - 20<br> - 21<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                       |
| windows | product: windows<br>service: application                          | Channel:<br> - Application                                                                                                                                                                                                 |
| windows | product: windows<br>service: applocker                            | Channel:<br> - Microsoft-Windows-AppLocker/MSI and Script<br> - Microsoft-Windows-AppLocker/EXE and DLL<br> - Microsoft-Windows-AppLocker/Packaged app-Deployment<br> - Microsoft-Windows-AppLocker/Packaged app-Execution |
| windows | product: windows<br>service: bits-client                          | Channel:<br> - Microsoft-Windows-Bits-Client/Operational                                                                                                                                                                   |
| windows | product: windows<br>service: codeintegrity-operational            | Channel:<br> - Microsoft-Windows-CodeIntegrity/Operational                                                                                                                                                                 |
| windows | product: windows<br>service: dhcp                                 | Channel:<br> - Microsoft-Windows-DHCP-Server/Operational                                                                                                                                                                   |
| windows | product: windows<br>service: dns-server                           | Channel:<br> - DNS Server                                                                                                                                                                                                  |
| windows | product: windows<br>service: driver-framework                     | Channel:<br> - Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                                                                                                     |
| windows | product: windows<br>service: firewall-as                          | Channel:<br> - Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                                                                                          |
| windows | product: windows<br>service: ldap_debug                           | Channel:<br> - Microsoft-Windows-LDAP-Client/Debug                                                                                                                                                                         |
| windows | product: windows<br>service: microsoft-servicebus-client          | Channel:<br> - Microsoft-ServiceBus-Client                                                                                                                                                                                 |
| windows | product: windows<br>service: msexchange-management                | Channel:<br> - MSExchange Management                                                                                                                                                                                       |
| windows | product: windows<br>service: ntlm                                 | Channel:<br> - Microsoft-Windows-NTLM/Operational                                                                                                                                                                          |
| windows | product: windows<br>service: powershell                           | Channel:<br> - Microsoft-Windows-PowerShell/Operational                                                                                                                                                                    |
| windows | product: windows<br>service: powershell-classic                   | Channel:<br> - Windows PowerShell                                                                                                                                                                                          |
| windows | product: windows<br>service: printservice-admin                   | Channel:<br> - Microsoft-Windows-PrintService/Admin                                                                                                                                                                        |
| windows | product: windows<br>service: printservice-operational             | Channel:<br> - Microsoft-Windows-PrintService/Operational                                                                                                                                                                  |
| windows | product: windows<br>service: security                             | Channel:<br>- Security                                                                                                                                                                                                     |
| windows | product: windows<br>service: security-mitigations                 | Channel:<br> - Microsoft-Windows-Security-Mitigations/Kernel Mode<br> - Microsoft-Windows-Security-Mitigations/User Mode                                                                                                   |
| windows | product: windows<br>service: smbclient-security                   | Channel:<br> - Microsoft-Windows-SmbClient/Security                                                                                                                                                                        |
| windows | product: windows<br>service: sysmon                               | Channel:<br> - Microsoft-Windows-Sysmon/Operational                                                                                                                                                                        |
| windows | product: windows<br>service: system                               | Channel:<br> - System                                                                                                                                                                                                      |
| windows | product: windows<br>service: taskscheduler                        | Channel:<br>  - Microsoft-Windows-TaskScheduler/Operational                                                                                                                                                                |
| windows | product: windows<br>service: terminalservices-localsessionmanager | Channel:<br> - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                                                                                          |
| windows | product: windows<br>service: windefend                            | Channel:<br> - Microsoft-Windows-Windows Defender/Operational                                                                                                                                                              |
| windows | product: windows<br>service: wmi                                  | Channel:<br> - Microsoft-Windows-WMI-Activity/Operational                                                                                                                                                                  |

# Fields

## Generic

### Process Creation Events

Process creation events can be defined with the generic log source category *process_creation*. The event scope can be further restricted with *product*. Example for a process creation event log source restricted to Windows:

```yml
category: process_creation
product: windows
```

The field names follow the field names used in [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) events:

| Field Name        | Example Value                                                                            | Comment   |
| ----------------- | ---------------------------------------------------------------------------------------- | --------- |
| UtcTime           | 2019-03-02 08:51:00.008                                                                  | (useless) |
| ProcessGuid       | {c1b49677-43f4-5c7a-0000-0010d3dd8044}                                                   | (useless) |
| ProcessId         | 1028                                                                                     |           |
| Image             | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe                                    |           |
| FileVersion       | 1.3.28.13                                                                                |           |
| Description       | Google Installer                                                                         |           |
| Product           | Google Update                                                                            |           |
| Company           | Google Inc.                                                                              |           |
| CommandLine       | "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /ua /installsource scheduler     |           |
| CurrentDirectory  | C:\Windows\system32\|                                                                    |
| User              | NT AUTHORITY\SYSTEM                                                                      |           |
| LogonGuid         | {c1b49677-3fb9-5c09-0000-0020e7030000}                                                   | (useless) |
| LogonId           | 0x3e7                                                                                    |           |
| TerminalSessionId | 0                                                                                        |           |
| IntegrityLevel    | System                                                                                   |           |
| imphash           | E96A73C7BF33A464C510EDE582318BF2                                                         |           |
| md5               | CCF1D1573F175299ADE01C07791A6541                                                         |           |
| sha1              | 0AE1F9071C5E8FE4A69D3F671937935D242D8A6C                                                 |           |
| sha256            | 68A15A34C2E28B9B521A240B948634617D72AD619E3950BC6DC769E60A0C3CF2                         |           |
| ParentProcessGuid | {c1b49677-6b43-5c78-0000-00107fb77544}                                                   | (useless) |
| ParentProcessId   | 1724                                                                                     |           |
| ParentImage       | C:\Windows\System32\taskeng.exe                                                          |           |
| ParentCommandLine | taskeng.exe {88F94E5C-5DC3-4606-AEFA-BDCA976D6113} S-1-5-18:NT AUTHORITY\System:Service: |           |

### Other Generic Rule Categories

We align our field names to the field names that [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) uses.
You can find all possible field values in the [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/Sysmon.md) and on [UltimateWindowsSecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx).

## Specific

* `product: windows`: Windows Operating System logs. The naming of Windows Eventlog attributes is used in Sigma rules.
  * `service: security`: Windows Security Event Log. Some may be covered by [generic log sources](#generic).
  * `service: system`: Windows System Event Log
  * `service: sysmon`: Event Logs created by Sysmon. Some may be covered by [generic log sources](#generic).
  * `service: taskscheduler`
  * `service: wmi`
  * `service: application`
  * `service: dns-server`
  * `service: driver-framework`
  * `service: powershell`
  * `service: powershell-classic`
* `product: linux`: Linux log files
  * `service: auth`: Linux authentication logs. Usually */var/log/auth.log*.
  * `service: auditd`: Linux audit logs
  * `service: clamav`: ClamAV logs
* `product: apache`: Apache httpd logs
  * `service: access`: Access logs
  * `service: error`: Error logs
* `category: proxy`
  * Field Name according to [W3C Extended Log File Format](https://www.w3.org/TR/WD-logfile.html). Additional W3 examples can be found from [Microsoft](https://docs.microsoft.com/en-us/windows/win32/http/w3c-logging).
  * Field names:
    * c-uri: URL requested by client
    * c-uri-extension: Extension of the URL. Commonly is the requested extension of a file name
    * c-uri-query: Path component of requested URL
    * c-uri-stem: Stem of the requested URL
    * c-useragent: the clients user agent.
    * cs-bytes: Number of bytes sent from the server
    * cs-cookie: Cookie headers sent from client to server.
    * cs-host: Host header send from client to server
    * cs-method: HTTP request method
    * r-dns: The Domain requested. Additionally is referred to as the Host header or URL Domain. Recommend to use `cs-host` instead of this field
    * cs-referrer: The referring link or site
    * cs-version: The HTTP protocol version that the client used
    * sc-bytes: Number of bytes sent from the client
    * sc-status: The HTTP status code
    * src_ip: The IP address of the client that made the request
    * dst_ip: The IP address of the server
* `category: firewall`
  * Field Names:
    * `src_ip`, `src_port`, `dst_ip`, `dst_port`, `username`
* `category: dns`
* `category: webserver`
  * Uses the same field names as `category: proxy`
* `product: antivirus`
  * Field Names:
    * Filename: the name and path of the source threat file
    * Signature: name of the threat like "EICAR-Test-File"
    * Action: action take by the antivirus like "delete"
