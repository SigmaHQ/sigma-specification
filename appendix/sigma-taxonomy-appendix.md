# Sigma Taxonomy <!-- omit in toc -->

The following document defines the field names and log sources that are allowed to be used in SIGMA rules that are shared on the official SigmaHQ repository.

* Version 2.0.0
* Release date 2024-08-08

## Summary

- [Summary](#summary)
- [Log Sources](#log-sources)
  - [Application Folder](#application-folder)
  - [Category Folder](#category-folder)
  - [Cloud Folder](#cloud-folder)
  - [Linux Folder](#linux-folder)
  - [Macos Folder](#macos-folder)
  - [Network Folder](#network-folder)
  - [Product Folder](#product-folder)
  - [Windows Folder](#windows-folder)
- [Fields](#fields)
  - [Generic](#generic)
    - [Process Creation Events](#process-creation-events)
    - [Other Generic Rule Categories](#other-generic-rule-categories)
  - [Specific](#specific)
- [History](#history)

## Log Sources

For a better comprehension, the log sources are organized by directory name similar to the [rules](https://github.com/SigmaHQ/sigma/tree/master/rules) structure in the SIGMA project

### Application Folder

The *application* folder contains rules that are intended for application security monitoring. The rules are organized into folders per application technology. All rules define log sources as follows:

* The *category* log source attribute is set to `application`. This can be used by processing pipelines to create a technology-agnostic conversion configuration in cases where the application technology stack is unknown.

* The *product* log source attribute is set to the name of the technology and should be equal to the folder name.

Because application logs are often ingested as raw text events with poor decomposition into fields by many target systems, these rules are keyword rules that don't match on specific fields.

| Product       | Logsource                                       | Event |
| ------------- | ----------------------------------------------- | ----- |
| django        | category: application<br>product: django        |       |
| python        | category: application<br>product: python        |       |
| rpc_firewall  | category: application<br>product: rpc_firewall  |       |
| ruby_on_rails | category: application<br>product: ruby_on_rails |       |
| spring        | category: application<br>product: spring        |       |
| sql           | category: application<br>product: sql           |       |

### Category Folder

| Product | Logsource           | Event                                                      |
| ------- | ------------------- | ---------------------------------------------------------- |
|         | category: antivirus | antivirus detection message (format depends on the editor) |
|         | category: database  | sql queries log (drop, select,...)                         |

### Cloud Folder

| Product    | Logsource                                                    | Event                  |
| ---------- | ------------------------------------------------------------ | ---------------------- |
| Aws        | product: aws<br>service: cloudtrail                          |                        |
| Azure      | product: azure<br>service: activitylogs                      |                        |
| Azure      | product: azure<br>service: signinlogs                        |                        |
| Gcp        | product: gcp<br>service: gcp.audit                           |                        |
| Github     | product: github<br>service: audit                            | organization Audit log |
| Gworkspace | product: google_workspace<br>service: google_workspace.admin |                        |
| M365       | product: m365<br>service: threat_management                  |                        |
| Okta       | product: okta<br>service: okta                               |                        |
| Onelogin   | product: onelogin<br>service: onelogin.events                |                        |

### Linux Folder

| Product | Logsource                                      | Event                          |
| ------- | ---------------------------------------------- | ------------------------------ |
| Linux   | product: linux                                 | All Linux Logs                 |
| Linux   | product: linux<br>category: file_event         | EventID: 11<br>service: sysmon |
| Linux   | product: linux<br>category: network_connection | EventID: 3<br>service: sysmon  |
| Linux   | product: linux<br>category: process_creation   | EventID: 1<br>service: sysmon  |
| Linux   | product: linux<br>service: auditd              | auditd.log                     |
| Linux   | product: linux<br>service: auth                | auth.log                       |
| Linux   | product: linux<br>service: clamav              |                                |
| Linux   | product: linux<br>service: cron                |                                |
| Linux   | product: linux<br>service: guacamole           |                                |
| Linux   | product: linux<br>service: sudo                |                                |
| Linux   | product: linux<br>service: sshd                |                                |
| Linux   | product: linux<br>service: syslog              |                                |
| Linux   | product: linux<br>service: vsftpd              |                                |

### Macos Folder

| Product | Logsource                                    | Event               |
| ------- | -------------------------------------------- | ------------------- |
| Macos   | product: macos                               |  All Macos Logs     |
| Macos   | product: macos<br>category: file_event       |                     |
| Macos   | product: macos<br>category: process_creation |                     |

### Network Folder

| Product | Logsource                           | Event |
| ------- | ----------------------------------- | ----- |
| Cisco   | product: cisco<br>service: aaa      |
| Cisco   | product: cisco<br>service: bgp      |
| Cisco   | product: cisco<br>service: ldp      |
| Huawei  | product: huawei<br>service: ldp     |
| Juniper | product: juniper<br>service: ldp    |
| Zeek    | product: zeek<br>service: dce_rpc   |
| Zeek    | product: zeek<br>service: dns       |
| Zeek    | product: zeek<br>service: http      |
| Zeek    | product: zeek<br>service: kerberos  |
| Zeek    | product: zeek<br>service: rdp       |
| Zeek    | product: zeek<br>service: smb_files |
| Zeek    | product: zeek<br>service: x509      |
|         | category: dns                       |
|         | category: firewall                  |
|         | category: proxy                     |
|         | category: webserver                 |

### Product Folder

| Product     | Logsource            | Event                 |
| ----------- | -------------------- | --------------------- |
| Apache      | service: apache      | Application error.log |
| Modsecurity | product: modsecurity |                       |

### Windows Folder

| Product | Logsource                                                         | Event                                                                                                                                                                                                                      |
| ------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| windows | product: windows                                                  | All Windows Logs                                                                                                                                                                                                           |
| windows | product: windows<br>category: clipboard_capture                   | EventID: 24<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: create_remote_thread                | EventID: 8<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: create_stream_hash                  | EventID: 15<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: dns_query                           | EventID: 22<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: driver_load                         | EventID: 6<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: file_access                         | ETW Provider: Microsoft-Windows-Kernel-File                                                                                                                                                                                |
| windows | product: windows<br>category: file_change                         | EventID: 2<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: file_delete                         | EventID:<br> - 23<br> - 26<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                |
| windows | product: windows<br>category: file_event                          | EventID: 11<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: file_rename                         | ETW Provider: Microsoft-Windows-Kernel-File                                                                                                                                                                                |
| windows | product: windows<br>category: image_load                          | EventID: 7<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: network_connection                  | EventID: 3<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: pipe_created                        | EventID:<br> - 17<br> - 18<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                |
| windows | product: windows<br>category: process_access                      | EventID: 10<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: process_creation                    | EventID: 1<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: process_tampering                   | EventID: 25<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: process_termination                 | EventID: 5<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: ps_classic_provider_start           | EventID: 600<br>Channel: Windows PowerShell                                                                                                                                                                                |
| windows | product: windows<br>category: ps_classic_script                   | EventID: 800<br>Channel: Windows PowerShell                                                                                                                                                                                |
| windows | product: windows<br>category: ps_classic_start                    | EventID: 400<br>Channel: Windows PowerShell                                                                                                                                                                                |
| windows | product: windows<br>category: ps_module                           | EventID: 4103<br>Channel:<br> - Microsoft-Windows-PowerShell/Operational<br> - PowerShellCore/Operational                                                                                                                  |
| windows | product: windows<br>category: ps_script                           | EventID: 4104<br>Channel:<br> - Microsoft-Windows-PowerShell/Operational<br> - PowerShellCore/Operational                                                                                                                  |
| windows | product: windows<br>category: raw_access_thread                   | EventID: 9<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                |
| windows | product: windows<br>category: registry_add                        | EventID: 12<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: registry_delete                     | EventID: 12<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: registry_event                      | EventID: <br> - 12<br> - 13<br> - 14<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                      |
| windows | product: windows<br>category: registry_rename                     | EventID: 14<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: registry_set                        | EventID: 13<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                               |
| windows | product: windows<br>category: sysmon_error                        | EventID: 255<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                              |
| windows | product: windows<br>category: sysmon_status                       | EventID: <br> - 4<br> - 16<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                |
| windows | product: windows<br>category: wmi_event                           | EventID: <br> - 19<br> - 20<br> - 21<br>Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                      |
| windows | product: windows<br>service: application                          | Channel: Application                                                                                                                                                                                                 |
| windows | product: windows<br>service: application-experience               | Channel:<br> - Microsoft-Windows-Application-Experience/Program-Telemetry<br> - Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant                                                             |
| windows | product: windows<br>service: applocker                            | Channel:<br> - Microsoft-Windows-AppLocker/MSI and Script<br> - Microsoft-Windows-AppLocker/EXE and DLL<br> - Microsoft-Windows-AppLocker/Packaged app-Deployment<br> - Microsoft-Windows-AppLocker/Packaged app-Execution |
| windows | product: windows<br>service: appmodel-runtime                     | Channel: Microsoft-Windows-AppModel-Runtime/Admin                                                                                                                                                                    |
| windows | product: windows<br>service: appxdeployment-server                | Channel: Microsoft-Windows-AppXDeploymentServer/Operational                                                                                                                                                          |
| windows | product: windows<br>service: appxpackaging-om                     | Channel: Microsoft-Windows-AppxPackaging/Operational                                                                                                                                                                 |
| windows | product: windows<br>service: bitlocker                            | Channel: Microsoft-Windows-BitLocker/BitLocker Management                                                                                                                                                            |
| windows | product: windows<br>service: bits-client                          | Channel: Microsoft-Windows-Bits-Client/Operational                                                                                                                                                                   |
| windows | product: windows<br>service: capi2                                | Channel: Microsoft-Windows-CAPI2/Operational                                                                                                                                                                         |
| windows | product: windows<br>service: certificateservicesclient-lifecycle-system  | Channel: Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                                                                                             |
| windows | product: windows<br>service: codeintegrity-operational            | Channel: Microsoft-Windows-CodeIntegrity/Operational                                                                                                                                                                 |
| windows | product: windows<br>service: dhcp                                 | Channel: Microsoft-Windows-DHCP-Server/Operational                                                                                                                                                                   |
| windows | product: windows<br>service: diagnosis-scripted                   | Channel: Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                                                                                            |
| windows | product: windows<br>service: dns-client                           | Channel: Microsoft-Windows-DNS Client Events/Operational                                                                                                                                                             |
| windows | product: windows<br>service: dns-server                           | Channel: DNS Server                                                                                                                                                                                                  |
| windows | product: windows<br>service: dns-server-analytic                  | Channel: Microsoft-Windows-DNS-Server/Analytical                                                                                                                                                                     |
| windows | product: windows<br>service: dns-server-audit                     | Channel: Microsoft-Windows-DNS-Server/Audit                                                                                                                                                                          |
| windows | product: windows<br>service: driver-framework                     | Channel: Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                                                                                                     |
| windows | product: windows<br>service: firewall-as                          | Channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                                                                                          |
| windows | product: windows<br>service: hyper-v-worker                       | Channel: Microsoft-Windows-Hyper-V-Worker                                                                                                                                                                            |
| windows | product: windows<br>service: kernel-event-tracing                 | Channel: Microsoft-Windows-Kernel-EventTracing                                                                                                                                                                       |
| windows | product: windows<br>service: kernel-shimengine                    | Channel:<br> - Microsoft-Windows-Kernel-ShimEngine/Operational<br> - WinEventLog:Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                                                                      |
| windows | product: windows<br>service: ldap                                 | Channel: Microsoft-Windows-LDAP-Client/Debug                                                                                                                                                                         |
| windows | product: windows<br>service: lsa-server                           | Channel: Microsoft-Windows-LSA/Operational                                                                                                                                                                           |
| windows | product: windows<br>service: msexchange-management                | Channel: MSExchange Management                                                                                                                                                                                       |
| windows | product: windows<br>service: ntfs                                 | Channel: Microsoft-Windows-Ntfs/Operational                                                                                                                                                                          |
| windows | product: windows<br>service: ntlm                                 | Channel: Microsoft-Windows-NTLM/Operational                                                                                                                                                                          |
| windows | product: windows<br>service: openssh                              | Channel: OpenSSH/Operational                                                                                                                                                                                         |
| windows | product: windows<br>service: powershell                           | Channel: Microsoft-Windows-PowerShell/Operational                                                                                                                                                                    |
| windows | product: windows<br>service: powershell-classic                   | Channel: Windows PowerShell                                                                                                                                                                                          |
| windows | product: windows<br>service: printservice-admin                   | Channel: Microsoft-Windows-PrintService/Admin                                                                                                                                                                        |
| windows | product: windows<br>service: printservice-operational             | Channel: Microsoft-Windows-PrintService/Operational                                                                                                                                                                  |
| windows | product: windows<br>service: security                             | Channel: Security                                                                                                                                                                                                    |
| windows | product: windows<br>service: security-mitigations                 | Channel:<br> - Microsoft-Windows-Security-Mitigations/Kernel Mode<br> - Microsoft-Windows-Security-Mitigations/User Mode                                                                                             |
| windows | product: windows<br>service: sense                                | Channel: Microsoft-Windows-SENSE/Operational                                                                                                                                                                         |
| windows | product: windows<br>service: servicebus-client                    | Channel: <br> - Microsoft-ServiceBus-Client/Operational<br> -  Microsoft-ServiceBus-Client/Admin                                                                                                                     |
| windows | product: windows<br>service: shell-core                           | Channel: Microsoft-Windows-Shell-Core/Operational                                                                                                                                                                    |
| windows | product: windows<br>service: smbclient-security                   | Channel: Microsoft-Windows-SmbClient/Security                                                                                                                                                                        |
| windows | product: windows<br>service: sysmon                               | Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                        |
| windows | product: windows<br>service: system                               | Channel: System                                                                                                                                                                                                      |
| windows | product: windows<br>service: taskscheduler                        | Channel: Microsoft-Windows-TaskScheduler/Operational                                                                                                                                                                 |
| windows | product: windows<br>service: terminalservices-localsessionmanager | Channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                                                                                          |
| windows | product: windows<br>service: vhdmp                                | Channel: Microsoft-Windows-VHDMP/Operational                                                                                                                                                                         |
| windows | product: windows<br>service: windefend                            | Channel: Microsoft-Windows-Windows Defender/Operational                                                                                                                                                              |
| windows | product: windows<br>service: wmi                                  | Channel: Microsoft-Windows-WMI-Activity/Operational                                                                                                                                                                  |

## Fields

### Generic

#### Process Creation Events

Process creation events can be defined with the generic log source category *process_creation*. The event scope can be further restricted with *product*. Example for a process creation event log source restricted to Windows:

```yml
category: process_creation
product: windows
```

The field names follow the field names used in [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) events:

| Field Name        | Example Value                                                                            | Comment |
| ----------------- | ---------------------------------------------------------------------------------------- | ------- |
| UtcTime           | 2019-03-02 08:51:00.008                                                                  |         |
| ProcessGuid       | {c1b49677-43f4-5c7a-0000-0010d3dd8044}                                                   |         |
| ProcessId         | 1028                                                                                     |         |
| Image             | C:\Program Files (x86)\Google\Update\GoogleUpdate.exe                                    |         |
| FileVersion       | 1.3.28.13                                                                                |         |
| Description       | Google Installer                                                                         |         |
| Product           | Google Update                                                                            |         |
| Company           | Google Inc.                                                                              |         |
| CommandLine       | "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /ua /installsource scheduler     |         |
| CurrentDirectory  | C:\Windows\system32\|                                                                    |         |
| User              | NT AUTHORITY\SYSTEM                                                                      |         |
| LogonGuid         | {c1b49677-3fb9-5c09-0000-0020e7030000}                                                   |         |
| LogonId           | 0x3e7                                                                                    |         |
| TerminalSessionId | 0                                                                                        |         |
| IntegrityLevel    | System                                                                                   |         |
| imphash           | E96A73C7BF33A464C510EDE582318BF2                                                         |         |
| md5               | CCF1D1573F175299ADE01C07791A6541                                                         |         |
| sha1              | 0AE1F9071C5E8FE4A69D3F671937935D242D8A6C                                                 |         |
| sha256            | 68A15A34C2E28B9B521A240B948634617D72AD619E3950BC6DC769E60A0C3CF2                         |         |
| ParentProcessGuid | {c1b49677-6b43-5c78-0000-00107fb77544}                                                   |         |
| ParentProcessId   | 1724                                                                                     |         |
| ParentImage       | C:\Windows\System32\taskeng.exe                                                          |         |
| ParentCommandLine | taskeng.exe {88F94E5C-5DC3-4606-AEFA-BDCA976D6113} S-1-5-18:NT AUTHORITY\System:Service: |         |

#### Other Generic Rule Categories

We align our field names to the field names that [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) uses.
You can find all possible field values in the [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/Sysmon.md) and on [UltimateWindowsSecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx).

### Specific

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
    * `c-uri`: URL requested by client
    * `c-uri-extension`: Extension of the URL. Commonly is the requested extension of a file name
    * `c-uri-query`: Path component of requested URL
    * `c-uri-stem`: Stem of the requested URL
    * `c-useragent`: the clients user agent.
    * `cs-bytes`: Number of bytes sent from the server
    * `cs-cookie`: Cookie headers sent from client to server.
    * `cs-host`: Host header send from client to server
    * `cs-method`: HTTP request method
    * `r-dns`: The Domain requested. Additionally is referred to as the Host header or URL Domain. Recommend to use `cs-host` instead of this field
    * `cs-referrer`: The referring link or site
    * `cs-version`: The HTTP protocol version that the client used
    * `sc-bytes`: Number of bytes sent from the client
    * `sc-status`: The HTTP status code
    * `src_ip`: The IP address of the client that made the request
    * `dst_ip`: The IP address of the server
* `category: firewall`
  * Field Names:
    * `src_ip`, `src_port`, `dst_ip`, `dst_port`, `username`
* `category: dns`
* `category: webserver`
  * `date`: The date that the activity occurred.
  * `time`: The time that the activity occurred.
  * `c-ip`:The IP address of the client that accessed your server.
  * `cs-username`: The name of the authenticated user who accessed your server. This does not include anonymous users, who are represented by a hyphen (-).
  * `s-sitename`: The Internet service and instance number that was accessed by a client.
  * `s-computername`: The name of the server on which the log entry was generated.
  * `s-ip`: The IP address of the server on which the log entry was generated.
  * `s-port`: The port number the client is connected to.
  * `cs-method`: The action the client was trying to perform (for example, a GET method).
  * `cs-uri-stem`: The resource accessed; for example, Default.htm.
  * `cs-uri-query`: The query, if any, the client was trying to perform.
  * `sc-status`: The status of the action, in HTTP or FTP terms.
  * `c-win32-status`: The status of the action, in terms used by Microsoft Windows®.
  * `sc-bytes`: The number of bytes sent by the server.
  * `cs-bytes`: The number of bytes received by the server.
  * `time-taken`: The duration of time, in milliseconds, that the action consumed.
  * `cs-version`: The protocol (HTTP, FTP) version used by the client. For HTTP this will be either HTTP 1.0 or HTTP 1.1.
  * `cs-host`: Displays the content of the host header.
  * `cs-user-agent`: The browser used on the client.
  * `cs-cookie`: The content of the cookie sent or received, if any.
  * `cs-referer`: The previous site visited by the user. This site provided a link to the current site.
* `product: antivirus`
  * Field Names:
    * `Filename`: the name and path of the source threat file
    * `Signature`: name of the threat like "EICAR-Test-File"
    * `Action`: action take by the antivirus like "delete"

## History

* 2024-08-08 Taxonomy Appendix v v2.0.0
  * Fix the following windows services:
    * Change `ldap_debug` to `ldap`
  * Add new windows services:
    * ``service: application-experience``
    * ``service: capi2``
    * ``service: certificateservicesclient-lifecycle-system``
    * ``service: hyper-v-worker``
    * ``service: kernel-event-tracing``
    * ``service: kernel-shimengine``
    * ``service: ntfs``
    * ``service: sense``
    * ``service: servicebus-client``
* 2023-01-21 Taxonomy Appendix v1.3.5
  * Add new product and its related service:
    * `product: github`
    * `service: audit`
* 2023-01-18 Taxonomy Appendix v1.3.4
  * Add the following new windows services:
    * `service: appxdeployment-server`
    * `service: lsa-server`
    * `service: appxpackaging-om`
    * `service: dns-client`
    * `service: appmodel-runtime`
    * `service: vhdmp`
  * Add new cisco services:
    * `service: bgp`
    * `service: ldp`
  * Add new huawei `service: bgp`
  * Add new juniper `service: bgp`
  * Add missing category folder
  * Add missing product folder
  * Add description for a special case when using only the `product` logsource
* 2023-01-03 Taxonomy Appendix v1.3.3
  * Add windows service dns-server-analytic and bitlocker
  * Add all the W3C fields names to the category `webserver`
  * Update linux `file_create` category to `file_event`
* 2022-12-19 Taxonomy Appendix v1.3.2
  * Minor tweak and updates to the syntax and text
* 2022-11-13 Taxonomy Appendix v1.3.1
  * Add missing service shell-core
* 2022-11-01 Taxonomy Appendix v1.3.0
  * Add missing windows services
* 2022-10-25 Taxonomy Appendix v1.2.0
  * Order the windows logs
* 2022-10-19 Taxonomy Appendix v1.1.0
  * Fix links and spelling
* 2022-09-18 Taxonomy v1.0.0
  * Initial release
