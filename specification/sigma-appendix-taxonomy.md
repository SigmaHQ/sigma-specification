# Sigma Taxonomy

The following document defines the field names and log sources that are allowed to be used in SIGMA rules that are shared on the official SigmaHQ repository.

- Version 2.1.1
- Release date 2026-11-11

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Log Sources](#log-sources)
  - [Application Folder](#application-folder)
    - [Django](#django)
    - [Python](#python)
    - [RPC Firewall](#rpc-firewall)
    - [Ruby on Rails](#ruby-on-rails)
    - [Spring Framewor](#spring-framewor)
    - [SQL](#sql)
  - [Category Folder](#category-folder)
  - [Cloud Folder](#cloud-folder)
    - [AWS](#aws)
    - [Azure](#azure)
    - [Bitbucket](#bitbucket)
    - [Cisco](#cisco)
    - [GCP](#gcp)
    - [Github](#github)
    - [M365](#m365)
    - [Okta](#okta)
    - [OneLogin](#onelogin)
  - [Linux Folder](#linux-folder)
    - [Category](#category)
    - [Service](#service)
  - [Macos Folder](#macos-folder)
    - [Category](#category-1)
    - [Service](#service-1)
  - [Network Folder](#network-folder)
    - [Cisco](#cisco-1)
    - [Huawei](#huawei)
    - [Juniper](#juniper)
    - [Zeek](#zeek)
  - [Other](#other)
  - [Product Folder](#product-folder)
  - [Windows Folder](#windows-folder)
    - [Category](#category-2)
    - [Service](#service-2)
- [Network Events](#network-events)
- [Fields](#fields)
  - [Generic](#generic)
    - [Process Creation Events](#process-creation-events)
    - [Other Generic Rule Categories](#other-generic-rule-categories)
  - [Specific](#specific)
  - [macOS Endpoint Security Framework (ESF)](#macos-endpoint-security-framework-esf)
    - [Process Fields](#process-fields)
    - [Code Signature Fields](#code-signature-fields)
    - [File Fields](#file-fields)
    - [Process Access and Signal Fields](#process-access-and-signal-fields)
    - [Privilege, Memory, XPC and Kernel Extension Fields](#privilege-memory-xpc-and-kernel-extension-fields)
    - [TCC and Background Task Fields](#tcc-and-background-task-fields)
    - [Account, Authentication and Outcome Fields](#account-authentication-and-outcome-fields)
    - [Screen Sharing Fields](#screen-sharing-fields)
    - [Configuration Profile and Open Directory Fields](#configuration-profile-and-open-directory-fields)
    - [XProtect and Gatekeeper Fields](#xprotect-and-gatekeeper-fields)
  - [Network category](#network-category)
- [History](#history)

<!-- mdformat-toc end -->

For example in pySigma for ocsf taxonomy you can use the [pySigma-pipeline-ocsf pipeline](https://github.com/SigmaHQ/pySigma-pipeline-ocsf)

## Log Sources

For a better comprehension, the log sources are organized by directory name similar to the [rules](https://github.com/SigmaHQ/sigma/tree/master/rules) structure in the SIGMA project.

### Application Folder

The *application* folder contains rules that are intended for application security monitoring. The rules are organized into folders per application technology. All rules define log sources as follows:

- The *category* log source attribute is set to `application`. This can be used by processing pipelines to create a technology-agnostic conversion configuration in cases where the application technology stack is unknown.

- The *product* log source attribute is set to the name of the technology and should be equal to the folder name.

Because application logs are often ingested as raw text events with poor decomposition into fields by many target systems, these rules are keyword rules that don't match on specific fields.

#### Django

| Product | Logsource                                | Description |
| ------- | ---------------------------------------- | ----------- |
| django  | category: application<br>product: django |             |

#### Python

| Product | Logsource                                | Description |
| ------- | ---------------------------------------- | ----------- |
| python  | category: application<br>product: python |             |

#### RPC Firewall

| Product      | Logsource                                      | Description |
| ------------ | ---------------------------------------------- | ----------- |
| rpc_firewall | category: application<br>product: rpc_firewall |             |

#### Ruby on Rails

| Product       | Logsource                                       | Description |
| ------------- | ----------------------------------------------- | ----------- |
| ruby_on_rails | category: application<br>product: ruby_on_rails |             |

#### Spring Framewor

| Product | Logsource                                | Description |
| ------- | ---------------------------------------- | ----------- |
| spring  | category: application<br>product: spring |             |

#### SQL

| Product | Logsource                             | Description |
| ------- | ------------------------------------- | ----------- |
| sql     | category: application<br>product: sql |             |

### Category Folder

| Product | Logsource           | Description                                                |
| ------- | ------------------- | ---------------------------------------------------------- |
|         | category: antivirus | antivirus detection message (format depends on the editor) |
|         | category: database  | sql queries log (drop, select,...)                         |

### Cloud Folder

#### AWS

| Product | Logsource                           | Description |
| ------- | ----------------------------------- | ----------- |
| Aws     | product: aws<br>service: cloudtrail |             |

#### Azure

| Product | Logsource                                | Description |
| ------- | ---------------------------------------- | ----------- |
| Azure   | product: azure<br>service: activitylogs  |             |
| Azure   | product: azure<br>service: auditlogs     |             |
| Azure   | product: azure<br>service: riskdetection |             |
| Azure   | product: azure<br>service: pim           |             |
| Azure   | product: azure<br>service: signinlogs    |             |

#### Bitbucket

| Product   | Logsource                            | Description |
| --------- | ------------------------------------ | ----------- |
| Bitbucket | product: bitbucket<br>service: audit |             |

#### Cisco

| Product | Logsource                      | Description |
| ------- | ------------------------------ | ----------- |
| Cisco   | product: cisco<br>service: duo |             |

#### GCP

| Product | Logsource                                       | Description |
| ------- | ----------------------------------------------- | ----------- |
| GCP     | product: gcp<br>service: gcp.audit              |             |
| GCP     | product: gcp<br>service: google_workspace.admin |             |

#### Github

| Product | Logsource                         | Description            |
| ------- | --------------------------------- | ---------------------- |
| Github  | product: github<br>service: audit | organization Audit log |

#### M365

| Product | Logsource                                   | Description |
| ------- | ------------------------------------------- | ----------- |
| M365    | product: m365<br>service: audit             |             |
| M365    | product: m365<br>service: exchange          |             |
| M365    | product: m365<br>service: threat_detection  |             |
| M365    | product: m365<br>service: threat_management |             |

#### Okta

| Product | Logsource                      | Description |
| ------- | ------------------------------ | ----------- |
| Okta    | product: okta<br>service: okta |             |

#### OneLogin

| Product  | Logsource                                     | Description |
| -------- | --------------------------------------------- | ----------- |
| Onelogin | product: onelogin<br>service: onelogin.events |             |

### Linux Folder

#### Category

| Product | Logsource                                      | Description                    |
| ------- | ---------------------------------------------- | ------------------------------ |
| Linux   | product: linux<br>category: file_event         | EventID: 11<br>service: sysmon |
| Linux   | product: linux<br>category: network_connection | EventID: 3<br>service: sysmon  |
| Linux   | product: linux<br>category: process_creation   | EventID: 1<br>service: sysmon  |

#### Service

| Product | Logsource                            | Description |
| ------- | ------------------------------------ | ----------- |
| Linux   | product: linux<br>service: auditd    | auditd.log  |
| Linux   | product: linux<br>service: auth      | auth.log    |
| Linux   | product: linux<br>service: clamav    |             |
| Linux   | product: linux<br>service: cron      |             |
| Linux   | product: linux<br>service: guacamole |             |
| Linux   | product: linux<br>service: sudo      |             |
| Linux   | product: linux<br>service: sshd      |             |
| Linux   | product: linux<br>service: syslog    |             |
| Linux   | product: linux<br>service: vsftpd    |             |

### Macos Folder

#### Category

The macOS categories are read from Apple Endpoint Security Framework (ESF) events. `service: endpointsecurity` is optional: a rule with `product: macos`, one of these categories and no `service` uses ESF events, and a rule may set `service: endpointsecurity` to say so explicitly.
The event names are the names `eslogger` uses (`eslogger --list-events`).
`file_event` covers `create` events and the destination of `rename` events, so a file written elsewhere and moved into place is included. Other ways a file can appear, such as `clone`, `link` or `copyfile`, are not.
`process_access` covers `get_task` and `trace`; the `get_task_read`, `get_task_inspect` and `get_task_name` variants are not included.
In `file_attribute_change`, `TargetFilename` is set for all five events and `ExtendedAttribute` for `setextattr` and `deleteextattr`. The new mode, owner and flags are not defined as fields yet.
ESF has no TCP/UDP connection or DNS events, so `network_connection` and `dns_query` are not macOS ESF categories.
The fields are listed in [macOS Endpoint Security Framework (ESF)](#macos-endpoint-security-framework-esf).

| Product | Logsource                                         | Description                                                                                                                                                                                                                                                                                                                                     |
| ------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Macos   | product: macos<br>category: authentication        | ESF event: `authentication`                                                                                                                                                                                                                                                                                                                     |
| Macos   | product: macos<br>category: background_task       | ESF events:<br> - `btm_launch_item_add`<br> - `btm_launch_item_remove`                                                                                                                                                                                                                                                                          |
| Macos   | product: macos<br>category: configuration_profile | ESF events:<br> - `profile_add`<br> - `profile_remove`                                                                                                                                                                                                                                                                                          |
| Macos   | product: macos<br>category: create_remote_thread  | ESF event: `remote_thread_create`                                                                                                                                                                                                                                                                                                               |
| Macos   | product: macos<br>category: driver_load           | ESF event: `kextload`                                                                                                                                                                                                                                                                                                                           |
| Macos   | product: macos<br>category: file_access           | ESF event: `open`                                                                                                                                                                                                                                                                                                                               |
| Macos   | product: macos<br>category: file_attribute_change | ESF events:<br> - `setextattr`<br> - `deleteextattr`<br> - `setmode`<br> - `setowner`<br> - `setflags`                                                                                                                                                                                                                                          |
| Macos   | product: macos<br>category: file_delete           | ESF event: `unlink`                                                                                                                                                                                                                                                                                                                             |
| Macos   | product: macos<br>category: file_event            | ESF events:<br> - `create`<br> - `rename` (the new path)                                                                                                                                                                                                                                                                                        |
| Macos   | product: macos<br>category: file_rename           | ESF event: `rename`                                                                                                                                                                                                                                                                                                                             |
| Macos   | product: macos<br>category: gatekeeper_override   | ESF event: `gatekeeper_user_override`                                                                                                                                                                                                                                                                                                           |
| Macos   | product: macos<br>category: memory_protection     | ESF event: `mprotect`                                                                                                                                                                                                                                                                                                                           |
| Macos   | product: macos<br>category: privilege_change      | ESF events:<br> - `setuid`<br> - `setgid`<br> - `seteuid`<br> - `setreuid`<br> - `setegid`<br> - `setregid`                                                                                                                                                                                                                                     |
| Macos   | product: macos<br>category: process_access        | ESF events:<br> - `get_task`<br> - `trace`                                                                                                                                                                                                                                                                                                      |
| Macos   | product: macos<br>category: process_creation      | ESF event: `exec`                                                                                                                                                                                                                                                                                                                               |
| Macos   | product: macos<br>category: process_signal        | ESF event: `signal`                                                                                                                                                                                                                                                                                                                             |
| Macos   | product: macos<br>category: screen_sharing        | ESF events:<br> - `screensharing_attach`<br> - `screensharing_detach`                                                                                                                                                                                                                                                                           |
| Macos   | product: macos<br>category: sudo                  | ESF events:<br> - `sudo`<br> - `su`                                                                                                                                                                                                                                                                                                             |
| Macos   | product: macos<br>category: tcc_modification      | ESF event: `tcc_modify`                                                                                                                                                                                                                                                                                                                         |
| Macos   | product: macos<br>category: user_account_change   | ESF events:<br> - `od_create_user`<br> - `od_delete_user`<br> - `od_modify_password`<br> - `od_disable_user`<br> - `od_enable_user`<br> - `od_attribute_value_add`<br> - `od_attribute_value_remove`<br> - `od_attribute_set`<br> - `od_create_group`<br> - `od_delete_group`<br> - `od_group_add`<br> - `od_group_remove`<br> - `od_group_set` |
| Macos   | product: macos<br>category: xpc_connection        | ESF event: `xpc_connect`                                                                                                                                                                                                                                                                                                                        |
| Macos   | product: macos<br>category: xprotect              | ESF events:<br> - `xp_malware_detected`<br> - `xp_malware_remediated`                                                                                                                                                                                                                                                                           |

#### Service

| Product | Logsource                                   | Description                                                                               |
| ------- | ------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Macos   | product: macos<br>service: endpointsecurity | Apple Endpoint Security Framework (ESF) events. Optional with the macOS categories above. |

### Network Folder

#### Cisco

| Product | Logsource                      | Description |
| ------- | ------------------------------ | ----------- |
| Cisco   | product: cisco<br>service: aaa |             |
| Cisco   | product: cisco<br>service: bgp |             |
| Cisco   | product: cisco<br>service: ldp |             |

#### Huawei

| Product | Logsource                       | Description |
| ------- | ------------------------------- | ----------- |
| Huawei  | product: huawei<br>service: ldp |             |

#### Juniper

| Product | Logsource                        | Description |
| ------- | -------------------------------- | ----------- |
| Juniper | product: juniper<br>service: ldp |             |

#### Zeek

| Product | Logsource                           | Description |
| ------- | ----------------------------------- | ----------- |
| Zeek    | product: zeek<br>service: dce_rpc   |             |
| Zeek    | product: zeek<br>service: dns       |             |
| Zeek    | product: zeek<br>service: http      |             |
| Zeek    | product: zeek<br>service: kerberos  |             |
| Zeek    | product: zeek<br>service: rdp       |             |
| Zeek    | product: zeek<br>service: smb_files |             |
| Zeek    | product: zeek<br>service: x509      |             |

### Other

| Product | Logsource           | Description |
| ------- | ------------------- | ----------- |
| N/A     | category: dns       |             |
| N/A     | category: firewall  |             |
| N/A     | category: proxy     |             |
| N/A     | category: webserver |             |

### Product Folder

| Product     | Logsource            | Description           |
| ----------- | -------------------- | --------------------- |
| Apache      | service: apache      | Application error.log |
| Modsecurity | product: modsecurity |                       |

### Windows Folder

#### Category

| Product | Logsource                                               | Description                                                                                               |
| ------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| windows | product: windows<br>category: process_creation          | EventID: 1<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: file_change               | EventID: 2<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: network_connection        | EventID: 3<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: sysmon_status             | EventIDs: <br> - 4<br> - 16<br>Channel: Microsoft-Windows-Sysmon/Operational                              |
| windows | product: windows<br>category: process_termination       | EventID: 5<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: driver_load               | EventID: 6<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: image_load                | EventID: 7<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: create_remote_thread      | EventID: 8<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: raw_access_thread         | EventID: 9<br>Channel: Microsoft-Windows-Sysmon/Operational                                               |
| windows | product: windows<br>category: process_access            | EventID: 10<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: file_event                | EventID: 11<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: registry_event            | EventID: <br> - 12<br> - 13<br> - 14<br>Channel: Microsoft-Windows-Sysmon/Operational                     |
| windows | product: windows<br>category: registry_add              | EventID: 12<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: registry_delete           | EventID: 12<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: registry_set              | EventID: 13<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: registry_rename           | EventID: 14<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: create_stream_hash        | EventID: 15<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: pipe_created              | EventIDs: <br> - 17<br> - 18<br>Channel: Microsoft-Windows-Sysmon/Operational                             |
| windows | product: windows<br>category: wmi_event                 | EventIDs: <br> - 19<br> - 20<br> - 21<br>Channel: Microsoft-Windows-Sysmon/Operational                    |
| windows | product: windows<br>category: dns_query                 | EventID: 22<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: file_delete               | EventID: 23<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: clipboard_capture         | EventID: 24<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: process_tampering         | EventID: 25<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: file_delete_detected      | EventID: 26<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: file_block_executable     | EventID: 27<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: file_block_shredding      | EventID: 28<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: file_executable_detected  | EventID: 29<br>Channel: Microsoft-Windows-Sysmon/Operational                                              |
| windows | product: windows<br>category: sysmon_error              | EventID: 255<br>Channel: Microsoft-Windows-Sysmon/Operational                                             |
| windows | product: windows<br>category: file_access               | ETW Provider: Microsoft-Windows-Kernel-File                                                               |
| windows | product: windows<br>category: ps_classic_start          | EventID: 400<br>Channel: Windows PowerShell                                                               |
| windows | product: windows<br>category: ps_classic_provider_start | EventID: 600<br>Channel: Windows PowerShell                                                               |
| windows | product: windows<br>category: ps_classic_script         | EventID: 800<br>Channel: Windows PowerShell                                                               |
| windows | product: windows<br>category: ps_module                 | EventID: 4103<br>Channel:<br> - Microsoft-Windows-PowerShell/Operational<br> - PowerShellCore/Operational |
| windows | product: windows<br>category: ps_script                 | EventID: 4104<br>Channel:<br> - Microsoft-Windows-PowerShell/Operational<br> - PowerShellCore/Operational |
| windows | product: windows<br>category: file_rename               | ETW Provider: Microsoft-Windows-Kernel-File                                                               |

#### Service

| Product | Logsource                                                               | Description                                                                                                                                                                                                                |
| ------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| windows | product: windows<br>service: application                                | Channel: Application                                                                                                                                                                                                       |
| windows | product: windows<br>service: application-experience                     | Channel:<br> - Microsoft-Windows-Application-Experience/Program-Telemetry<br> - Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant                                                                   |
| windows | product: windows<br>service: applocker                                  | Channel:<br> - Microsoft-Windows-AppLocker/MSI and Script<br> - Microsoft-Windows-AppLocker/EXE and DLL<br> - Microsoft-Windows-AppLocker/Packaged app-Deployment<br> - Microsoft-Windows-AppLocker/Packaged app-Execution |
| windows | product: windows<br>service: appmodel-runtime                           | Channel: Microsoft-Windows-AppModel-Runtime/Admin                                                                                                                                                                          |
| windows | product: windows<br>service: appxdeployment-server                      | Channel: Microsoft-Windows-AppXDeploymentServer/Operational                                                                                                                                                                |
| windows | product: windows<br>service: appxpackaging-om                           | Channel: Microsoft-Windows-AppxPackaging/Operational                                                                                                                                                                       |
| windows | product: windows<br>service: bitlocker                                  | Channel: Microsoft-Windows-BitLocker/BitLocker Management                                                                                                                                                                  |
| windows | product: windows<br>service: bits-client                                | Channel: Microsoft-Windows-Bits-Client/Operational                                                                                                                                                                         |
| windows | product: windows<br>service: capi2                                      | Channel: Microsoft-Windows-CAPI2/Operational                                                                                                                                                                               |
| windows | product: windows<br>service: certificateservicesclient-lifecycle-system | Channel: Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational                                                                                                                                          |
| windows | product: windows<br>service: codeintegrity-operational                  | Channel: Microsoft-Windows-CodeIntegrity/Operational                                                                                                                                                                       |
| windows | product: windows<br>service: dhcp                                       | Channel: Microsoft-Windows-DHCP-Server/Operational                                                                                                                                                                         |
| windows | product: windows<br>service: diagnosis-scripted                         | Channel: Microsoft-Windows-Diagnosis-Scripted/Operational                                                                                                                                                                  |
| windows | product: windows<br>service: dns-client                                 | Channel: Microsoft-Windows-DNS Client Events/Operational                                                                                                                                                                   |
| windows | product: windows<br>service: dns-server                                 | Channel: DNS Server                                                                                                                                                                                                        |
| windows | product: windows<br>service: dns-server-analytic                        | Channel: Microsoft-Windows-DNS-Server/Analytical                                                                                                                                                                           |
| windows | product: windows<br>service: dns-server-audit                           | Channel: Microsoft-Windows-DNS-Server/Audit                                                                                                                                                                                |
| windows | product: windows<br>service: driver-framework                           | Channel: Microsoft-Windows-DriverFrameworks-UserMode/Operational                                                                                                                                                           |
| windows | product: windows<br>service: firewall-as                                | Channel: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall                                                                                                                                                |
| windows | product: windows<br>service: hyper-v-worker                             | Channel: Microsoft-Windows-Hyper-V-Worker                                                                                                                                                                                  |
| windows | product: windows<br>service: iis-configuration                          | Channel: Microsoft-IIS-Configuration/Operational                                                                                                                                                                           |
| windows | product: windows<br>service: kernel-event-tracing                       | Channel: Microsoft-Windows-Kernel-EventTracing                                                                                                                                                                             |
| windows | product: windows<br>service: kernel-shimengine                          | Channel:<br> - Microsoft-Windows-Kernel-ShimEngine/Operational<br> - WinEventLog:Microsoft-Windows-Kernel-ShimEngine/Diagnostic                                                                                            |
| windows | product: windows<br>service: ldap                                       | Channel: Microsoft-Windows-LDAP-Client/Debug                                                                                                                                                                               |
| windows | product: windows<br>service: lsa-server                                 | Channel: Microsoft-Windows-LSA/Operational                                                                                                                                                                                 |
| windows | product: windows<br>service: msexchange-management                      | Channel: MSExchange Management                                                                                                                                                                                             |
| windows | product: windows<br>service: ntfs                                       | Channel: Microsoft-Windows-Ntfs/Operational                                                                                                                                                                                |
| windows | product: windows<br>service: ntlm                                       | Channel: Microsoft-Windows-NTLM/Operational                                                                                                                                                                                |
| windows | product: windows<br>service: openssh                                    | Channel: OpenSSH/Operational                                                                                                                                                                                               |
| windows | product: windows<br>service: powershell                                 | Channel: Microsoft-Windows-PowerShell/Operational                                                                                                                                                                          |
| windows | product: windows<br>service: powershell-classic                         | Channel: Windows PowerShell                                                                                                                                                                                                |
| windows | product: windows<br>service: printservice-admin                         | Channel: Microsoft-Windows-PrintService/Admin                                                                                                                                                                              |
| windows | product: windows<br>service: printservice-operational                   | Channel: Microsoft-Windows-PrintService/Operational                                                                                                                                                                        |
| windows | product: windows<br>service: security                                   | Channel: Security                                                                                                                                                                                                          |
| windows | product: windows<br>service: security-mitigations                       | Channel:<br> - Microsoft-Windows-Security-Mitigations/Kernel Mode<br> - Microsoft-Windows-Security-Mitigations/User Mode                                                                                                   |
| windows | product: windows<br>service: sense                                      | Channel: Microsoft-Windows-SENSE/Operational                                                                                                                                                                               |
| windows | product: windows<br>service: servicebus-client                          | Channel: <br> - Microsoft-ServiceBus-Client/Operational<br> - Microsoft-ServiceBus-Client/Admin                                                                                                                            |
| windows | product: windows<br>service: shell-core                                 | Channel: Microsoft-Windows-Shell-Core/Operational                                                                                                                                                                          |
| windows | product: windows<br>service: smbclient-security                         | Channel: Microsoft-Windows-SmbClient/Security                                                                                                                                                                              |
| windows | product: windows<br>service: sysmon                                     | Channel: Microsoft-Windows-Sysmon/Operational                                                                                                                                                                              |
| windows | product: windows<br>service: system                                     | Channel: System                                                                                                                                                                                                            |
| windows | product: windows<br>service: taskscheduler                              | Channel: Microsoft-Windows-TaskScheduler/Operational                                                                                                                                                                       |
| windows | product: windows<br>service: terminalservices-localsessionmanager       | Channel: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational                                                                                                                                                |
| windows | product: windows<br>service: vhdmp                                      | Channel: Microsoft-Windows-VHDMP/Operational                                                                                                                                                                               |
| windows | product: windows<br>service: windefend                                  | Channel: Microsoft-Windows-Windows Defender/Operational                                                                                                                                                                    |
| windows | product: windows<br>service: wmi                                        | Channel: Microsoft-Windows-WMI-Activity/Operational                                                                                                                                                                        |

## Network Events

Network events can be defined with the generic logsource category *network*.

The event scope can be further restricted with *service*.

The most common values should follow the rule : "lower case letters, spaces replaces with underscores".

| Product | Logsource                                | Description                    |
| ------- | ---------------------------------------- | ------------------------------ |
|         | category: network<br>service: connection | networks connection in general |
|         | category: network<br>service: dns        | DNS queries in general         |

## Fields

### Generic

#### Process Creation Events

Process creation events can be defined with the generic log source category *process_creation*. The event scope can be further restricted with *product*. Example for a process creation event log source restricted to Windows:

```yml
category: process_creation
product: windows
```

The field names follow the field names used in [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) events:

| Field Name        | Example Value                                                                             | Comment |
| ----------------- | ----------------------------------------------------------------------------------------- | ------- |
| UtcTime           | 2019-03-02 08:51:00.008                                                                   |         |
| ProcessGuid       | {c1b49677-43f4-5c7a-0000-0010d3dd8044}                                                    |         |
| ProcessId         | 1028                                                                                      |         |
| Image             | C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe                                 |         |
| FileVersion       | 1.3.28.13                                                                                 |         |
| Description       | Google Installer                                                                          |         |
| Product           | Google Update                                                                             |         |
| Company           | Google Inc.                                                                               |         |
| CommandLine       | "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe" /ua /installsource scheduler  |         |
| CurrentDirectory  | C:\\Windows\\system32\|                                                                   |         |
| User              | NT AUTHORITY\\SYSTEM                                                                      |         |
| LogonGuid         | {c1b49677-3fb9-5c09-0000-0020e7030000}                                                    |         |
| LogonId           | 0x3e7                                                                                     |         |
| TerminalSessionId | 0                                                                                         |         |
| IntegrityLevel    | System                                                                                    |         |
| imphash           | E96A73C7BF33A464C510EDE582318BF2                                                          |         |
| md5               | CCF1D1573F175299ADE01C07791A6541                                                          |         |
| sha1              | 0AE1F9071C5E8FE4A69D3F671937935D242D8A6C                                                  |         |
| sha256            | 68A15A34C2E28B9B521A240B948634617D72AD619E3950BC6DC769E60A0C3CF2                          |         |
| ParentProcessGuid | {c1b49677-6b43-5c78-0000-00107fb77544}                                                    |         |
| ParentProcessId   | 1724                                                                                      |         |
| ParentImage       | C:\\Windows\\System32\\taskeng.exe                                                        |         |
| ParentCommandLine | taskeng.exe {88F94E5C-5DC3-4606-AEFA-BDCA976D6113} S-1-5-18:NT AUTHORITY\\System:Service: |         |

#### Other Generic Rule Categories

We align our field names to the field names that [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) uses.
You can find all possible field values in the [Sysmon Community Guide](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/Sysmon.md) and on [UltimateWindowsSecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx).

### Specific

- `product: windows`: Windows Operating System logs. The naming of Windows Eventlog attributes is used in Sigma rules.
  - `service: security`: Windows Security Event Log. Some may be covered by [generic log sources](#generic).
  - `service: system`: Windows System Event Log
  - `service: sysmon`: Event Logs created by Sysmon. Some may be covered by [generic log sources](#generic).
  - `service: taskscheduler`
  - `service: wmi`
  - `service: application`
  - `service: dns-server`
  - `service: driver-framework`
  - `service: powershell`
  - `service: powershell-classic`
- `product: linux`: Linux log files
  - `service: auth`: Linux authentication logs. Usually */var/log/auth.log*.
  - `service: auditd`: Linux audit logs
  - `service: clamav`: ClamAV logs
- `product: macos`: macOS Operating System logs
  - `service: endpointsecurity`: Apple Endpoint Security Framework (ESF) events, as `eslogger` or an endpoint agent reports them. The service is optional with the [macOS categories](#macos-folder). See [Apple ESF Documentation](https://developer.apple.com/documentation/endpointsecurity).
- `product: apache`: Apache httpd logs
  - `service: access`: Access logs
  - `service: error`: Error logs
- `category: proxy`
  - Field Name according to [W3C Extended Log File Format](https://www.w3.org/TR/WD-logfile.html). Additional W3 examples can be found from [Microsoft](https://docs.microsoft.com/en-us/windows/win32/http/w3c-logging).
  - Field names:
    - `c-uri`: URL requested by client
    - `c-uri-extension`: Extension of the URL. Commonly is the requested extension of a file name
    - `c-uri-query`: Path component of requested URL
    - `c-uri-stem`: Stem of the requested URL
    - `c-useragent`: the clients user agent.
    - `cs-bytes`: Number of bytes sent from the server
    - `cs-cookie`: Cookie headers sent from client to server.
    - `cs-host`: Host header send from client to server
    - `cs-method`: HTTP request method
    - `r-dns`: The Domain requested. Additionally is referred to as the Host header or URL Domain. Recommend to use `cs-host` instead of this field
    - `cs-referrer`: The referring link or site
    - `cs-version`: The HTTP protocol version that the client used
    - `sc-bytes`: Number of bytes sent from the client
    - `sc-status`: The HTTP status code
    - `src_ip`: The IP address of the client that made the request
    - `dst_ip`: The IP address of the server
- `category: firewall`
  - Field Names:
    - `src_ip`, `src_port`, `dst_ip`, `dst_port`, `username`
- `category: dns`
- `category: webserver`
  - `date`: The date that the activity occurred.
  - `time`: The time that the activity occurred.
  - `c-ip`:The IP address of the client that accessed your server.
  - `cs-username`: The name of the authenticated user who accessed your server. This does not include anonymous users, who are represented by a hyphen (-).
  - `s-sitename`: The Internet service and instance number that was accessed by a client.
  - `s-computername`: The name of the server on which the log entry was generated.
  - `s-ip`: The IP address of the server on which the log entry was generated.
  - `s-port`: The port number the client is connected to.
  - `cs-method`: The action the client was trying to perform (for example, a GET method).
  - `cs-uri-stem`: The resource accessed; for example, Default.htm.
  - `cs-uri-query`: The query, if any, the client was trying to perform.
  - `sc-status`: The status of the action, in HTTP or FTP terms.
  - `c-win32-status`: The status of the action, in terms used by Microsoft Windows®.
  - `sc-bytes`: The number of bytes sent by the server.
  - `cs-bytes`: The number of bytes received by the server.
  - `time-taken`: The duration of time, in milliseconds, that the action consumed.
  - `cs-version`: The protocol (HTTP, FTP) version used by the client. For HTTP this will be either HTTP 1.0 or HTTP 1.1.
  - `cs-host`: Displays the content of the host header.
  - `cs-user-agent`: The browser used on the client.
  - `cs-cookie`: The content of the cookie sent or received, if any.
  - `cs-referer`: The previous site visited by the user. This site provided a link to the current site.
- `product: antivirus`
  - Field Names:
    - `Filename`: the name and path of the source threat file
    - `Signature`: name of the threat like "EICAR-Test-File"
    - `Action`: action take by the antivirus like "delete"

### macOS Endpoint Security Framework (ESF)

The following fields are used with the [macOS categories](#macos-folder) (`product: macos`, optional `service: endpointsecurity`). "All" means every macOS ESF category. Generic `process_creation` fields that are not listed here, such as `CurrentDirectory`, are not documented for macOS yet.

Unless noted, a field describes the process that caused the event. In the categories that have `InstigatorImage` (`authentication`, `background_task`, `configuration_profile`, `tcc_modification` and `user_account_change`), the process fields describe the daemon that reports the event, such as `opendirectoryd`, `mdmclient`, `tccd` or `backgroundtaskmanagementd`, not the process that requested it; `InstigatorImage` is the requesting process. In `process_creation`, `Image`, `CommandLine`, `User`, `UserId` and the code signature fields describe the new process (the `exec` target).

#### Process Fields

| Field Name      | Categories                                                                                            | Description                                                                                                                                                                                                                  | Example                                 |
| --------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| Image           | All                                                                                                   | Executable path                                                                                                                                                                                                              | /usr/bin/curl                           |
| CommandLine     | process_creation                                                                                      | Command line of the new process                                                                                                                                                                                              | curl -o /tmp/file https://example.com/f |
| ParentImage     | process_creation                                                                                      | Parent process executable. With `eslogger`, the process image before `exec` (the event's process before the new image), so it can differ from the process `ParentProcessId` names; in Elastic Defend events, the real parent | /bin/zsh                                |
| ProcessId       | All                                                                                                   | Process ID                                                                                                                                                                                                                   | 12345                                   |
| ParentProcessId | All                                                                                                   | Parent process ID                                                                                                                                                                                                            | 1234                                    |
| User            | All                                                                                                   | Effective user name                                                                                                                                                                                                          | admin                                   |
| UserId          | All                                                                                                   | Effective user ID (euid)                                                                                                                                                                                                     | 501                                     |
| InstigatorImage | authentication<br>background_task<br>configuration_profile<br>tcc_modification<br>user_account_change | Executable of the process that requested the event. In `authentication`, set for Open Directory authentications                                                                                                              | /usr/libexec/smd                        |

#### Code Signature Fields

In `driver_load`, these fields describe the process that loaded the kernel extension, not the extension.

| Field Name | Categories | Description                                                                                                                                                                                                                                                                                                  | Example          |
| ---------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------- |
| SigningID  | All        | Code signing identifier                                                                                                                                                                                                                                                                                      | com.apple.Safari |
| TeamID     | All        | Apple Developer Team ID. Empty for Apple platform binaries and ad-hoc signed code                                                                                                                                                                                                                            | ABCDE12345       |
| Signed     | All        | The binary has a code signature, including an ad-hoc signature (boolean). It doesn't mean the signature is trusted: on Apple silicon, native code must be signed, at least ad hoc, to run. Only set by sources that report it, such as Elastic Defend: `eslogger` reports code signing flags, not this value | true             |
| Trusted    | All        | macOS evaluated the signature and trusts it (boolean). Only set by sources that evaluate trust, such as Elastic Defend: `eslogger` reports code signing flags, not a trust result                                                                                                                            | false            |

#### File Fields

| Field Name        | Categories                                                                                                          | Description                                                                                                                                                                                                                                             | Example                                  |
| ----------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| TargetFilename    | file_access<br>file_attribute_change<br>file_delete<br>file_event<br>file_rename<br>gatekeeper_override<br>xprotect | Path of the file. In `file_rename`, and for renames in `file_event`, the new path. In `xprotect`, the detected or remediated path; in `gatekeeper_override`, the file the user allowed (both from `ESMessage.h`, not yet observed in `eslogger` output) | /Library/LaunchDaemons/com.example.plist |
| SourceFilename    | file_event<br>file_rename                                                                                           | Path before the rename. In `file_event`, set for renames only                                                                                                                                                                                           | /tmp/com.example.plist                   |
| TargetDirectory   | file_event<br>file_rename                                                                                           | Directory the file is created or renamed into. Only set when ESF reports a new path, which is rare for creates                                                                                                                                          | /Library/LaunchDaemons                   |
| ExtendedAttribute | file_attribute_change                                                                                               | Name of the extended attribute set or deleted. `setextattr` and `deleteextattr` only                                                                                                                                                                    | com.apple.quarantine                     |

#### Process Access and Signal Fields

| Field Name   | Categories                               | Description                                                                                                                                                                                                                         | Example                                          |
| ------------ | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| TargetImage  | process_access<br>process_signal<br>sudo | Executable of the target process. In `sudo`, the command `sudo` runs (its resolved path, without arguments) or the shell `su` starts. In `process_access`, `get_task` only; not yet available for `trace` or `create_remote_thread` | /Applications/Example.app/Contents/MacOS/Example |
| SignalNumber | process_signal                           | Signal number                                                                                                                                                                                                                       | 9                                                |

#### Privilege, Memory, XPC and Kernel Extension Fields

| Field Name       | Categories               | Description                                                                                    | Example                                          |
| ---------------- | ------------------------ | ---------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| TargetUserId     | privilege_change<br>sudo | User ID passed to `setuid`; not set for `seteuid` or `setreuid`. In `sudo`, the run-as user ID | 0                                                |
| TargetGroupId    | privilege_change         | Group ID passed to `setgid`. Not set for `setegid` or `setregid`                               | 0                                                |
| MemoryProtection | memory_protection        | New protection as a `PROT_*` bitmask: 1 read, 2 write, 4 execute                               | 7                                                |
| XpcServiceName   | xpc_connection           | XPC service name                                                                               | com.apple.backgroundtaskmanagement.notifications |
| KextIdentifier   | driver_load              | Kernel extension bundle identifier                                                             | com.example.driver                               |

#### TCC and Background Task Fields

| Field Name    | Categories       | Description                                                                                        | Example                                                |
| ------------- | ---------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| TccService    | tcc_modification | TCC service, without the `kTCCService` prefix                                                      | SystemPolicyAllFiles                                   |
| TccIdentity   | tcc_modification | Bundle identifier or path of the client whose permission changed                                   | com.example.app                                        |
| TccRight      | tcc_modification | Authorization right, as the integer ESF reports                                                    | 2                                                      |
| TccReason     | tcc_modification | Reason for the change, as the integer ESF reports                                                  | 3                                                      |
| BtmItemType   | background_task  | Item type, as the integer ESF reports (4 is a launch daemon). Not yet for `btm_launch_item_remove` | 4                                                      |
| BtmItemUrl    | background_task  | URL of the item. Not yet for `btm_launch_item_remove`                                              | file:///Library/LaunchDaemons/com.example.daemon.plist |
| BtmExecutable | background_task  | Executable the item runs. `btm_launch_item_add` only                                               | /Library/Application Support/Example/daemon            |

#### Account, Authentication and Outcome Fields

| Field Name         | Categories                                                                  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Example             |
| ------------------ | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| SourceUser         | sudo                                                                        | User who ran `sudo` or `su`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | jsmith              |
| TargetUser         | authentication<br>screen_sharing<br>sudo<br>user_account_change             | Account the event acts on or authenticates as. In `sudo`, the run-as user. In `authentication`, the Open Directory record authenticated against (Open Directory only). In `screen_sharing`, the account used to authenticate the connection, not the user of the shared session; `screensharing_attach` only, and empty when no username was used. In `user_account_change`: the user in the user events and `od_modify_password`; the member in `od_group_add` and `od_group_remove`, which is a user name, a user UUID or a group UUID; the record name in the `od_attribute_*` events, which is a user or group name | root                |
| TargetGroup        | user_account_change                                                         | Group the event acts on                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | admin               |
| Success            | authentication<br>screen_sharing<br>sudo<br>user_account_change<br>xprotect | The operation succeeded, `true` or `false`. In `user_account_change`, an Open Directory error code of 0. In `screen_sharing` and `xprotect`, set for `screensharing_attach` and `xp_malware_remediated` (the latter from `ESMessage.h`, not yet observed in `eslogger` output)                                                                                                                                                                                                                                                                                                                                          | false               |
| FailureReason      | sudo                                                                        | Why `sudo` or `su` refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | user NOT in sudoers |
| AuthenticationType | authentication                                                              | Authentication method, as the integer ESF reports: 0 Open Directory, 1 Touch ID, 2 token, 3 Auto Unlock                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 0                   |

#### Screen Sharing Fields

| Field Name      | Categories     | Description                                                                       | Example            |
| --------------- | -------------- | --------------------------------------------------------------------------------- | ------------------ |
| SourceAddress   | screen_sharing | Address the connection comes from                                                 | 192.0.2.10         |
| ViewerAppleID   | screen_sharing | Apple ID of the viewer, when one is used                                          | viewer@example.com |
| ExistingSession | screen_sharing | A user session already existed on the host (boolean). `screensharing_attach` only | true               |

#### Configuration Profile and Open Directory Fields

`profile_remove`, and the `od_*` events other than `od_create_user`, `od_delete_user`, `od_modify_password`, `od_group_add` and `od_attribute_value_add`, use the same field paths as the observed events of their family, as Apple's `ESMessage.h` defines them. The exception is `od_attribute_set`, whose values are an array (`attribute_values`) rather than one value.

| Field Name           | Categories            | Description                                                                                                                                     | Example                                    |
| -------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| ProfileIdentifier    | configuration_profile | Profile identifier                                                                                                                              | com.example.settings                       |
| ProfileDisplayName   | configuration_profile | Profile display name                                                                                                                            | Example Settings                           |
| ProfileInstallSource | configuration_profile | How the profile was installed, as the integer ESF reports: 0 managed, 1 installed manually                                                      | 1                                          |
| ProfileScope         | configuration_profile | Profile scope                                                                                                                                   | system                                     |
| OdAttributeName      | user_account_change   | Name of the attribute added, removed or set (`od_attribute_*` events)                                                                           | dsAttrTypeStandard:AuthenticationAuthority |
| OdAttributeValue     | user_account_change   | Attribute value. For `od_attribute_set`, ESF reports an array of values, which a source has to flatten, for example by joining them with spaces | ;DisabledTags;SecureToken                  |

#### XProtect and Gatekeeper Fields

These fields, and `TargetFilename` for `xprotect` and `gatekeeper_override` and `Success` for `xprotect`, follow Apple's `ESMessage.h`. They have not yet been observed in `eslogger` output.

| Field Name                | Categories          | Description                                                                                                                                            | Example                                                          |
| ------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| MalwareIdentifier         | xprotect            | Malware identifier XProtect reports                                                                                                                    | ExampleMalware.A                                                 |
| MalwareIncidentIdentifier | xprotect            | Identifier that links a detection to its remediations                                                                                                  | 00000000-0000-0000-0000-0000000000A1                             |
| RemediationAction         | xprotect            | Remediation action taken. `xp_malware_remediated` only                                                                                                 | path_delete                                                      |
| FileSha256                | gatekeeper_override | SHA-256 of the file. ESF provides it only for files under 100 MB, so it can be absent. By convention lowercase hex; `eslogger` reports it in uppercase | 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c |
| FileSigningID             | gatekeeper_override | Code signing identifier of the file. Absent when the file is unsigned                                                                                  | com.example.app                                                  |
| FileTeamID                | gatekeeper_override | Apple Developer Team ID of the file. Absent when the file is unsigned or has none                                                                      | ABCDE12345                                                       |

### Network category

- `service: connection`
  - event.duration:Connection duration in seconds
  - network.type: Network layer type (e.g., ipv4, ipv6, ipsec)
  - network.transport: Transport layer protocol (e.g., tcp, udp)
  - network.protocol: Application layer protocol (e.g., http, dns, ssh)
  - source.ip: Source IP address
  - source.port: Source port number
  - destination.ip:Destination IP address
  - destination.port: Destination port number
  - source.packets: Number of packets
  - destination.packets: Number of packets
  - source.bytes: Number of bytes
  - destination.bytes: Number of bytes
  - network.community_id: Community ID hash
  - network.state: State of the connection
  - network.history: History of the connection
- `service: dns`
  - source.ip : Source IP address
  - source.port: Source port number
  - destination.ip: Destination IP address
  - destination.port: Destination port number
  - network.community_id: Community ID hash
  - dns.id: DNS transaction identifier
  - dns.question.name: DNS question name
  - dns.question.type: DNS question type
  - dns.question.class: DNS question class
  - dns.answers.name: DNS answer name
  - dns.answers.type: DNS answer type
  - dns.answers.class: DNS answer class
  - dns.answers.data: DNS answer data
  - dns.answers.ttl: DNS answer TTL
  - dns.header.flags: DNS header flags
  - dns.response.code: DNS response code

## History

- 2026-11-11 Taxonomy Appendix v2.1.1
  - Add macOS Endpoint Security Framework (ESF) as the source of the macOS categories, with an optional service:
    - `product: macos`, `service: endpointsecurity`
  - Add macOS categories, each mapped to `eslogger` event names:
    - `authentication`, `background_task`, `configuration_profile`, `create_remote_thread`, `driver_load`, `file_access`, `file_attribute_change`, `file_delete`, `file_rename`, `gatekeeper_override`, `memory_protection`, `privilege_change`, `process_access`, `process_signal`, `screen_sharing`, `sudo`, `tcc_modification`, `user_account_change`, `xpc_connection`, `xprotect`
  - Define `file_event` on macOS as file creation, including the destination of a rename
  - Add macOS ESF fields, including `Signed` and `Trusted`
- 2025-08-02 Specification v2.1.0
  - Add generic network category:
    - `service: connection`
    - `service: dns`
- 2024-11-01 Taxonomy Appendix v v2.0.2
  - Add new windows services:
    - `service: iis-configuration`
- 2024-08-11 Taxonomy Appendix v v2.0.1
  - Restructure the document for a better reading experience
- 2024-08-08 Taxonomy Appendix v v2.0.0
  - Fix the following windows services:
    - Change `ldap_debug` to `ldap`
  - Add new windows services:
    - `service: application-experience`
    - `service: capi2`
    - `service: certificateservicesclient-lifecycle-system`
    - `service: hyper-v-worker`
    - `service: kernel-event-tracing`
    - `service: kernel-shimengine`
    - `service: ntfs`
    - `service: sense`
    - `service: servicebus-client`
- 2023-01-21 Taxonomy Appendix v1.3.5
  - Add new product and its related service:
    - `product: github`
    - `service: audit`
- 2023-01-18 Taxonomy Appendix v1.3.4
  - Add the following new windows services:
    - `service: appxdeployment-server`
    - `service: lsa-server`
    - `service: appxpackaging-om`
    - `service: dns-client`
    - `service: appmodel-runtime`
    - `service: vhdmp`
  - Add new cisco services:
    - `service: bgp`
    - `service: ldp`
  - Add new huawei `service: bgp`
  - Add new juniper `service: bgp`
  - Add missing category folder
  - Add missing product folder
  - Add description for a special case when using only the `product` logsource
- 2023-01-03 Taxonomy Appendix v1.3.3
  - Add windows service dns-server-analytic and bitlocker
  - Add all the W3C fields names to the category `webserver`
  - Update linux `file_create` category to `file_event`
- 2022-12-19 Taxonomy Appendix v1.3.2
  - Minor tweak and updates to the syntax and text
- 2022-11-13 Taxonomy Appendix v1.3.1
  - Add missing service shell-core
- 2022-11-01 Taxonomy Appendix v1.3.0
  - Add missing windows services
- 2022-10-25 Taxonomy Appendix v1.2.0
  - Order the windows logs
- 2022-10-19 Taxonomy Appendix v1.1.0
  - Fix links and spelling
- 2022-09-18 Taxonomy v1.0.0
  - Initial release
