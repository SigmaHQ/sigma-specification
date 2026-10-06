# Sigma Taxonomy

The following document defines the log sources and the field names that are allowed to be used in SIGMA rules that are shared on the official SigmaHQ repository.

- Version 2.1.0
- Release date 2025-08-02

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Log Sources](#log-sources)
  - [Application Folder](#application-folder)
  - [Category Folder](#category-folder)
  - [Cloud Folder](#cloud-folder)
  - [Identity Folder](#identity-folder)
  - [Linux Folder](#linux-folder)
  - [Macos Folder](#macos-folder)
  - [Network Folder](#network-folder)
  - [Web Folder](#web-folder)
  - [Windows Folder](#windows-folder)
- [Network Category](#network-category)
- [History](#history)

<!-- mdformat-toc end -->

For example in pySigma for ocsf taxonomy you can use the [pySigma-pipeline-ocsf pipeline](https://github.com/SigmaHQ/pySigma-pipeline-ocsf)

## Log Sources

Every log source is documented in its own page of the [`appendix-taxonomy`](appendix-taxonomy/) directory, named after the attributes of its `logsource` block. The pages are listed here by the folder of the rules repository that uses them.

### Application Folder

The *application* folder contains the rules that are intended for application security monitoring. They set the *category* attribute of the logsource to `application`, which lets a pipeline write a conversion configuration that doesn't depend on the application technology, and the *product* attribute to the name of the technology. Application logs are often ingested as raw text, the rules of this folder are keyword rules that don't match on specific fields.

| Log Source                                                   | Page                                                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| `product: bitbucket, service: audit`                         | [bitbucket_audit.md](appendix-taxonomy/bitbucket_audit.md)                     |
| `category: application, product: django`                     | [django_application.md](appendix-taxonomy/django_application.md)               |
| `product: github, service: audit`                            | [github_audit.md](appendix-taxonomy/github_audit.md)                           |
| `category: application, product: jvm`                        | [jvm_application.md](appendix-taxonomy/jvm_application.md)                     |
| `category: application, product: kubernetes, service: audit` | [kubernetes_application.md](appendix-taxonomy/kubernetes_application.md)       |
| `product: kubernetes, service: audit`                        | [kubernetes_audit.md](appendix-taxonomy/kubernetes_audit.md)                   |
| `category: application, product: nodejs`                     | [nodejs_application.md](appendix-taxonomy/nodejs_application.md)               |
| `category: application, product: opencanary`                 | [opencanary_application.md](appendix-taxonomy/opencanary_application.md)       |
| `category: application, product: python`                     | [python_application.md](appendix-taxonomy/python_application.md)               |
| `category: application, product: rpc_firewall`               | [rpc_firewall_application.md](appendix-taxonomy/rpc_firewall_application.md)   |
| `category: application, product: ruby_on_rails`              | [ruby_on_rails_application.md](appendix-taxonomy/ruby_on_rails_application.md) |
| `category: application, product: spring`                     | [spring_application.md](appendix-taxonomy/spring_application.md)               |
| `category: application, product: sql`                        | [sql_application.md](appendix-taxonomy/sql_application.md)                     |
| `category: application, product: velocity`                   | [velocity_application.md](appendix-taxonomy/velocity_application.md)           |

### Category Folder

The *category* folder contains the rules that don't belong to a product, they only set the *category* attribute of the logsource.

| Log Source            | Page                                           |
| --------------------- | ---------------------------------------------- |
| `category: antivirus` | [antivirus.md](appendix-taxonomy/antivirus.md) |
| `category: database`  | [database.md](appendix-taxonomy/database.md)   |

### Cloud Folder

The *cloud* folder contains the rules that monitor the audit logs of the cloud services and of the SaaS platforms, they set the *product* attribute to the name of the service and the *service* attribute to the log of the service.

| Log Source                                      | Page                                                                             |
| ----------------------------------------------- | -------------------------------------------------------------------------------- |
| `product: aws, service: cloudtrail`             | [aws_cloudtrail.md](appendix-taxonomy/aws_cloudtrail.md)                         |
| `product: azure, service: activitylogs`         | [azure_activitylogs.md](appendix-taxonomy/azure_activitylogs.md)                 |
| `product: azure, service: auditlogs`            | [azure_auditlogs.md](appendix-taxonomy/azure_auditlogs.md)                       |
| `product: azure, service: pim`                  | [azure_pim.md](appendix-taxonomy/azure_pim.md)                                   |
| `product: azure, service: riskdetection`        | [azure_riskdetection.md](appendix-taxonomy/azure_riskdetection.md)               |
| `product: azure, service: signinlogs`           | [azure_signinlogs.md](appendix-taxonomy/azure_signinlogs.md)                     |
| `product: gcp, service: gcp.audit`              | [gcp_gcp.audit.md](appendix-taxonomy/gcp_gcp.audit.md)                           |
| `product: gcp, service: google_workspace.admin` | [gcp_google_workspace.admin.md](appendix-taxonomy/gcp_google_workspace.admin.md) |
| `product: gcp, service: google_workspace.login` | [gcp_google_workspace.login.md](appendix-taxonomy/gcp_google_workspace.login.md) |
| `product: m365, service: audit`                 | [m365_audit.md](appendix-taxonomy/m365_audit.md)                                 |
| `product: m365, service: exchange`              | [m365_exchange.md](appendix-taxonomy/m365_exchange.md)                           |
| `product: m365, service: threat_detection`      | [m365_threat_detection.md](appendix-taxonomy/m365_threat_detection.md)           |
| `product: m365, service: threat_management`     | [m365_threat_management.md](appendix-taxonomy/m365_threat_management.md)         |

### Identity Folder

The *identity* folder contains the rules that monitor the audit logs of the identity providers, they set the *product* attribute to the name of the provider and the *service* attribute to the log of the provider.

| Log Source                                    | Page                                                                         |
| --------------------------------------------- | ---------------------------------------------------------------------------- |
| `product: cisco, service: duo`                | [cisco_duo.md](appendix-taxonomy/cisco_duo.md)                               |
| `product: okta, service: okta`                | [okta_okta.md](appendix-taxonomy/okta_okta.md)                               |
| `product: onelogin, service: onelogin.events` | [onelogin_onelogin.events.md](appendix-taxonomy/onelogin_onelogin.events.md) |

### Linux Folder

The *linux* folder contains the rules that monitor the logs of the Linux hosts. They set the *product* attribute to `linux` and either the *category* attribute or the *service* attribute, depending on the log that is monitored.

| Log Source                                     | Page                                                                         |
| ---------------------------------------------- | ---------------------------------------------------------------------------- |
| `product: linux`                               | [linux.md](appendix-taxonomy/linux.md)                                       |
| `product: linux, service: auditd`              | [linux_auditd.md](appendix-taxonomy/linux_auditd.md)                         |
| `product: linux, service: auth`                | [linux_auth.md](appendix-taxonomy/linux_auth.md)                             |
| `product: linux, service: clamav`              | [linux_clamav.md](appendix-taxonomy/linux_clamav.md)                         |
| `product: linux, service: cron`                | [linux_cron.md](appendix-taxonomy/linux_cron.md)                             |
| `category: file_event, product: linux`         | [linux_file_event.md](appendix-taxonomy/linux_file_event.md)                 |
| `product: linux, service: guacamole`           | [linux_guacamole.md](appendix-taxonomy/linux_guacamole.md)                   |
| `category: network_connection, product: linux` | [linux_network_connection.md](appendix-taxonomy/linux_network_connection.md) |
| `category: process_creation, product: linux`   | [linux_process_creation.md](appendix-taxonomy/linux_process_creation.md)     |
| `product: linux, service: sshd`                | [linux_sshd.md](appendix-taxonomy/linux_sshd.md)                             |
| `product: linux, service: sudo`                | [linux_sudo.md](appendix-taxonomy/linux_sudo.md)                             |
| `product: linux, service: syslog`              | [linux_syslog.md](appendix-taxonomy/linux_syslog.md)                         |
| `product: linux, service: vsftpd`              | [linux_vsftpd.md](appendix-taxonomy/linux_vsftpd.md)                         |

### Macos Folder

The *macos* folder contains the rules that monitor the logs of the macOS hosts, they set the *product* attribute to `macos` and either the *category* attribute or the *service* attribute, depending on the log that is monitored.

| Log Source                                   | Page                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------ |
| `product: macos, service: endpointsecurity`  | [macos_endpointsecurity.md](appendix-taxonomy/macos_endpointsecurity.md) |
| `category: file_event, product: macos`       | [macos_file_event.md](appendix-taxonomy/macos_file_event.md)             |
| `category: process_creation, product: macos` | [macos_process_creation.md](appendix-taxonomy/macos_process_creation.md) |

### Network Folder

The *network* folder contains the rules that monitor the network devices and the network traffic. The products set the *product* and the *service* attributes, the generic network logs only set the *category* attribute.

| Log Source                           | Page                                                       |
| ------------------------------------ | ---------------------------------------------------------- |
| `product: cisco, service: aaa`       | [cisco_aaa.md](appendix-taxonomy/cisco_aaa.md)             |
| `product: cisco, service: bgp`       | [cisco_bgp.md](appendix-taxonomy/cisco_bgp.md)             |
| `product: cisco, service: ldp`       | [cisco_ldp.md](appendix-taxonomy/cisco_ldp.md)             |
| `category: dns`                      | [dns.md](appendix-taxonomy/dns.md)                         |
| `category: firewall`                 | [firewall.md](appendix-taxonomy/firewall.md)               |
| `product: fortigate, service: event` | [fortigate_event.md](appendix-taxonomy/fortigate_event.md) |
| `product: huawei, service: bgp`      | [huawei_bgp.md](appendix-taxonomy/huawei_bgp.md)           |
| `product: huawei, service: ldp`      | [huawei_ldp.md](appendix-taxonomy/huawei_ldp.md)           |
| `product: juniper, service: bgp`     | [juniper_bgp.md](appendix-taxonomy/juniper_bgp.md)         |
| `product: juniper, service: ldp`     | [juniper_ldp.md](appendix-taxonomy/juniper_ldp.md)         |
| `product: zeek, service: dce_rpc`    | [zeek_dce_rpc.md](appendix-taxonomy/zeek_dce_rpc.md)       |
| `product: zeek, service: dns`        | [zeek_dns.md](appendix-taxonomy/zeek_dns.md)               |
| `product: zeek, service: http`       | [zeek_http.md](appendix-taxonomy/zeek_http.md)             |
| `product: zeek, service: kerberos`   | [zeek_kerberos.md](appendix-taxonomy/zeek_kerberos.md)     |
| `product: zeek, service: rdp`        | [zeek_rdp.md](appendix-taxonomy/zeek_rdp.md)               |
| `product: zeek, service: smb_files`  | [zeek_smb_files.md](appendix-taxonomy/zeek_smb_files.md)   |
| `product: zeek, service: x509`       | [zeek_x509.md](appendix-taxonomy/zeek_x509.md)             |

### Web Folder

The *web* folder contains the rules that monitor the web servers and the proxies. The rules that don't belong to a product set the *category* attribute to `proxy` or to `webserver`, the rules of a product set the *service* attribute to its name.

| Log Source             | Page                                               |
| ---------------------- | -------------------------------------------------- |
| `service: apache`      | [apache.md](appendix-taxonomy/apache.md)           |
| `product: modsecurity` | [modsecurity.md](appendix-taxonomy/modsecurity.md) |
| `service: nginx`       | [nginx.md](appendix-taxonomy/nginx.md)             |
| `category: proxy`      | [proxy.md](appendix-taxonomy/proxy.md)             |
| `category: webserver`  | [webserver.md](appendix-taxonomy/webserver.md)     |

### Windows Folder

The *windows* folder contains the rules that monitor the logs of the Windows hosts, they set the *product* attribute to `windows` and either the *category* attribute or the *service* attribute, depending on the log that is monitored.

| Log Source                                                              | Page                                                                                                                             |
| ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `product: windows`                                                      | [windows.md](appendix-taxonomy/windows.md)                                                                                       |
| `product: windows, service: application-experience`                     | [windows_application-experience.md](appendix-taxonomy/windows_application-experience.md)                                         |
| `product: windows, service: application`                                | [windows_application.md](appendix-taxonomy/windows_application.md)                                                               |
| `product: windows, service: applocker`                                  | [windows_applocker.md](appendix-taxonomy/windows_applocker.md)                                                                   |
| `product: windows, service: appmodel-runtime`                           | [windows_appmodel-runtime.md](appendix-taxonomy/windows_appmodel-runtime.md)                                                     |
| `product: windows, service: appxdeployment-server`                      | [windows_appxdeployment-server.md](appendix-taxonomy/windows_appxdeployment-server.md)                                           |
| `product: windows, service: appxpackaging-om`                           | [windows_appxpackaging-om.md](appendix-taxonomy/windows_appxpackaging-om.md)                                                     |
| `product: windows, service: bitlocker`                                  | [windows_bitlocker.md](appendix-taxonomy/windows_bitlocker.md)                                                                   |
| `product: windows, service: bits-client`                                | [windows_bits-client.md](appendix-taxonomy/windows_bits-client.md)                                                               |
| `product: windows, service: capi2`                                      | [windows_capi2.md](appendix-taxonomy/windows_capi2.md)                                                                           |
| `product: windows, service: certificateservicesclient-lifecycle-system` | [windows_certificateservicesclient-lifecycle-system.md](appendix-taxonomy/windows_certificateservicesclient-lifecycle-system.md) |
| `category: clipboard_capture, product: windows`                         | [windows_clipboard_capture.md](appendix-taxonomy/windows_clipboard_capture.md)                                                   |
| `product: windows, service: codeintegrity-operational`                  | [windows_codeintegrity-operational.md](appendix-taxonomy/windows_codeintegrity-operational.md)                                   |
| `category: create_remote_thread, product: windows`                      | [windows_create_remote_thread.md](appendix-taxonomy/windows_create_remote_thread.md)                                             |
| `category: create_stream_hash, product: windows`                        | [windows_create_stream_hash.md](appendix-taxonomy/windows_create_stream_hash.md)                                                 |
| `product: windows, service: dhcp`                                       | [windows_dhcp.md](appendix-taxonomy/windows_dhcp.md)                                                                             |
| `product: windows, service: diagnosis-scripted`                         | [windows_diagnosis-scripted.md](appendix-taxonomy/windows_diagnosis-scripted.md)                                                 |
| `product: windows, service: dns-client`                                 | [windows_dns-client.md](appendix-taxonomy/windows_dns-client.md)                                                                 |
| `product: windows, service: dns-server-analytic`                        | [windows_dns-server-analytic.md](appendix-taxonomy/windows_dns-server-analytic.md)                                               |
| `product: windows, service: dns-server-audit`                           | [windows_dns-server-audit.md](appendix-taxonomy/windows_dns-server-audit.md)                                                     |
| `product: windows, service: dns-server`                                 | [windows_dns-server.md](appendix-taxonomy/windows_dns-server.md)                                                                 |
| `category: dns_query, product: windows`                                 | [windows_dns_query.md](appendix-taxonomy/windows_dns_query.md)                                                                   |
| `product: windows, service: driver-framework`                           | [windows_driver-framework.md](appendix-taxonomy/windows_driver-framework.md)                                                     |
| `category: driver_load, product: windows`                               | [windows_driver_load.md](appendix-taxonomy/windows_driver_load.md)                                                               |
| `category: file_access, product: windows`                               | [windows_file_access.md](appendix-taxonomy/windows_file_access.md)                                                               |
| `category: file_block_executable, product: windows`                     | [windows_file_block_executable.md](appendix-taxonomy/windows_file_block_executable.md)                                           |
| `category: file_block_shredding, product: windows`                      | [windows_file_block_shredding.md](appendix-taxonomy/windows_file_block_shredding.md)                                             |
| `category: file_change, product: windows`                               | [windows_file_change.md](appendix-taxonomy/windows_file_change.md)                                                               |
| `category: file_delete, product: windows`                               | [windows_file_delete.md](appendix-taxonomy/windows_file_delete.md)                                                               |
| `category: file_delete_detected, product: windows`                      | [windows_file_delete_detected.md](appendix-taxonomy/windows_file_delete_detected.md)                                             |
| `category: file_event, product: windows`                                | [windows_file_event.md](appendix-taxonomy/windows_file_event.md)                                                                 |
| `category: file_executable_detected, product: windows`                  | [windows_file_executable_detected.md](appendix-taxonomy/windows_file_executable_detected.md)                                     |
| `category: file_rename, product: windows`                               | [windows_file_rename.md](appendix-taxonomy/windows_file_rename.md)                                                               |
| `product: windows, service: firewall-as`                                | [windows_firewall-as.md](appendix-taxonomy/windows_firewall-as.md)                                                               |
| `product: windows, service: hyper-v-worker`                             | [windows_hyper-v-worker.md](appendix-taxonomy/windows_hyper-v-worker.md)                                                         |
| `product: windows, service: iis-configuration`                          | [windows_iis-configuration.md](appendix-taxonomy/windows_iis-configuration.md)                                                   |
| `category: image_load, product: windows`                                | [windows_image_load.md](appendix-taxonomy/windows_image_load.md)                                                                 |
| `product: windows, service: kernel-event-tracing`                       | [windows_kernel-event-tracing.md](appendix-taxonomy/windows_kernel-event-tracing.md)                                             |
| `product: windows, service: kernel-shimengine`                          | [windows_kernel-shimengine.md](appendix-taxonomy/windows_kernel-shimengine.md)                                                   |
| `product: windows, service: ldap`                                       | [windows_ldap.md](appendix-taxonomy/windows_ldap.md)                                                                             |
| `product: windows, service: lsa-server`                                 | [windows_lsa-server.md](appendix-taxonomy/windows_lsa-server.md)                                                                 |
| `product: windows, service: microsoft-servicebus-client`                | [windows_microsoft-servicebus-client.md](appendix-taxonomy/windows_microsoft-servicebus-client.md)                               |
| `product: windows, service: msexchange-management`                      | [windows_msexchange-management.md](appendix-taxonomy/windows_msexchange-management.md)                                           |
| `category: network_connection, product: windows`                        | [windows_network_connection.md](appendix-taxonomy/windows_network_connection.md)                                                 |
| `product: windows, service: ntfs`                                       | [windows_ntfs.md](appendix-taxonomy/windows_ntfs.md)                                                                             |
| `product: windows, service: ntlm`                                       | [windows_ntlm.md](appendix-taxonomy/windows_ntlm.md)                                                                             |
| `product: windows, service: openssh`                                    | [windows_openssh.md](appendix-taxonomy/windows_openssh.md)                                                                       |
| `category: pipe_created, product: windows`                              | [windows_pipe_created.md](appendix-taxonomy/windows_pipe_created.md)                                                             |
| `product: windows, service: powershell-classic`                         | [windows_powershell-classic.md](appendix-taxonomy/windows_powershell-classic.md)                                                 |
| `product: windows, service: powershell`                                 | [windows_powershell.md](appendix-taxonomy/windows_powershell.md)                                                                 |
| `product: windows, service: printservice-admin`                         | [windows_printservice-admin.md](appendix-taxonomy/windows_printservice-admin.md)                                                 |
| `product: windows, service: printservice-operational`                   | [windows_printservice-operational.md](appendix-taxonomy/windows_printservice-operational.md)                                     |
| `category: process_access, product: windows`                            | [windows_process_access.md](appendix-taxonomy/windows_process_access.md)                                                         |
| `category: process_creation, product: windows`                          | [windows_process_creation.md](appendix-taxonomy/windows_process_creation.md)                                                     |
| `category: process_tampering, product: windows`                         | [windows_process_tampering.md](appendix-taxonomy/windows_process_tampering.md)                                                   |
| `category: process_termination, product: windows`                       | [windows_process_termination.md](appendix-taxonomy/windows_process_termination.md)                                               |
| `category: ps_classic_provider_start, product: windows`                 | [windows_ps_classic_provider_start.md](appendix-taxonomy/windows_ps_classic_provider_start.md)                                   |
| `category: ps_classic_script, product: windows`                         | [windows_ps_classic_script.md](appendix-taxonomy/windows_ps_classic_script.md)                                                   |
| `category: ps_classic_start, product: windows`                          | [windows_ps_classic_start.md](appendix-taxonomy/windows_ps_classic_start.md)                                                     |
| `category: ps_module, product: windows`                                 | [windows_ps_module.md](appendix-taxonomy/windows_ps_module.md)                                                                   |
| `category: ps_script, product: windows`                                 | [windows_ps_script.md](appendix-taxonomy/windows_ps_script.md)                                                                   |
| `category: raw_access_thread, product: windows`                         | [windows_raw_access_thread.md](appendix-taxonomy/windows_raw_access_thread.md)                                                   |
| `category: registry_add, product: windows`                              | [windows_registry_add.md](appendix-taxonomy/windows_registry_add.md)                                                             |
| `category: registry_delete, product: windows`                           | [windows_registry_delete.md](appendix-taxonomy/windows_registry_delete.md)                                                       |
| `category: registry_event, product: windows`                            | [windows_registry_event.md](appendix-taxonomy/windows_registry_event.md)                                                         |
| `category: registry_rename, product: windows`                           | [windows_registry_rename.md](appendix-taxonomy/windows_registry_rename.md)                                                       |
| `category: registry_set, product: windows`                              | [windows_registry_set.md](appendix-taxonomy/windows_registry_set.md)                                                             |
| `product: windows, service: security-mitigations`                       | [windows_security-mitigations.md](appendix-taxonomy/windows_security-mitigations.md)                                             |
| `product: windows, service: security`                                   | [windows_security.md](appendix-taxonomy/windows_security.md)                                                                     |
| `product: windows, service: sense`                                      | [windows_sense.md](appendix-taxonomy/windows_sense.md)                                                                           |
| `product: windows, service: servicebus-client`                          | [windows_servicebus-client.md](appendix-taxonomy/windows_servicebus-client.md)                                                   |
| `product: windows, service: shell-core`                                 | [windows_shell-core.md](appendix-taxonomy/windows_shell-core.md)                                                                 |
| `product: windows, service: smbclient-security`                         | [windows_smbclient-security.md](appendix-taxonomy/windows_smbclient-security.md)                                                 |
| `product: windows, service: smbserver-connectivity`                     | [windows_smbserver-connectivity.md](appendix-taxonomy/windows_smbserver-connectivity.md)                                         |
| `product: windows, service: sysmon`                                     | [windows_sysmon.md](appendix-taxonomy/windows_sysmon.md)                                                                         |
| `category: sysmon_error, product: windows`                              | [windows_sysmon_error.md](appendix-taxonomy/windows_sysmon_error.md)                                                             |
| `category: sysmon_status, product: windows`                             | [windows_sysmon_status.md](appendix-taxonomy/windows_sysmon_status.md)                                                           |
| `product: windows, service: system`                                     | [windows_system.md](appendix-taxonomy/windows_system.md)                                                                         |
| `product: windows, service: taskscheduler`                              | [windows_taskscheduler.md](appendix-taxonomy/windows_taskscheduler.md)                                                           |
| `product: windows, service: terminalservices-localsessionmanager`       | [windows_terminalservices-localsessionmanager.md](appendix-taxonomy/windows_terminalservices-localsessionmanager.md)             |
| `product: windows, service: vhdmp`                                      | [windows_vhdmp.md](appendix-taxonomy/windows_vhdmp.md)                                                                           |
| `product: windows, service: windefend`                                  | [windows_windefend.md](appendix-taxonomy/windows_windefend.md)                                                                   |
| `product: windows, service: wmi`                                        | [windows_wmi.md](appendix-taxonomy/windows_wmi.md)                                                                               |
| `category: wmi_event, product: windows`                                 | [windows_wmi_event.md](appendix-taxonomy/windows_wmi_event.md)                                                                   |

## Network Category

The generic network logs are documented with a page of their own, they set the *category* attribute to `network` and the *service* attribute to the kind of event that was observed. No rule of the repository uses them yet.

| Log Source                               | Page                                                             |
| ---------------------------------------- | ---------------------------------------------------------------- |
| `category: network, service: connection` | [network_connection.md](appendix-taxonomy/network_connection.md) |
| `category: network, service: dns`        | [network_dns.md](appendix-taxonomy/network_dns.md)               |

## History

- 2025-XX-XX Taxonomy Appendix v2.2.0

  - Split the appendix into one page per log source, in the `appendix-taxonomy` directory
  - Document `category: webserver` with the field names of the Microsoft HTTP Server API
  - Document `category: proxy` without the claim that it uses the W3C extended log file format
  - Document the fields that the Windows event sources write with [EVTX-ETW-Resources](https://github.com/nasbench/EVTX-ETW-Resources)
  - Add the log sources that the rules of the SigmaHQ repository use:
    - `product: linux`
    - `product: windows`
    - `category: application, product: jvm`
    - `category: application, product: kubernetes, service: audit`
    - `category: application, product: nodejs`
    - `category: application, product: opencanary`
    - `category: application, product: velocity`
    - `product: kubernetes, service: audit`
    - `product: fortigate, service: event`
    - `product: gcp, service: google_workspace.login`
    - `product: huawei, service: bgp`
    - `product: juniper, service: bgp`
    - `product: windows, service: microsoft-servicebus-client`
    - `product: windows, service: smbserver-connectivity`
    - `service: nginx`

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
