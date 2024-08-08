# SigmaHQ Filename Conventions <!-- omit in toc -->

This document describe a soft convention to name rule files. The following convention has been set to help with the management of the rules files repository and is not part of the SIGMA specification.

## Summary <!-- omit in toc -->

- [Product](#product)
- [Cloud](#cloud)
- [Category](#category)
- [Category without product](#category-without-product)
- [Service](#service)
  - [Linux](#linux)
  - [Windows](#windows)

## Product

| product    | Pattern        | example                                                 |
| ---------- | -------------- | ------------------------------------------------------- |
| modsec     | modsec_*       | modsec_mulitple_blocks.yml                              |

## Cloud

| product    | Pattern        | example                                                 |
| ---------- | -------------- | ------------------------------------------------------- |
| aws        | aws_*          | aws_cloudtrail_disable_logging.yml                      |
| azure      | azure_*        | azure_ad_bitlocker_key_retrieval.yml                    |
| gcp        | gcp_*          | gcp_service_account_disabled_or_deleted.yml             |
| gworkspace | gworkspace_*   | gworkspace_role_privilege_deleted.yml                   |
| m365       | microsoft365_* | microsoft365_from_susp_ip_addresses.yml                 |
| okta       | okta_*         | okta_application_sign_on_policy_modified_or_deleted.yml |
| onelogin   | onelogin_*     | onelogin_user_account_locked.yml                        |

## Category

| Category             | Pattern                    | example                                         |
| -------------------- | -------------------------- | ----------------------------------------------- |
| clipboard_capture    |                            |                                                 |
| create_remote_thread | create_remote_thread_win_* | create_remote_thread_win_bumblebee.yml          |
| create_stream_hash   | create_stream_hash_*       | create_stream_hash_ads_executable.yml           |
| dns_query            | dns_query_*os*_*           | dns_query_win_mal_cobaltstrike.yml              |
| driver_load          | driver_load_*os*_*         | driver_load_vuln_drivers_names.yml              |
| file_access          | file_access_*os*_*         | file_access_win_browser_credential_stealing.yml |
| file_change          | file_change_*os*_*         | file_change_win_2022_timestomping.yml           |
| file_delete          | file_delete_*os*_*         | file_delete_win_delete_backup_file.yml          |
| file_event           | file_event_*os*_*          | file_event_macos_startup_items.yml              |
| file_rename          | file_rename_*os*_*         | file_rename_win_not_dll_to_dll.yml              |
| image_load           | image_load_*               | image_load_susp_advapi32_dll.yml                |
| network_connection   | net_connection_*os*_*      | net_connection_lnx_crypto_mining_indicators.yml |
| pipe_created         | pipe_created_*             | pipe_created_tool_psexec.yml                    |
| ps_classic_start     | posh_pc_*                  | posh_pc_downgrade_attack.yml                    |
| ps_module            | posh_pm_*                  | posh_pm_get_clipboard.yml                       |
| ps_script            | posh_ps_*                  | posh_ps_as_rep_roasting.yml                     |
| process_access       | proc_access_*os*_*         | proc_access_win_lsass_memdump.yml               |
| process_creation     | proc_creation_*os*_*       | proc_creation_win_apt_apt29_thinktanks.yml      |
| process_tampering    |                            |                                                 |
| process_termination  |                            |                                                 |
| raw_access_thread    |                            |                                                 |
| registry_event       | registry_event_*           | registry_event_apt_pandemic.yml                 |
| registry_add         | registry_add_*             | registry_add_mal_ursnif.yml                     |
| registry_delete      | registry_delete_*          | registry_delete_mstsc_history_cleared.yml       |
| registry_set         | registry_set_*             | registry_set_add_port_monitor.yml               |
| registry_rename      | registry_rename_*          |                                                 |
| sysmon_error         |                            |                                                 |
| sysmon_status        |                            |                                                 |
| wmi_event            |                            |                                                 |

## Category without product

| Category  | Pattern        | example                                 |
| --------- | -------------- | --------------------------------------- |
| dns       | net_dns_*      | net_dns_mal_cobaltstrike.yml            |
| firewall  | net_firewall_* | net_firewall_high_dns_requests_rate.yml |
| webserver | web_*          | web_cve_2020_5902_f5_bigip.yml          |

## Service

### Linux

The naming convetion for rules using linux services is the as follows:

- Filename must start with `lnx_`
- Followed by the service name and underscore at the end `service_`. Example: `auditd_`
- If the service name contains a dash `-`. For example `bits-client`. Then replace it with an underscore `bits_client_`
- Filename must end with a `.yml` extension

| Service                               | Pattern                       | example                                           |
| ------------------------------------- | ----------------------------- | ------------------------------------------------- |
| auditd                                | lnx_auditd_*                  | lnx_auditd_alter_bash_profile.yml                 |
| auth                                  | lnx_auth_*                    | lnx_auth_susp_failed_logons_single_source.yml     |
| clamav                                | lnx_clamav_*                  | lnx_clamav_message.yml                            |
| cron                                  | lnx_cron_*                    | lnx_cron_crontab_file_modification.yml            |
| guacamole                             | lnx_guacamole_*               | lnx_guacamole_session_anomaly.yml                 |
| sshd                                  | lnx_sshd_*                    | lnx_sshd_susp_ssh.yml                             |
| sudo                                  | lnx_sudo_*                    | lnx_sudo_cve_2019_14287_user.yml                  |
| syslog                                | lnx_syslog_*                  | lnx_syslog_susp_named.yml                         |
| vsftpd                                | lnx_vsftpd_*                  | lnx_vsftp_error_messages.yml                      |

### Windows

The naming convention for rules using windows services is the as follows:

- Filename must start with `win_`
- Followed by the service name and underscore at the end `service_`. Example: `applocker_`
- If the service name contains a dash `-`. For example `bits-client`. Then replace it with an underscore `bits_client_`
- Filename must end with a `.yml` extension

| Service                               | Pattern                       | example                                                 |
| ------------------------------------- | ----------------------------- | ------------------------------------------------------- |
| application                           | ----                          | ---                                                     |
| applocker                             | win_applocker_*               | win_applocker_file_was_not_allowed_to_run.yml           |
| bits-client                           | win_bits_client_*             | win_bits_client_susp_local_file.yml                     |
| codeintegrity-operational             | win_codeintegrity_*           | win_codeintegrity_attempted_dll_load.yml                |
| diagnosis-scripted                    | win_diagnosis_scripted_*      | win_diagnosis_scripted_load_remote_diagcab.yml          |
| dns-server                            | win_dns_server_*              | win_dns_server_susp_dns_config.yml                      |
| dns-server-analytic                   | win_dns_analytic_*            | win_dns_analytic_apt_gallium.yml                        |
| driver-framework                      | ----                          | ---                                                     |
| firewall-as                           | win_firewall_as_*             | win_firewall_as_change_rule.yml                         |
| ldap_debug                            | ----                          | ---                                                     |
| msexchange-management                 | win_exchange_*                | win_exchange_proxylogon_oabvirtualdir.yml               |
| ntlm                                  | ----                          | ---                                                     |
| openssh                               | win_sshd_openssh_*            | win_sshd_openssh_server_listening_on_socket.yml         |
| printservice-operational              | ----                          | ---                                                     |
| security                              | win_security_*                | win_security_dcsync.yml                                 |
| security-mitigations                  | win_security_mitigations_*    | win_security_mitigations_defender_load_unsigned_dll.yml |
| microsoft-servicebus-client           | ----                          | ---                                                     |
| shell-core                            | win_shell_core_*              | win_shell_core_susp_packages_installed.yml              |
| smbclient-security                    | ----                          | ---                                                     |
| system                                | win_system_*                  | win_system_ntfs_vuln_exploit.yml                        |
| taskscheduler                         | win_taskscheduler_*           | win_taskscheduler_susp_task_locations.yml               |
| terminalservices-localsessionmanager  | win_terminalservices_*        | win_terminalservices_rdp_ngrok.yml                      |
| windefend                             | win_defender_*                | win_defender_amsi_trigger.yml                           |
| wmi                                   | win_wmi_*                     | win_wmi_persistence.yml                                 |
