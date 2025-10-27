# SigmaHQ Filename Conventions

This document describe a soft convention to name rule files. The following convention has been set to help with the management of the rules files repository and is not part of the SIGMA specification.

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Product](#product)
- [Cloud](#cloud)
- [Category](#category)
- [Category without product](#category-without-product)
- [Service](#service)
  - [Linux](#linux)
  - [Windows](#windows)

<!-- mdformat-toc end -->

## Product

| product | Pattern    | example                    |
| ------- | ---------- | -------------------------- |
| modsec  | modsec\_\* | modsec_mulitple_blocks.yml |

## Cloud

| product    | Pattern          | example                                                 |
| ---------- | ---------------- | ------------------------------------------------------- |
| aws        | aws\_\*          | aws_cloudtrail_disable_logging.yml                      |
| azure      | azure\_\*        | azure_ad_bitlocker_key_retrieval.yml                    |
| gcp        | gcp\_\*          | gcp_service_account_disabled_or_deleted.yml             |
| gworkspace | gworkspace\_\*   | gworkspace_role_privilege_deleted.yml                   |
| m365       | microsoft365\_\* | microsoft365_from_susp_ip_addresses.yml                 |
| okta       | okta\_\*         | okta_application_sign_on_policy_modified_or_deleted.yml |
| onelogin   | onelogin\_\*     | onelogin_user_account_locked.yml                        |

## Category

| Category             | Pattern                      | example                                         |
| -------------------- | ---------------------------- | ----------------------------------------------- |
| clipboard_capture    |                              |                                                 |
| create_remote_thread | create_remote_thread_win\_\* | create_remote_thread_win_bumblebee.yml          |
| create_stream_hash   | create_stream_hash\_\*       | create_stream_hash_ads_executable.yml           |
| dns_query            | dns_query\_*os*\_\*          | dns_query_win_mal_cobaltstrike.yml              |
| driver_load          | driver_load\_*os*\_\*        | driver_load_vuln_drivers_names.yml              |
| file_access          | file_access\_*os*\_\*        | file_access_win_browser_credential_stealing.yml |
| file_change          | file_change\_*os*\_\*        | file_change_win_2022_timestomping.yml           |
| file_delete          | file_delete\_*os*\_\*        | file_delete_win_delete_backup_file.yml          |
| file_event           | file_event\_*os*\_\*         | file_event_macos_startup_items.yml              |
| file_rename          | file_rename\_*os*\_\*        | file_rename_win_not_dll_to_dll.yml              |
| image_load           | image_load\_\*               | image_load_susp_advapi32_dll.yml                |
| network_connection   | net_connection\_*os*\_\*     | net_connection_lnx_crypto_mining_indicators.yml |
| pipe_created         | pipe_created\_\*             | pipe_created_tool_psexec.yml                    |
| ps_classic_start     | posh_pc\_\*                  | posh_pc_downgrade_attack.yml                    |
| ps_module            | posh_pm\_\*                  | posh_pm_get_clipboard.yml                       |
| ps_script            | posh_ps\_\*                  | posh_ps_as_rep_roasting.yml                     |
| process_access       | proc_access\_*os*\_\*        | proc_access_win_lsass_memdump.yml               |
| process_creation     | proc_creation\_*os*\_\*      | proc_creation_win_apt_apt29_thinktanks.yml      |
| process_tampering    |                              |                                                 |
| process_termination  |                              |                                                 |
| raw_access_thread    |                              |                                                 |
| registry_event       | registry_event\_\*           | registry_event_apt_pandemic.yml                 |
| registry_add         | registry_add\_\*             | registry_add_mal_ursnif.yml                     |
| registry_delete      | registry_delete\_\*          | registry_delete_mstsc_history_cleared.yml       |
| registry_set         | registry_set\_\*             | registry_set_add_port_monitor.yml               |
| registry_rename      | registry_rename\_\*          |                                                 |
| sysmon_error         |                              |                                                 |
| sysmon_status        |                              |                                                 |
| wmi_event            |                              |                                                 |

## Category without product

| Category  | Pattern          | example                                 |
| --------- | ---------------- | --------------------------------------- |
| dns       | net_dns\_\*      | net_dns_mal_cobaltstrike.yml            |
| firewall  | net_firewall\_\* | net_firewall_high_dns_requests_rate.yml |
| webserver | web\_\*          | web_cve_2020_5902_f5_bigip.yml          |

## Service

### Linux

The naming convention for rules using linux services is the as follows:

- Filename must start with `lnx_`
- Followed by the service name and underscore at the end `service_`. Example: `auditd_`
- If the service name contains a dash `-`. For example `bits-client`. Then replace it with an underscore `bits_client_`
- Filename must end with a `.yml` extension

| Service   | Pattern           | example                                       |
| --------- | ----------------- | --------------------------------------------- |
| auditd    | lnx_auditd\_\*    | lnx_auditd_alter_bash_profile.yml             |
| auth      | lnx_auth\_\*      | lnx_auth_susp_failed_logons_single_source.yml |
| clamav    | lnx_clamav\_\*    | lnx_clamav_message.yml                        |
| cron      | lnx_cron\_\*      | lnx_cron_crontab_file_modification.yml        |
| guacamole | lnx_guacamole\_\* | lnx_guacamole_session_anomaly.yml             |
| sshd      | lnx_sshd\_\*      | lnx_sshd_susp_ssh.yml                         |
| sudo      | lnx_sudo\_\*      | lnx_sudo_cve_2019_14287_user.yml              |
| syslog    | lnx_syslog\_\*    | lnx_syslog_susp_named.yml                     |
| vsftpd    | lnx_vsftpd\_\*    | lnx_vsftp_error_messages.yml                  |

### Windows

The naming convention for rules using windows services is the as follows:

- Filename must start with `win_`
- Followed by the service name and underscore at the end `service_`. Example: `applocker_`
- If the service name contains a dash `-`. For example `bits-client`. Then replace it with an underscore `bits_client_`
- Filename must end with a `.yml` extension

| Service                              | Pattern                      | example                                                 |
| ------------------------------------ | ---------------------------- | ------------------------------------------------------- |
| application                          | ----                         | ---                                                     |
| applocker                            | win_applocker\_\*            | win_applocker_file_was_not_allowed_to_run.yml           |
| bits-client                          | win_bits_client\_\*          | win_bits_client_susp_local_file.yml                     |
| codeintegrity-operational            | win_codeintegrity\_\*        | win_codeintegrity_attempted_dll_load.yml                |
| diagnosis-scripted                   | win_diagnosis_scripted\_\*   | win_diagnosis_scripted_load_remote_diagcab.yml          |
| dns-server                           | win_dns_server\_\*           | win_dns_server_susp_dns_config.yml                      |
| dns-server-analytic                  | win_dns_analytic\_\*         | win_dns_analytic_apt_gallium.yml                        |
| driver-framework                     | ----                         | ---                                                     |
| firewall-as                          | win_firewall_as\_\*          | win_firewall_as_change_rule.yml                         |
| ldap_debug                           | ----                         | ---                                                     |
| msexchange-management                | win_exchange\_\*             | win_exchange_proxylogon_oabvirtualdir.yml               |
| ntlm                                 | ----                         | ---                                                     |
| openssh                              | win_sshd_openssh\_\*         | win_sshd_openssh_server_listening_on_socket.yml         |
| printservice-operational             | ----                         | ---                                                     |
| security                             | win_security\_\*             | win_security_dcsync.yml                                 |
| security-mitigations                 | win_security_mitigations\_\* | win_security_mitigations_defender_load_unsigned_dll.yml |
| microsoft-servicebus-client          | ----                         | ---                                                     |
| shell-core                           | win_shell_core\_\*           | win_shell_core_susp_packages_installed.yml              |
| smbclient-security                   | ----                         | ---                                                     |
| system                               | win_system\_\*               | win_system_ntfs_vuln_exploit.yml                        |
| taskscheduler                        | win_taskscheduler\_\*        | win_taskscheduler_susp_task_locations.yml               |
| terminalservices-localsessionmanager | win_terminalservices\_\*     | win_terminalservices_rdp_ngrok.yml                      |
| windefend                            | win_defender\_\*             | win_defender_amsi_trigger.yml                           |
| wmi                                  | win_wmi\_\*                  | win_wmi_persistence.yml                                 |
