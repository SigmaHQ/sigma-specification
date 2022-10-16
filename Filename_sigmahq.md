# SigmaHQ filename Normalisation <!-- omit in toc -->

To help with the management of the rules files, a stardardization has been set up on the SigmaHQ repository.  

# Summary

- [Summary](#summary)
- [Cloud](#cloud)
- [Category](#category)
- [Category without product](#category-without-product)
- [Service](#service)

# Cloud

| product    | Pattern        | example                                                 |
| ---------- | -------------- | ------------------------------------------------------- |
| aws        | aws_*          | aws_cloudtrail_disable_logging.yml                      |
| azure      | azure_*        | azure_ad_bitlocker_key_retrieval.yml                    |
| gcp        | gcp_*          | gcp_service_account_disabled_or_deleted.yml             |
| gworkspace | gworkspace_*   | gworkspace_role_privilege_deleted.yml                   |
| m365       | microsoft365_* | microsoft365_from_susp_ip_addresses.yml                 |
| okta       | okta_*         | okta_application_sign_on_policy_modified_or_deleted.yml |
| onelogin   | onelogin_*     | onelogin_user_account_locked.yml                        |

# Category

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

# Category without product

| Category  | Pattern        | example                                 |
| --------- | -------------- | --------------------------------------- |
| dns       | net_dns_*      | net_dns_mal_cobaltstrike.yml            |
| firewall  | net_firewall_* | net_firewall_high_dns_requests_rate.yml |
| webserver | web_*          | web_cve_2020_5902_f5_bigip.yml          |

# Service

| Service     | Pattern      | example                           |
| ----------- | ------------ | --------------------------------- |
| auditd      | lnx_auditd_* | lnx_auditd_alter_bash_profile.yml |
| modsecurity | modsec_*     | modsec_mulitple_blocks.yml        |

