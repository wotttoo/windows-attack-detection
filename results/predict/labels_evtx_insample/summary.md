# Kết quả dự đoán

- 36,659 event, 274 file, ngưỡng nhị phân 0.5
- ngoài phạm vi (Sysmon 7 nạp DLL hệ thống ký Microsoft, không chấm): 546 event
- báo độc hại: 3,794 event

## Theo file

| File | Event | Báo độc hại | Tactic dự đoán (số event) |
|---|---|---|---|
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | 23 | 20 | defense-evasion (13), persistence (6), execution (1) |
| AutomatedTestingTools/Malware/rundll32_cmd_schtask.json | 50 | 49 | persistence (49) |
| AutomatedTestingTools/Malware/rundll32_hollowing_wermgr_masquerading.json | 4 | 4 | defense-evasion (3), persistence (1) |
| AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.json | 7 | 7 | defense-evasion (5), lateral-movement (2) |
| AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.json | 18 | 18 | defense-evasion (18) |
| Command and Control/DE_RDP_Tunnel_5156.json | 101 | 49 | discovery (23), privilege-escalation (16), command-and-control (6), lateral-movement (2), defense-evasion (1), persistence (1) |
| Command and Control/DE_RDP_Tunneling_4624.json | 18 | 7 | command-and-control (4), privilege-escalation (3) |
| Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.json | 228 | 36 | command-and-control (36) |
| Command and Control/DE_sysmon-3-rdp-tun.json | 73 | 22 | discovery (11), command-and-control (5), privilege-escalation (4), defense-evasion (1), persistence (1) |
| Command and Control/bits_openvpn.json | 1537 | 28 | command-and-control (22), persistence (5), execution (1) |
| Command and Control/tunna_iis_rdp_smb_tunneling_sysmon_3.json | 12 | 6 | privilege-escalation (4), discovery (2) |
| Credential Access/4794_DSRM_password_change_t1098.json | 1 | 1 | credential-access (1) |
| Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.json | 55 | 40 | credential-access (33), privilege-escalation (6), defense-evasion (1) |
| Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.json | 4 | 3 | credential-access (2), lateral-movement (1) |
| Credential Access/CA_DCSync_4662.json | 3 | 3 | persistence (3) |
| Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.json | 1 | 0 |  |
| Credential Access/CA_PetiPotam_etw_rpc_efsr_5_6.json | 29109 | 2 | credential-access (2) |
| Credential Access/CA_chrome_firefox_opera_4663.json | 5 | 5 | credential-access (4), defense-evasion (1) |
| Credential Access/CA_hashdump_4663_4656_lsass_access.json | 2 | 2 | credential-access (2) |
| Credential Access/CA_keefarce_keepass_credump.json | 5 | 5 | defense-evasion (4), privilege-escalation (1) |
| Credential Access/CA_keepass_KeeThief_Get-KeePassDatabaseKey.json | 2 | 2 | defense-evasion (1), execution (1) |
| Credential Access/CA_protectedstorage_5145_rpc_masterkey.json | 1 | 1 | lateral-movement (1) |
| Credential Access/CA_sysmon_hashdump_cmd_meterpreter.json | 9 | 9 | credential-access (9) |
| Credential Access/CA_teamviewer-dumper_sysmon_10.json | 1 | 1 | credential-access (1) |
| Credential Access/LsassSilentProcessExit_process_exit_monitor_3001_lsass.json | 2 | 2 | credential-access (2) |
| Credential Access/MSSQL_multiple_failed_logon_EventID_18456.json | 10 | 10 | credential-access (10) |
| Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.json | 4 | 4 | persistence (3), credential-access (1) |
| Credential Access/Sysmon13_MachineAccount_Password_Hash_Changed_via_LsarSetSecret.json | 4 | 4 | credential-access (4) |
| Credential Access/Sysmon_13_Local_Admin_Password_Changed.json | 1 | 1 | persistence (1) |
| Credential Access/Zerologon_CVE-2020-1472_DFIR_System_NetLogon_Error_EventID_5805.json | 2 | 2 | defense-evasion (1), persistence (1) |
| Credential Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.json | 9 | 4 | privilege-escalation (3), defense-evasion (1) |
| Credential Access/babyshark_mimikatz_powershell.json | 33 | 11 | privilege-escalation (8), credential-access (2), defense-evasion (1) |
| Credential Access/dc_applog_ntdsutil_dfir_325_326_327.json | 4 | 4 | credential-access (4) |
| Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.json | 40 | 40 | credential-access (40) |
| Credential Access/etw_rpc_zerologon.json | 415 | 5 | credential-access (5) |
| Credential Access/kerberos_pwd_spray_4771.json | 12 | 12 | credential-access (8), privilege-escalation (2), defense-evasion (1), lateral-movement (1) |
| Credential Access/phish_windows_credentials_powershell_scriptblockLog_4104.json | 2 | 2 | credential-access (1), defense-evasion (1) |
| Credential Access/ppl_bypass_ppldump_knowdll_hijack_sysmon_security.json | 20 | 11 | credential-access (7), defense-evasion (3), privilege-escalation (1) |
| Credential Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.json | 7 | 6 | discovery (3), defense-evasion (2), privilege-escalation (1) |
| Credential Access/remote_sam_registry_access_via_backup_operator_priv.json | 31 | 15 | lateral-movement (8), privilege-escalation (4), discovery (2), defense-evasion (1) |
| Credential Access/sysmon17_18_kekeo_tsssp_default_np.json | 3 | 2 | lateral-movement (2) |
| Credential Access/sysmon_10_11_lsass_memdump.json | 4 | 4 | credential-access (4) |
| Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.json | 15 | 15 | credential-access (13), defense-evasion (2) |
| Credential Access/sysmon_10_1_memdump_comsvcs_minidump.json | 6 | 4 | privilege-escalation (1), credential-access (1), persistence (1), defense-evasion (1) |
| Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.json | 1 | 1 | credential-access (1) |
| Credential Access/sysmon_13_keylogger_directx.json | 6 | 6 | credential-access (2), lateral-movement (2), privilege-escalation (2) |
| Credential Access/sysmon_2x10_lsass_with_different_pid_RtlCreateProcessReflection.json | 3 | 3 | credential-access (3) |
| Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.json | 2 | 2 | execution (1), credential-access (1) |
| Credential Access/sysmon_rdrleakdiag_lsass_dump.json | 4 | 3 | credential-access (2), defense-evasion (1) |
| Credential Access/tutto_malseclogon.json | 15 | 11 | privilege-escalation (7), credential-access (4) |
| Defense Evasion/DE_104_system_log_cleared.json | 1 | 1 | defense-evasion (1) |
| Defense Evasion/DE_1102_security_log_cleared.json | 112 | 1 | defense-evasion (1) |
| Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.json | 6 | 3 | defense-evasion (3) |
| Defense Evasion/DE_EventLog_Service_Crashed.json | 4 | 2 | defense-evasion (2) |
| Defense Evasion/DE_Fake_ComputerAccount_4720.json | 2 | 2 | defense-evasion (2) |
| Defense Evasion/DE_KernelDebug_and_TestSigning_ON_Security_4826.json | 6 | 6 | defense-evasion (6) |
| Defense Evasion/DE_Powershell_CLM_Disabled_Sysmon_12.json | 1 | 1 | defense-evasion (1) |
| Defense Evasion/DE_ProcessHerpaderping_Sysmon_11_10_1_7.json | 4 | 4 | defense-evasion (2), persistence (1), lateral-movement (1) |
| Defense Evasion/DE_UAC_Disabled_Sysmon_12_13.json | 3 | 3 | defense-evasion (3) |
| Defense Evasion/DE_WinEventLogSvc_Crash_System_7036.json | 6 | 1 | defense-evasion (1) |
| Defense Evasion/DE_remote_eventlog_svc_crash_byt3bl33d3r_sysmon_17_1_3.json | 11 | 8 | defense-evasion (5), lateral-movement (2), discovery (1) |
| Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.json | 11 | 10 | defense-evasion (8), discovery (2) |
| Defense Evasion/DE_suspicious_remote_eventlog_svc_access_5145.json | 8 | 7 | defense-evasion (5), discovery (2) |
| Defense Evasion/DE_xp_cmdshell_enabled_MSSQL_EID_15457.json | 4 | 4 | defense-evasion (4) |
| Defense Evasion/DSE_bypass_BYOV_TDL_dummydriver_sysmon_6_7_13.json | 8 | 7 | defense-evasion (6), discovery (1) |
| Defense Evasion/Sysmon 7  Update Session Orchestrator Dll Hijack.json | 64 | 59 | defense-evasion (57), persistence (1), privilege-escalation (1) |
| Defense Evasion/Sysmon 7 dllhijack_cdpsshims_CDPSvc.json | 13 | 8 | defense-evasion (7), privilege-escalation (1) |
| Defense Evasion/Sysmon_10_Evasion_Suspicious_NtOpenProcess_CallTrace.json | 1 | 1 | defense-evasion (1) |
| Defense Evasion/Sysmon_12_DE_AntiForensics_MRU_DeleteKey.json | 3 | 3 | defense-evasion (3) |
| Defense Evasion/Win_4985_T1186_Process_Doppelganging.json | 2 | 2 | defense-evasion (2) |
| Defense Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.json | 11 | 11 | defense-evasion (9), privilege-escalation (2) |
| Defense Evasion/de_PsScriptBlockLogging_disabled_sysmon12_13.json | 2 | 2 | persistence (1), defense-evasion (1) |
| Defense Evasion/de_hiding_files_via_attrib_cmdlet.json | 1 | 1 | defense-evasion (1) |
| Defense Evasion/de_portforward_netsh_rdp_sysmon_13_1.json | 3 | 3 | execution (2), defense-evasion (1) |
| Defense Evasion/de_powershell_execpolicy_changed_sysmon_13.json | 5 | 1 | defense-evasion (1) |
| Defense Evasion/de_sysmon_13_VBA_Security_AccessVBOM.json | 1 | 1 | lateral-movement (1) |
| Defense Evasion/de_unmanagedpowershell_psinject_sysmon_7_8_10.json | 84 | 84 | execution (83), defense-evasion (1) |
| Defense Evasion/evasion_codeinj_odzhan_conhost_sysmon_10_1.json | 4 | 2 | defense-evasion (1), privilege-escalation (1) |
| Defense Evasion/evasion_codeinj_odzhan_spoolsv_sysmon_10_1.json | 4 | 1 | defense-evasion (1) |
| Defense Evasion/faxhell_sysmon_7_1_18_3_bindshell_dllhijack.json | 10 | 9 | privilege-escalation (4), defense-evasion (3), execution (1), persistence (1) |
| Defense Evasion/meterpreter_migrate_to_explorer_sysmon_8.json | 1 | 1 | defense-evasion (1) |
| Defense Evasion/process_suspend_sysmon_10_ga_800.json | 1 | 1 | defense-evasion (1) |
| Defense Evasion/sideloading_wwlib_sysmon_7_1_11.json | 7 | 5 | execution (3), defense-evasion (1), lateral-movement (1) |
| Defense Evasion/sysmon_10_1_ppid_spoofing.json | 5 | 3 | defense-evasion (1), execution (1), privilege-escalation (1) |
| Defense Evasion/sysmon_13_rdp_settings_tampering.json | 20 | 20 | defense-evasion (18), privilege-escalation (2) |
| Defense Evasion/sysmon_2_11_evasion_timestomp_MACE.json | 2 | 2 | persistence (1), execution (1) |
| Discovery/4799_remote_local_groups_enumeration.json | 5 | 5 | discovery (5) |
| Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.json | 20 | 20 | discovery (20) |
| Discovery/dicovery_4661_net_group_domain_admins_target.json | 63 | 30 | discovery (24), lateral-movement (4), defense-evasion (2) |
| Discovery/discovery_UEFI_Settings_rweverything_sysmon_6.json | 1 | 1 | discovery (1) |
| Discovery/discovery_bloodhound.json | 10 | 9 | discovery (8), defense-evasion (1) |
| Discovery/discovery_enum_shares_target_sysmon_3_18.json | 4 | 4 | discovery (4) |
| Discovery/discovery_local_user_or_group_windows_security_4799_4798.json | 3 | 3 | discovery (3) |
| Discovery/discovery_meterpreter_ps_cmd_process_listing_sysmon_10.json | 52 | 49 | discovery (49) |
| Discovery/discovery_psloggedon.json | 4 | 4 | discovery (3), defense-evasion (1) |
| Discovery/discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.json | 1 | 1 | discovery (1) |
| Discovery/discovery_sysmon_3_Invoke_UserHunter_SourceMachine.json | 9 | 2 | defense-evasion (2) |
| Execution/Exec_sysmon_meterpreter_reversetcp_msipackage.json | 8 | 6 | execution (6) |
| Execution/Exec_via_cpl_Application_Experience_EventID_17_ControlPanelApplet.json | 4 | 4 | execution (4) |
| Execution/Sysmon_Exec_CompiledHTML.json | 2 | 2 | execution (2) |
| Execution/Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.json | 13 | 12 | execution (12) |
| Execution/evasion_execution_imageload_wuauclt_lolbas.json | 3 | 3 | execution (3) |
| Execution/exec_driveby_cve-2018-15982_sysmon_1_10.json | 2 | 2 | execution (2) |
| Execution/exec_msxsl_xsl_sysmon_1_7.json | 3 | 2 | execution (2) |
| Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.json | 8 | 8 | execution (8) |
| Execution/exec_sysmon_1_11_lolbin_rundll32_openurl_FileProtocolHandler.json | 11 | 11 | execution (11) |
| Execution/exec_sysmon_1_11_lolbin_rundll32_shdocvw_openurl.json | 6 | 3 | execution (3) |
| Execution/exec_sysmon_1_11_lolbin_rundll32_zipfldr_RouteTheCall.json | 2 | 2 | execution (2) |
| Execution/exec_sysmon_1_7_jscript9_defense_evasion.json | 3 | 2 | execution (2) |
| Execution/exec_sysmon_1_ftp.json | 4 | 4 | execution (4) |
| Execution/exec_sysmon_1_lolbin_pcalua.json | 3 | 3 | execution (3) |
| Execution/exec_sysmon_1_lolbin_renamed_regsvr32_scrobj.json | 2 | 2 | execution (2) |
| Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.json | 2 | 2 | execution (2) |
| Execution/exec_sysmon_1_rundll32_pcwutl_LaunchApplication.json | 1 | 1 | execution (1) |
| Execution/exec_sysmon_lobin_regsvr32_sct.json | 3 | 3 | execution (3) |
| Execution/exec_wmic_xsl_internet_sysmon_3_1_11.json | 8 | 3 | execution (2), privilege-escalation (1) |
| Execution/execution_evasion_visual_studio_prebuild_event.json | 29 | 6 | execution (5), persistence (1) |
| Execution/revshell_cmd_svchost_sysmon_1.json | 4 | 1 | execution (1) |
| Execution/rogue_msi_url_1040_1042.json | 351 | 0 |  |
| Execution/susp_explorer_exec.json | 3 | 3 | execution (3) |
| Execution/susp_explorer_exec_root_cmdline_@rimpq_@CyberRaiju.json | 10 | 6 | execution (3), defense-evasion (2), persistence (1) |
| Execution/sysmon_11_1_lolbas_downldr_desktopimgdownldr.json | 3 | 2 | execution (2) |
| Execution/sysmon_1_11_rundll32_cpl_ostap.json | 5 | 5 | execution (5) |
| Execution/sysmon_exec_from_vss_persistence.json | 17 | 17 | execution (17) |
| Execution/sysmon_lolbas_rundll32_zipfldr_routethecall_shell.json | 2 | 2 | execution (2) |
| Execution/sysmon_lolbin_bohops_vshadow_exec.json | 6 | 6 | execution (6) |
| Execution/sysmon_mshta_sharpshooter_stageless_meterpreter.json | 3 | 3 | execution (3) |
| Execution/sysmon_vbs_sharpshooter_stageless_meterpreter.json | 5 | 4 | execution (4) |
| Execution/sysmon_zipexec.json | 8 | 7 | execution (7) |
| Execution/temp_scheduled_task_4698_4699.json | 2 | 2 | execution (2) |
| Execution/windows_bits_4_59_60_lolbas desktopimgdownldr.json | 5 | 5 | execution (5) |
| Lateral Movement/DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.json | 21 | 21 | lateral-movement (21) |
| Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.json | 14 | 8 | lateral-movement (3), privilege-escalation (3), discovery (1), execution (1) |
| Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.json | 6 | 5 | privilege-escalation (4), defense-evasion (1) |
| Lateral Movement/LM_5145_Remote_FileCopy.json | 869 | 869 | lateral-movement (869) |
| Lateral Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.json | 2 | 2 | execution (1), defense-evasion (1) |
| Lateral Movement/LM_ImageLoad_NFSH_Sysmon_7.json | 2 | 2 | lateral-movement (2) |
| Lateral Movement/LM_NewShare_Added_Sysmon_12_13.json | 3 | 3 | lateral-movement (3) |
| Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.json | 1 | 1 | lateral-movement (1) |
| Lateral Movement/LM_REMCOM_5145_TargetHost.json | 30 | 30 | lateral-movement (27), discovery (3) |
| Lateral Movement/LM_Remote_Service01_5145_svcctl.json | 1 | 1 | discovery (1) |
| Lateral Movement/LM_Remote_Service02_7045.json | 3 | 3 | lateral-movement (3) |
| Lateral Movement/LM_ScheduledTask_ATSVC_target_host.json | 34 | 30 | lateral-movement (9), discovery (8), privilege-escalation (7), defense-evasion (4), execution (2) |
| Lateral Movement/LM_WMIC_4648_rpcss.json | 5 | 4 | defense-evasion (2), persistence (2) |
| Lateral Movement/LM_WMI_4624_4688_TargetHost.json | 8 | 6 | discovery (2), lateral-movement (2), defense-evasion (1), privilege-escalation (1) |
| Lateral Movement/LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.json | 1 | 1 | execution (1) |
| Lateral Movement/LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.json | 4 | 4 | lateral-movement (4) |
| Lateral Movement/LM_impacket_docmexec_mmc_sysmon_01.json | 9 | 8 | lateral-movement (5), persistence (1), defense-evasion (1), discovery (1) |
| Lateral Movement/LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.json | 6 | 5 | lateral-movement (3), discovery (1), privilege-escalation (1) |
| Lateral Movement/LM_renamed_psexecsvc_5145.json | 22 | 18 | discovery (9), lateral-movement (9) |
| Lateral Movement/LM_sysmon_1_12_13_3_tsclient_SharpRdp.json | 9 | 9 | lateral-movement (8), defense-evasion (1) |
| Lateral Movement/LM_sysmon_3_12_13_1_SharpRDP.json | 38 | 37 | lateral-movement (28), execution (6), defense-evasion (2), privilege-escalation (1) |
| Lateral Movement/LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.json | 3 | 3 | lateral-movement (3) |
| Lateral Movement/LM_sysmon_psexec_smb_meterpreter.json | 10 | 10 | lateral-movement (6), discovery (1), persistence (1), privilege-escalation (1), command-and-control (1) |
| Lateral Movement/LM_sysmon_remote_task_src_powershell.json | 3 | 2 | discovery (2) |
| Lateral Movement/LM_tsclient_startup_folder.json | 4 | 1 | persistence (1) |
| Lateral Movement/LM_typical_IIS_webshell_sysmon_1_10_traces.json | 4 | 3 | privilege-escalation (2), discovery (1) |
| Lateral Movement/LM_winrm_exec_sysmon_1_winrshost.json | 3 | 3 | lateral-movement (2), defense-evasion (1) |
| Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.json | 1 | 1 | lateral-movement (1) |
| Lateral Movement/LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.json | 15 | 15 | lateral-movement (14), execution (1) |
| Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.json | 7 | 6 | lateral-movement (5), discovery (1) |
| Lateral Movement/LM_xp_cmdshell_MSSQL_Events.json | 21 | 21 | lateral-movement (17), defense-evasion (4) |
| Lateral Movement/MSSQL_15281_xp_cmdshell_exec_failed_attempt.json | 1 | 1 | lateral-movement (1) |
| Lateral Movement/RemotePowerShell_MS_Windows-Remote_Management_EventID_169.json | 6 | 6 | lateral-movement (6) |
| Lateral Movement/dfir_rdpsharp_target_RdpCoreTs_168_68_131.json | 40 | 40 | lateral-movement (40) |
| Lateral Movement/lateral_movement_startup_3_11.json | 2 | 2 | persistence (1), lateral-movement (1) |
| Lateral Movement/lm_remote_registry_sysmon_1_13_3.json | 4 | 3 | privilege-escalation (1), persistence (1), lateral-movement (1) |
| Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.json | 7 | 7 | lateral-movement (3), privilege-escalation (2), discovery (1), persistence (1) |
| Lateral Movement/net_share_drive_5142.json | 2 | 2 | defense-evasion (1), lateral-movement (1) |
| Lateral Movement/powercat_revShell_sysmon_1_3.json | 9 | 9 | lateral-movement (5), privilege-escalation (3), execution (1) |
| Lateral Movement/remote task update 4624 4702 same logonid.json | 8 | 3 | defense-evasion (1), privilege-escalation (1), lateral-movement (1) |
| Lateral Movement/remote_file_copy_system_proc_file_write_sysmon_11.json | 2 | 2 | privilege-escalation (2) |
| Lateral Movement/sharprdp_sysmon_7_mstscax.dll.json | 4 | 3 | execution (3) |
| Lateral Movement/smb_bi_auth_conn_spoolsample.json | 2 | 1 | discovery (1) |
| Lateral Movement/smbmap_upload_exec_sysmon.json | 27 | 20 | lateral-movement (11), persistence (8), privilege-escalation (1) |
| Lateral Movement/spoolsample_5145.json | 1 | 1 | discovery (1) |
| Lateral Movement/sysmon_1_exec_via_sql_xpcmdshell.json | 1 | 1 | persistence (1) |
| Lateral Movement/wmi_remote_registry_sysmon.json | 13 | 2 | persistence (1), lateral-movement (1) |
| Other/emotet/exec_emotet_ps_4104.json | 1 | 1 | execution (1) |
| Other/emotet/exec_emotet_ps_800_get-item.json | 1 | 1 | execution (1) |
| Other/emotet/exec_emotet_ps_800_invoke-item.json | 1 | 1 | execution (1) |
| Other/emotet/exec_emotet_ps_800_new-item.json | 1 | 1 | execution (1) |
| Other/emotet/exec_emotet_ps_800_new-object.json | 1 | 1 | execution (1) |
| Other/emotet/exec_emotet_sysmon_1.json | 1 | 1 | execution (1) |
| Other/maldoc_mshta_via_shellbrowserwind_rundll32.json | 11 | 10 | execution (10) |
| Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json | 733 | 725 | lateral-movement (457), discovery (268) |
| Persistence/DACL_DCSync_Right_Powerview_ Add-DomainObjectAcl.json | 28 | 28 | persistence (27), defense-evasion (1) |
| Persistence/Network_Service_Guest_added_to_admins_4732.json | 2 | 2 | persistence (2) |
| Persistence/Persistence_Shime_Microsoft-Windows-Application-Experience_Program-Telemetry_500.json | 7 | 7 | persistence (7) |
| Persistence/Persistence_Winsock_Catalog Change EventId_1.json | 2 | 2 | persistence (2) |
| Persistence/evasion_persis_hidden_run_keyvalue_sysmon_13.json | 1 | 1 | persistence (1) |
| Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.json | 6 | 6 | persistence (6) |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | 19 | 17 | persistence (17) |
| Persistence/persist_turla_outlook_backdoor_comhijack.json | 3 | 3 | persistence (3) |
| Persistence/persist_valid_account_guest_rid_hijack.json | 4 | 3 | persistence (3) |
| Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.json | 13 | 10 | persistence (10) |
| Persistence/persistence_accessibility_features_osk_sysmon1.json | 3 | 1 | persistence (1) |
| Persistence/persistence_hidden_local_account_sysmon.json | 1 | 1 | persistence (1) |
| Persistence/persistence_pendingGPO_sysmon_13.json | 4 | 3 | persistence (3) |
| Persistence/persistence_security_dcshadow_4742.json | 10 | 10 | persistence (9), defense-evasion (1) |
| Persistence/persistence_startup_UserShellStartup_Folder_Changed_sysmon_13.json | 1 | 1 | persistence (1) |
| Persistence/persistence_sysmon_11_13_1_shime_appfix.json | 237 | 124 | persistence (73), privilege-escalation (29), execution (15), command-and-control (5), credential-access (2) |
| Persistence/sysmon_13_1_persistence_via_winlogon_shell.json | 25 | 16 | persistence (11), execution (3), credential-access (1), privilege-escalation (1) |
| Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.json | 6 | 5 | persistence (3), execution (2) |
| Persistence/sysmon_1_smss_child_proc_bootexecute_setupexecute.json | 1 | 1 | persistence (1) |
| Persistence/sysmon_20_21_1_CommandLineEventConsumer.json | 17 | 17 | persistence (17) |
| Persistence/sysmon_local_account_creation_and_added_admingroup_12_13.json | 17 | 17 | persistence (17) |
| Persistence/wmighost_sysmon_20_21_1.json | 4 | 3 | persistence (3) |
| Privilege Escalation/4624 LT3 AnonymousLogon Localhost - JuicyPotato.json | 3 | 2 | defense-evasion (1), privilege-escalation (1) |
| Privilege Escalation/4765_sidhistory_add_t1178.json | 3 | 3 | privilege-escalation (2), discovery (1) |
| Privilege Escalation/CVE-2020-0796_SMBV3Ghost_LocalPrivEsc_Sysmon_3_1_10.json | 4 | 4 | privilege-escalation (4) |
| Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.json | 20 | 7 | privilege-escalation (5), discovery (1), persistence (1) |
| Privilege Escalation/Invoke_TokenDuplication_UAC_Bypass4624.json | 1 | 1 | privilege-escalation (1) |
| Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.json | 11 | 11 | privilege-escalation (10), defense-evasion (1) |
| Privilege Escalation/PrivEsc_CVE-2020-1313_Sysmon_13_UScheduler_Cmdline.json | 4 | 3 | privilege-escalation (3) |
| Privilege Escalation/PrivEsc_Imperson_NetSvc_to_Sys_Decoder_Sysmon_1_17_18.json | 13 | 10 | privilege-escalation (10) |
| Privilege Escalation/PrivEsc_NetSvc_SessionToken_Retrival_via_localSMB_Auth_5145.json | 1 | 1 | privilege-escalation (1) |
| Privilege Escalation/PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.json | 2 | 2 | privilege-escalation (2) |
| Privilege Escalation/RogueWinRM.json | 7 | 5 | privilege-escalation (5) |
| Privilege Escalation/Runas_4624_4648_Webshell_CreateProcessAsUserA.json | 3 | 3 | privilege-escalation (2), defense-evasion (1) |
| Privilege Escalation/Sysmon_13_1_UACBypass_SDCLTBypass.json | 5 | 5 | privilege-escalation (5) |
| Privilege Escalation/Sysmon_13_1_UAC_Bypass_EventVwrBypass.json | 6 | 5 | privilege-escalation (5) |
| Privilege Escalation/Sysmon_UACME_22.json | 19 | 19 | privilege-escalation (19) |
| Privilege Escalation/Sysmon_UACME_23.json | 8 | 8 | privilege-escalation (8) |
| Privilege Escalation/Sysmon_UACME_30.json | 11 | 11 | privilege-escalation (11) |
| Privilege Escalation/Sysmon_UACME_32.json | 8 | 8 | privilege-escalation (8) |
| Privilege Escalation/Sysmon_UACME_33.json | 9 | 9 | privilege-escalation (9) |
| Privilege Escalation/Sysmon_UACME_34.json | 6 | 6 | privilege-escalation (6) |
| Privilege Escalation/Sysmon_UACME_36_FileCreate.json | 13 | 13 | privilege-escalation (13) |
| Privilege Escalation/Sysmon_UACME_37_FileCreate.json | 7 | 7 | privilege-escalation (7) |
| Privilege Escalation/Sysmon_UACME_38.json | 8 | 8 | privilege-escalation (7), execution (1) |
| Privilege Escalation/Sysmon_UACME_39.json | 7 | 7 | privilege-escalation (7) |
| Privilege Escalation/Sysmon_UACME_41.json | 4 | 4 | privilege-escalation (4) |
| Privilege Escalation/Sysmon_UACME_43.json | 5 | 5 | privilege-escalation (5) |
| Privilege Escalation/Sysmon_UACME_45.json | 8 | 8 | privilege-escalation (8) |
| Privilege Escalation/Sysmon_UACME_53.json | 14 | 14 | privilege-escalation (14) |
| Privilege Escalation/Sysmon_UACME_54.json | 10 | 10 | privilege-escalation (10) |
| Privilege Escalation/Sysmon_UACME_56.json | 15 | 15 | privilege-escalation (15) |
| Privilege Escalation/Sysmon_UACME_63.json | 3 | 3 | privilege-escalation (2), persistence (1) |
| Privilege Escalation/Sysmon_UACME_64.json | 530 | 16 | privilege-escalation (16) |
| Privilege Escalation/Sysmon_uacme_58.json | 6 | 6 | privilege-escalation (6) |
| Privilege Escalation/System_7045_namedpipe_privesc.json | 1 | 1 | privilege-escalation (1) |
| Privilege Escalation/UACME_59_Sysmon.json | 7 | 2 | privilege-escalation (2) |
| Privilege Escalation/UACME_61_Changepk.json | 2 | 2 | privilege-escalation (2) |
| Privilege Escalation/eop_appcontainer_il_broker_filewrite.json | 3 | 2 | privilege-escalation (2) |
| Privilege Escalation/privesc_KrbRelayUp_windows_4624.json | 1 | 1 | privilege-escalation (1) |
| Privilege Escalation/privesc_registry_symlink_CVE-2020-1377.json | 30 | 20 | privilege-escalation (20) |
| Privilege Escalation/privesc_roguepotato_sysmon_17_18.json | 6 | 5 | privilege-escalation (5) |
| Privilege Escalation/privesc_rotten_potato_from_webshell_metasploit_sysmon_1_8_3.json | 13 | 9 | privilege-escalation (8), execution (1) |
| Privilege Escalation/privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.json | 7 | 7 | privilege-escalation (7) |
| Privilege Escalation/privesc_spoolfool_mahdihtm_sysmon_1_11_7_13.json | 4 | 4 | privilege-escalation (4) |
| Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.json | 37 | 33 | privilege-escalation (31), persistence (1), execution (1) |
| Privilege Escalation/privesc_sysmon_cve_20201030_spooler.json | 8 | 6 | privilege-escalation (6) |
| Privilege Escalation/privesc_unquoted_svc_sysmon_1_11.json | 87 | 6 | privilege-escalation (4), execution (1), lateral-movement (1) |
| Privilege Escalation/privexchange_dirkjan.json | 8 | 4 | privilege-escalation (4) |
| Privilege Escalation/samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.json | 18 | 16 | privilege-escalation (15), defense-evasion (1) |
| Privilege Escalation/security_4624_4673_token_manip.json | 14 | 12 | privilege-escalation (10), defense-evasion (1), persistence (1) |
| Privilege Escalation/sysmon_11_1_15_WScriptBypassUAC.json | 15 | 15 | privilege-escalation (15) |
| Privilege Escalation/sysmon_11_1_7_uacbypass_cliconfg.json | 8 | 8 | privilege-escalation (8) |
| Privilege Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.json | 10 | 10 | privilege-escalation (6), persistence (2), lateral-movement (1), defense-evasion (1) |
| Privilege Escalation/sysmon_13_1_12_11_perfmonUACBypass.json | 5 | 5 | privilege-escalation (5) |
| Privilege Escalation/sysmon_13_1_compmgmtlauncherUACBypass.json | 4 | 4 | privilege-escalation (3), execution (1) |
| Privilege Escalation/sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.json | 4 | 4 | privilege-escalation (4) |
| Privilege Escalation/sysmon_1_11_exec_as_system_via_schedtask.json | 6 | 6 | privilege-escalation (5), persistence (1) |
| Privilege Escalation/sysmon_1_13_11_cmstp_ini_uacbypass.json | 5 | 5 | privilege-escalation (4), defense-evasion (1) |
| Privilege Escalation/sysmon_1_13_UACBypass_AppPath_Control.json | 3 | 3 | privilege-escalation (3) |
| Privilege Escalation/sysmon_1_7_11_mcx2prov_uacbypass.json | 9 | 9 | privilege-escalation (9) |
| Privilege Escalation/sysmon_1_7_11_migwiz.json | 7 | 7 | privilege-escalation (7) |
| Privilege Escalation/sysmon_1_7_11_sysprep_uacbypass.json | 7 | 7 | privilege-escalation (7) |
| Privilege Escalation/sysmon_1_7_elevate_uacbypass_sysprep.json | 15 | 12 | privilege-escalation (12) |
| Privilege Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.json | 3 | 3 | privilege-escalation (2), persistence (1) |
| Privilege Escalation/sysmon_privesc_psexec_dwell.json | 12 | 9 | privilege-escalation (8), lateral-movement (1) |
| Privilege Escalation/sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.json | 8 | 7 | privilege-escalation (7) |
| Privilege Escalation/win10_4703_SeDebugPrivilege_enabled.json | 1 | 1 | privilege-escalation (1) |

## 30 event điểm cao nhất

| File | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | Sysmon 11 | Flash_update.exe | 1.00 | persistence (0.57) |  |
| Privilege Escalation/security_4624_4673_token_manip.json | Security-Auditing 4688 | python.exe | 1.00 | privilege-escalation (0.90) |  |
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | Sysmon 7 | Flash_update.exe | 1.00 | out_of_scope (0.58) |  |
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | Sysmon 2 | Flash_update.exe | 1.00 | defense-evasion (0.70) |  |
| Privilege Escalation/sysmon_privesc_from_admin_to_system_handle_inheritance.json | Sysmon 1 | python.exe | 1.00 | persistence (0.58) | python  winpwnage.py -u elevate -i 1 -p c:\Windows\System32\cmd.exe |
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | Sysmon 2 | Flash_update.exe | 1.00 | defense-evasion (0.79) |  |
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | Sysmon 11 | Flash_update.exe | 1.00 | defense-evasion (0.37) |  |
| AutomatedTestingTools/Malware/rundll32_cmd_schtask.json | Sysmon 1 | cmd.exe | 1.00 | persistence (0.90) | "C:\Windows\System32\cmd.exe"  /C schtasks /Create /f /XML C:\Users\IEUser\AppData\Local\Temp\sduchxll.tmp /TN DataUsage |
| AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json | Sysmon 2 | Flash_update.exe | 1.00 | defense-evasion (0.77) |  |
| Privilege Escalation/sysmon_1_11_exec_as_system_via_schedtask.json | Sysmon 1 | python.exe | 1.00 | persistence (0.58) | python  winpwnage.py -u elevate -i 4 -p c:\Windows\System32\cmd.exe |
| Lateral Movement/LM_5145_Remote_FileCopy.json | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| Privilege Escalation/sysmon_1_13_UACBypass_AppPath_Control.json | Sysmon 13 | powershell.exe | 1.00 | privilege-escalation (0.96) |  |
| AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.json | Sysmon 7 | WINWORD.exe | 1.00 | defense-evasion (0.95) |  |
| AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.json | Sysmon 8 | WINWORD.exe | 1.00 | defense-evasion (0.96) |  |
| AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.json | Sysmon 8 | WINWORD.exe | 1.00 | defense-evasion (0.96) |  |
| Privilege Escalation/Sysmon_UACME_64.json | Sysmon 1 | [1]consent.exe | 1.00 | privilege-escalation (0.90) | C:\Users\den\AppData\Local\Temp\IDC1.tmp\[1]consent.exe |
| Privilege Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.json | Sysmon 11 | UACBypass.exe | 1.00 | privilege-escalation (0.66) |  |
| AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.json | Sysmon 1 | WINWORD.exe | 1.00 | defense-evasion (0.99) | C:\Users\IEUser\AppData\Roaming\WINWORD.exe --xStart |
| Privilege Escalation/UACME_59_Sysmon.json | Sysmon 10 | Akagi_64.exe | 1.00 | privilege-escalation (0.55) |  |
| AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.json | Sysmon 7 | WINWORD.exe | 1.00 | defense-evasion (0.95) |  |
| Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.json | Sysmon 1 | powershell.exe | 1.00 | lateral-movement (0.49) | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -s -NoLogo -NoProfile |
| Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.json | Sysmon 1 | appcmd.exe | 1.00 | credential-access (0.94) | "C:\Windows\System32\inetsrv\appcmd.exe"  list apppool /text:processmodel.username |
| Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.json | Sysmon 1 | appcmd.exe | 1.00 | credential-access (0.94) | "C:\Windows\System32\inetsrv\appcmd.exe"  list apppool /text:processmodel.password |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | Sysmon 1 | firefox.exe | 1.00 | persistence (0.98) | "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="3168.6.1176946839\1268428683" -childID 1 -isForBr |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | Sysmon 1 | firefox.exe | 1.00 | persistence (0.98) | "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="3168.13.1464597065\1561502721" -childID 2 -isForB |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | Sysmon 1 | firefox.exe | 1.00 | persistence (0.98) | "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="3168.20.1502540827\1989220046" -childID 3 -isForB |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | Sysmon 11 | com-hijack.exe | 1.00 | persistence (0.50) |  |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | Sysmon 13 | com-hijack.exe | 1.00 | persistence (0.99) |  |
| Persistence/persist_firefox_comhijack_sysmon_11_13_7_1.json | Sysmon 1 | com-hijack.exe | 1.00 | persistence (0.88) | "C:\Users\IEUser\Downloads\com-hijack.exe"  |
| Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.json | Sysmon 1 | appcmd.exe | 1.00 | credential-access (0.94) | "C:\Windows\System32\inetsrv\appcmd.exe"  list apppool /text:processmodel.username |

## So với nhãn (bỏ uncertain và event ngoài phạm vi)

- nhị phân: precision 0.969, recall 0.943, F1 0.956, PR-AUC 0.983
- tactic (event độc hại được báo đúng): accuracy 0.863, macro-F1 0.801
