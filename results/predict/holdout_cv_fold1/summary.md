# Kết quả dự đoán

- 65,559 event, 75 file, ngưỡng nhị phân 0.5
- ngoài phạm vi (Sysmon 7 nạp DLL hệ thống ký Microsoft, không chấm): 2,914 event
- báo độc hại: 8,251 event

## Theo file

| File | Event | Báo độc hại | Tactic dự đoán (số event) |
|---|---|---|---|
| labels__evtx__AutomatedTestingTools__Malware__sideloading_uacbypass_rundll32_injection_c2.json | 18 | 18 | defense-evasion (12), execution (5), credential-access (1) |
| labels__evtx__Command and Control__DE_RDP_Tunnel_5156.json | 101 | 13 | command-and-control (5), discovery (3), defense-evasion (2), lateral-movement (2), persistence (1) |
| labels__evtx__Command and Control__tunna_iis_rdp_smb_tunneling_sysmon_3.json | 12 | 4 | privilege-escalation (2), discovery (2) |
| labels__evtx__Credential Access__CA_4624_4625_LogonType2_LogonProc_chrome.json | 4 | 3 | lateral-movement (3) |
| labels__evtx__Credential Access__CA_DCSync_4662.json | 3 | 3 | persistence (3) |
| labels__evtx__Credential Access__CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.json | 1 | 0 |  |
| labels__evtx__Credential Access__CA_PetiPotam_etw_rpc_efsr_5_6.json | 29109 | 0 |  |
| labels__evtx__Credential Access__CA_hashdump_4663_4656_lsass_access.json | 2 | 2 | credential-access (2) |
| labels__evtx__Credential Access__CA_teamviewer-dumper_sysmon_10.json | 1 | 1 | lateral-movement (1) |
| labels__evtx__Credential Access__LsassSilentProcessExit_process_exit_monitor_3001_lsass.json | 2 | 2 | persistence (2) |
| labels__evtx__Credential Access__MSSQL_multiple_failed_logon_EventID_18456.json | 10 | 10 | lateral-movement (10) |
| labels__evtx__Credential Access__etw_rpc_zerologon.json | 415 | 0 |  |
| labels__evtx__Credential Access__sysmon_10_1_memdump_comsvcs_minidump.json | 6 | 4 | persistence (2), execution (1), defense-evasion (1) |
| labels__evtx__Credential Access__sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.json | 1 | 1 | credential-access (1) |
| labels__evtx__Credential Access__tutto_malseclogon.json | 15 | 7 | privilege-escalation (4), lateral-movement (3) |
| labels__evtx__Defense Evasion__DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.json | 6 | 3 | credential-access (2), defense-evasion (1) |
| labels__evtx__Defense Evasion__Sysmon 7  Update Session Orchestrator Dll Hijack.json | 64 | 5 | persistence (3), execution (1), privilege-escalation (1) |
| labels__evtx__Defense Evasion__Sysmon 7 dllhijack_cdpsshims_CDPSvc.json | 13 | 8 | privilege-escalation (3), defense-evasion (2), lateral-movement (1), discovery (1), persistence (1) |
| labels__evtx__Defense Evasion__Sysmon_10_Evasion_Suspicious_NtOpenProcess_CallTrace.json | 1 | 1 | defense-evasion (1) |
| labels__evtx__Defense Evasion__apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.json | 11 | 9 | privilege-escalation (6), defense-evasion (2), persistence (1) |
| labels__evtx__Defense Evasion__de_sysmon_13_VBA_Security_AccessVBOM.json | 1 | 1 | lateral-movement (1) |
| labels__evtx__Defense Evasion__sysmon_10_1_ppid_spoofing.json | 5 | 3 | defense-evasion (1), execution (1), persistence (1) |
| labels__evtx__Defense Evasion__sysmon_2_11_evasion_timestomp_MACE.json | 2 | 1 | persistence (1) |
| labels__evtx__Discovery__discovery_meterpreter_ps_cmd_process_listing_sysmon_10.json | 52 | 45 | privilege-escalation (44), credential-access (1) |
| labels__evtx__Discovery__discovery_sysmon_18_Invoke_UserHunter_NetSessionEnum_DC-srvsvc.json | 1 | 1 | discovery (1) |
| labels__evtx__Execution__exec_wmic_xsl_internet_sysmon_3_1_11.json | 8 | 3 | execution (2), privilege-escalation (1) |
| labels__evtx__Execution__execution_evasion_visual_studio_prebuild_event.json | 29 | 18 | lateral-movement (11), privilege-escalation (4), execution (2), persistence (1) |
| labels__evtx__Execution__susp_explorer_exec.json | 3 | 3 | execution (3) |
| labels__evtx__Execution__windows_bits_4_59_60_lolbas desktopimgdownldr.json | 5 | 1 | command-and-control (1) |
| labels__evtx__Lateral Movement__DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.json | 21 | 21 | lateral-movement (21) |
| labels__evtx__Lateral Movement__LM_4624_mimikatz_sekurlsa_pth_source_machine.json | 6 | 3 | defense-evasion (1), command-and-control (1), persistence (1) |
| labels__evtx__Lateral Movement__LM_Remote_Service01_5145_svcctl.json | 1 | 1 | discovery (1) |
| labels__evtx__Lateral Movement__LM_ScheduledTask_ATSVC_target_host.json | 34 | 28 | lateral-movement (8), discovery (8), privilege-escalation (4), defense-evasion (4), execution (2), persistence (2) |
| labels__evtx__Lateral Movement__LM_WMIC_4648_rpcss.json | 5 | 2 | defense-evasion (2) |
| labels__evtx__Lateral Movement__LM_WMI_4624_4688_TargetHost.json | 8 | 4 | discovery (3), defense-evasion (1) |
| labels__evtx__Lateral Movement__LM_impacket_docmexec_mmc_sysmon_01.json | 9 | 8 | lateral-movement (3), persistence (2), defense-evasion (1), discovery (1), execution (1) |
| labels__evtx__Lateral Movement__LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.json | 6 | 3 | discovery (3) |
| labels__evtx__Lateral Movement__LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.json | 3 | 3 | lateral-movement (3) |
| labels__evtx__Lateral Movement__LM_sysmon_psexec_smb_meterpreter.json | 10 | 6 | persistence (4), lateral-movement (1), command-and-control (1) |
| labels__evtx__Lateral Movement__LM_typical_IIS_webshell_sysmon_1_10_traces.json | 4 | 3 | privilege-escalation (2), discovery (1) |
| labels__evtx__Lateral Movement__smbmap_upload_exec_sysmon.json | 27 | 17 | persistence (8), discovery (5), defense-evasion (3), privilege-escalation (1) |
| labels__evtx__Lateral Movement__sysmon_1_exec_via_sql_xpcmdshell.json | 1 | 1 | persistence (1) |
| labels__evtx__Lateral Movement__wmi_remote_registry_sysmon.json | 13 | 2 | persistence (1), lateral-movement (1) |
| labels__evtx__Persistence__Network_Service_Guest_added_to_admins_4732.json | 2 | 2 | discovery (2) |
| labels__evtx__Persistence__evasion_persis_hidden_run_keyvalue_sysmon_13.json | 1 | 1 | persistence (1) |
| labels__evtx__Persistence__persistence_sysmon_11_13_1_shime_appfix.json | 237 | 160 | privilege-escalation (76), command-and-control (39), persistence (24), execution (16), defense-evasion (5) |
| labels__evtx__Persistence__sysmon_13_1_persistence_via_winlogon_shell.json | 25 | 23 | command-and-control (6), execution (5), persistence (5), credential-access (2), defense-evasion (2), privilege-escalation (2), lateral-movement (1) |
| labels__evtx__Persistence__sysmon_20_21_1_CommandLineEventConsumer.json | 17 | 17 | persistence (7), execution (6), privilege-escalation (3), credential-access (1) |
| labels__evtx__Privilege Escalation__4765_sidhistory_add_t1178.json | 3 | 3 | discovery (1), privilege-escalation (1), defense-evasion (1) |
| labels__evtx__Privilege Escalation__Sysmon_UACME_30.json | 11 | 11 | privilege-escalation (8), persistence (2), execution (1) |
| labels__evtx__Privilege Escalation__Sysmon_UACME_33.json | 9 | 9 | privilege-escalation (9) |
| labels__evtx__Privilege Escalation__Sysmon_UACME_38.json | 8 | 8 | privilege-escalation (5), execution (2), persistence (1) |
| labels__evtx__Privilege Escalation__eop_appcontainer_il_broker_filewrite.json | 3 | 2 | privilege-escalation (1), defense-evasion (1) |
| labels__evtx__Privilege Escalation__privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.json | 7 | 7 | privilege-escalation (6), persistence (1) |
| labels__evtx__Privilege Escalation__privesc_spoolsv_spl_file_write_sysmon11.json | 37 | 17 | privilege-escalation (13), persistence (3), execution (1) |
| labels__evtx__Privilege Escalation__security_4624_4673_token_manip.json | 14 | 6 | defense-evasion (2), persistence (2), privilege-escalation (1), command-and-control (1) |
| labels__evtx__Privilege Escalation__sysmon_11_1_15_WScriptBypassUAC.json | 15 | 15 | execution (10), privilege-escalation (3), defense-evasion (2) |
| labels__evtx__Privilege Escalation__sysmon_13_1_compmgmtlauncherUACBypass.json | 4 | 4 | privilege-escalation (2), execution (2) |
| labels__evtx__Privilege Escalation__sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.json | 4 | 1 | privilege-escalation (1) |
| labels__evtx__Privilege Escalation__sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.json | 8 | 6 | privilege-escalation (4), persistence (1), execution (1) |
| labels__evtx__Privilege Escalation__win10_4703_SeDebugPrivilege_enabled.json | 1 | 1 | lateral-movement (1) |
| labels__mordor__credential_access__host__covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges__covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges_2020-08-05020926.json | 869 | 26 | execution (8), discovery (7), lateral-movement (6), persistence (3), command-and-control (2) |
| labels__mordor__defense_evasion__host__covenant_lolbin_wuauclt_createremotethread__covenant_lolbin_wuauclt_createremotethread_2020-10-12183248.json | 1326 | 107 | lateral-movement (36), execution (30), privilege-escalation (16), persistence (12), defense-evasion (6), discovery (5), command-and-control (2) |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | 5898 | 4323 | credential-access (3589), command-and-control (460), execution (124), lateral-movement (53), persistence (42), privilege-escalation (36), defense-evasion (19) |
| labels__mordor__defense_evasion__host__psh_cmstp_execution_bypassuac__psh_cmstp_execution_bypassuac_2020-10-2201543213.json | 1166 | 265 | defense-evasion (227), execution (21), persistence (7), privilege-escalation (4), command-and-control (4), lateral-movement (1), discovery (1) |
| labels__mordor__defense_evasion__host__wmic_remote_xsl_jscript__wmic_remote_xsl_jscript_2020-10-1802171958.json | 1364 | 170 | defense-evasion (164), lateral-movement (4), persistence (2) |
| labels__mordor__discovery__host__cmd_discover_iexplorer_version_registry__cmd_discover_iexplorer_version_registry_2020-10-2123281491.json | 68 | 10 | defense-evasion (4), execution (4), persistence (1), discovery (1) |
| labels__mordor__discovery__host__cmd_seatbelt_group_user__cmd_seatbelt_group_user_2020-11-0216391814.json | 451 | 88 | defense-evasion (69), lateral-movement (7), credential-access (6), privilege-escalation (2), command-and-control (2), persistence (2) |
| labels__mordor__discovery__host__empire_find_localadmin_smb_svcctl_OpenSCManager__empire_find_localadmin_smb_svcctl_OpenSCManager_2020-09-22021559.json | 4570 | 1678 | command-and-control (819), credential-access (668), lateral-movement (146), execution (18), defense-evasion (14), privilege-escalation (8), discovery (5) |
| labels__mordor__discovery__host__empire_getsession_dcerpc_smb_srvsvc_NetSessEnum__empire_getsession_dcerpc_smb_srvsvc_NetSessEnum_2020-09-22034513.json | 5047 | 616 | credential-access (293), command-and-control (291), lateral-movement (20), execution (8), discovery (4) |
| labels__mordor__lateral_movement__host__covenant_sharpsc_stop_dcerpc_smb_svcctl__covenant_sharpsc_stop_dcerpc_smb_svcctl_2020-08-06031938.json | 1264 | 56 | lateral-movement (36), discovery (9), persistence (6), command-and-control (3), execution (1), defense-evasion (1) |
| labels__mordor__lateral_movement__host__covenant_sharpwmi_create_dcerpc_wmi__covenant_sharpwmi_create_dcerpc_wmi_2020-08-06035621.json | 2343 | 128 | lateral-movement (66), execution (36), privilege-escalation (15), discovery (6), command-and-control (3), defense-evasion (2) |
| labels__mordor__lateral_movement__host__covenant_wmi_wbemcomn_dll_hijack__covenant_wmi_wbemcomn_dll_hijack_2020-10-09173318.json | 8947 | 155 | lateral-movement (105), persistence (12), privilege-escalation (10), discovery (9), execution (9), defense-evasion (9), command-and-control (1) |
| labels__mordor__lateral_movement__host__mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2__mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2_2020-09-16233923.json | 790 | 57 | lateral-movement (27), discovery (8), privilege-escalation (7), defense-evasion (5), persistence (5), execution (5) |
| labels__mordor__persistence__host__covenant_persistwmi__covenant_persistwmi_2019-12-05044734.json | 1001 | 7 | defense-evasion (2), persistence (2), discovery (2), lateral-movement (1) |

## 30 event điểm cao nhất

| File | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| labels__evtx__AutomatedTestingTools__Malware__sideloading_uacbypass_rundll32_injection_c2.json | Sysmon 1 | WINWORD.exe | 1.00 | defense-evasion (0.65) | C:\Users\IEUser\AppData\Roaming\WINWORD.exe --xStart |
| labels__evtx__Credential Access__sysmon_10_1_memdump_comsvcs_minidump.json | Sysmon 1 | rundll32.exe | 1.00 | persistence (0.81) | rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full |
| labels__evtx__Credential Access__tutto_malseclogon.json | Sysmon 1 | MalSeclogon.exe | 1.00 | privilege-escalation (0.91) | MalSeclogon.exe  -p 636 -d 2 |
| labels__evtx__Credential Access__tutto_malseclogon.json | Sysmon 1 | MalSeclogon.exe | 1.00 | privilege-escalation (0.70) | MalSeclogon.exe  -p 636 -d 2 -l 1 |
| labels__evtx__Execution__exec_wmic_xsl_internet_sysmon_3_1_11.json | Sysmon 1 | cmd.exe | 1.00 | execution (0.92) | "C:\Windows\System32\cmd.exe"  |
| labels__evtx__Execution__susp_explorer_exec.json | Sysmon 1 | wscript.exe | 1.00 | execution (0.95) | "c:\windows\system32\wscript.exe" /E:vbs c:\windows\temp\icon.ico "powershell -exec bypass -c ""IEX ([System.Text.Encodi |
| labels__evtx__Lateral Movement__LM_impacket_docmexec_mmc_sysmon_01.json | Sysmon 1 | cmd.exe | 1.00 | persistence (0.50) | "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| labels__evtx__Lateral Movement__LM_impacket_docmexec_mmc_sysmon_01.json | Sysmon 1 | cmd.exe | 1.00 | lateral-movement (0.46) | "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| labels__evtx__Lateral Movement__LM_impacket_docmexec_mmc_sysmon_01.json | Sysmon 1 | cmd.exe | 1.00 | lateral-movement (0.49) | "C:\Windows\System32\cmd.exe" /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| labels__evtx__Lateral Movement__LM_sysmon_psexec_smb_meterpreter.json | Sysmon 1 | cmd.exe | 1.00 | persistence (0.63) | C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='pow |
| labels__evtx__Lateral Movement__LM_sysmon_psexec_smb_meterpreter.json | Sysmon 1 | powershell.exe | 1.00 | persistence (0.74) | powershell.exe  -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\Win |
| labels__evtx__Lateral Movement__LM_sysmon_psexec_smb_meterpreter.json | Sysmon 1 | powershell.exe | 1.00 | persistence (0.78) | "powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.G |
| labels__evtx__Persistence__sysmon_13_1_persistence_via_winlogon_shell.json | Sysmon 1 | a.exe | 1.00 | persistence (0.79) | "C:\Users\IEUser\Downloads\a.exe"  |
| labels__evtx__Persistence__sysmon_13_1_persistence_via_winlogon_shell.json | Sysmon 11 | a.exe | 1.00 | defense-evasion (0.47) |  |
| labels__evtx__Persistence__sysmon_13_1_persistence_via_winlogon_shell.json | Sysmon 13 | a.exe | 1.00 | lateral-movement (0.50) |  |
| labels__evtx__Persistence__sysmon_13_1_persistence_via_winlogon_shell.json | Sysmon 1 | a.exe | 1.00 | persistence (0.63) | "C:\Users\IEUser\Downloads\a.exe" |
| labels__evtx__Privilege Escalation__Sysmon_UACME_38.json | Sysmon 1 | Fubuki.exe | 1.00 | execution (0.54) | "C:\Users\IEUser\AppData\Local\Temp\fubuki.exe"  |
| labels__evtx__Privilege Escalation__Sysmon_UACME_38.json | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation (0.65) | "C:\Windows\system32\cmd.exe" |
| labels__evtx__Privilege Escalation__sysmon_13_1_compmgmtlauncherUACBypass.json | Sysmon 1 | whoami.exe | 1.00 | execution (0.64) | whoami  /priv |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.98) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.99) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.96) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.97) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.99) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.98) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.99) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.96) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.97) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.99) |  |
| labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json | PowerShell 4103 |  | 1.00 | command-and-control (0.98) |  |

## So với nhãn (bỏ uncertain và event ngoài phạm vi)

- nhị phân: precision 0.951, recall 0.939, F1 0.945, PR-AUC 0.974
- tactic (event độc hại được báo đúng): accuracy 0.281, macro-F1 0.274
