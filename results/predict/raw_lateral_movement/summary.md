# Kết quả dự đoán

- 1,288 event, 47 file, ngưỡng nhị phân 0.5
- ngoài phạm vi (Sysmon 7 nạp DLL hệ thống ký Microsoft, không chấm): 3 event
- báo độc hại: 1,235 event

## Theo file

| File | Event | Báo độc hại | Tactic dự đoán (số event) |
|---|---|---|---|
| DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx | 21 | 21 | lateral-movement (21) |
| ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx | 14 | 8 | lateral-movement (3), privilege-escalation (3), discovery (1), execution (1) |
| LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx | 6 | 5 | privilege-escalation (4), defense-evasion (1) |
| LM_5145_Remote_FileCopy.evtx | 869 | 869 | lateral-movement (869) |
| LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx | 2 | 2 | execution (1), defense-evasion (1) |
| LM_ImageLoad_NFSH_Sysmon_7.evtx | 2 | 2 | lateral-movement (2) |
| LM_NewShare_Added_Sysmon_12_13.evtx | 3 | 3 | lateral-movement (3) |
| LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx | 1 | 1 | lateral-movement (1) |
| LM_REMCOM_5145_TargetHost.evtx | 30 | 30 | lateral-movement (27), discovery (3) |
| LM_Remote_Service01_5145_svcctl.evtx | 1 | 1 | discovery (1) |
| LM_Remote_Service02_7045.evtx | 3 | 3 | lateral-movement (3) |
| LM_ScheduledTask_ATSVC_target_host.evtx | 34 | 30 | lateral-movement (9), discovery (8), privilege-escalation (7), defense-evasion (4), execution (2) |
| LM_WMIC_4648_rpcss.evtx | 5 | 4 | defense-evasion (2), persistence (2) |
| LM_WMI_4624_4688_TargetHost.evtx | 8 | 6 | discovery (2), lateral-movement (2), defense-evasion (1), privilege-escalation (1) |
| LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx | 1 | 1 | execution (1) |
| LM_dcom_shwnd_shbrwnd_mmc20_failed_traces_system_10016.evtx | 4 | 4 | lateral-movement (4) |
| LM_impacket_docmexec_mmc_sysmon_01.evtx | 9 | 8 | lateral-movement (5), persistence (1), defense-evasion (1), discovery (1) |
| LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx | 6 | 5 | lateral-movement (3), discovery (1), privilege-escalation (1) |
| LM_renamed_psexecsvc_5145.evtx | 22 | 18 | discovery (9), lateral-movement (9) |
| LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx | 9 | 9 | lateral-movement (8), defense-evasion (1) |
| LM_sysmon_3_12_13_1_SharpRDP.evtx | 38 | 37 | lateral-movement (28), execution (6), defense-evasion (2), privilege-escalation (1) |
| LM_sysmon_3_DCOM_ShellBrowserWindow_ShellWindows.evtx | 3 | 3 | lateral-movement (3) |
| LM_sysmon_psexec_smb_meterpreter.evtx | 10 | 10 | lateral-movement (6), discovery (1), persistence (1), privilege-escalation (1), command-and-control (1) |
| LM_sysmon_remote_task_src_powershell.evtx | 3 | 2 | discovery (2) |
| LM_tsclient_startup_folder.evtx | 4 | 1 | persistence (1) |
| LM_typical_IIS_webshell_sysmon_1_10_traces.evtx | 4 | 3 | privilege-escalation (2), discovery (1) |
| LM_winrm_exec_sysmon_1_winrshost.evtx | 3 | 3 | lateral-movement (2), defense-evasion (1) |
| LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx | 1 | 1 | lateral-movement (1) |
| LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx | 15 | 15 | lateral-movement (14), execution (1) |
| LM_wmiexec_impacket_sysmon_whoami.evtx | 7 | 6 | lateral-movement (5), discovery (1) |
| LM_xp_cmdshell_MSSQL_Events.evtx | 21 | 21 | lateral-movement (17), defense-evasion (4) |
| MSSQL_15281_xp_cmdshell_exec_failed_attempt.evtx | 1 | 1 | lateral-movement (1) |
| RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx | 6 | 6 | lateral-movement (6) |
| dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx | 40 | 40 | lateral-movement (40) |
| lateral_movement_startup_3_11.evtx | 2 | 2 | persistence (1), lateral-movement (1) |
| lm_remote_registry_sysmon_1_13_3.evtx | 4 | 3 | privilege-escalation (1), persistence (1), lateral-movement (1) |
| lm_sysmon_18_remshell_over_namedpipe.evtx | 7 | 7 | lateral-movement (3), privilege-escalation (2), discovery (1), persistence (1) |
| net_share_drive_5142.evtx | 2 | 2 | defense-evasion (1), lateral-movement (1) |
| powercat_revShell_sysmon_1_3.evtx | 9 | 9 | lateral-movement (5), privilege-escalation (3), execution (1) |
| remote task update 4624 4702 same logonid.evtx | 8 | 3 | defense-evasion (1), privilege-escalation (1), lateral-movement (1) |
| remote_file_copy_system_proc_file_write_sysmon_11.evtx | 2 | 2 | privilege-escalation (2) |
| sharprdp_sysmon_7_mstscax.dll.evtx | 4 | 3 | execution (3) |
| smb_bi_auth_conn_spoolsample.evtx | 2 | 1 | discovery (1) |
| smbmap_upload_exec_sysmon.evtx | 27 | 20 | lateral-movement (11), persistence (8), privilege-escalation (1) |
| spoolsample_5145.evtx | 1 | 1 | discovery (1) |
| sysmon_1_exec_via_sql_xpcmdshell.evtx | 1 | 1 | persistence (1) |
| wmi_remote_registry_sysmon.evtx | 13 | 2 | persistence (1), lateral-movement (1) |

## 30 event điểm cao nhất

| File | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| lm_sysmon_18_remshell_over_namedpipe.evtx | Sysmon 1 | powershell.exe | 1.00 | lateral-movement (0.49) | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -s -NoLogo -NoProfile |
| LM_sysmon_psexec_smb_meterpreter.evtx | Sysmon 1 | powershell.exe | 1.00 | lateral-movement (0.59) | "powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.G |
| LM_sysmon_psexec_smb_meterpreter.evtx | Sysmon 1 | powershell.exe | 1.00 | lateral-movement (0.58) | powershell.exe  -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:windir+'\syswow64\Win |
| LM_impacket_docmexec_mmc_sysmon_01.evtx | Sysmon 1 | cmd.exe | 1.00 | lateral-movement (0.70) | "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| powercat_revShell_sysmon_1_3.evtx | Sysmon 3 | powershell.exe | 1.00 | lateral-movement (0.48) |  |
| LM_impacket_docmexec_mmc_sysmon_01.evtx | Sysmon 1 | cmd.exe | 1.00 | lateral-movement (0.80) | "C:\Windows\System32\cmd.exe" /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| LM_impacket_docmexec_mmc_sysmon_01.evtx | Sysmon 1 | cmd.exe | 1.00 | lateral-movement (0.87) | "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx | Sysmon 3 | mshta.exe | 1.00 | defense-evasion (0.93) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.98) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.98) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.99) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.98) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (0.98) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
| LM_5145_Remote_FileCopy.evtx | Security-Auditing 5145 |  | 1.00 | lateral-movement (1.00) |  |
