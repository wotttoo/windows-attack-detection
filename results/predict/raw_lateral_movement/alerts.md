# Cảnh báo

- 1,288 event đầu vào, 1,235 event bị báo độc hại → **68 cảnh báo**
- nối event: cùng cây process / PID / phiên đăng nhập trên cùng máy, hoặc cách nhau ≤ 60s; cắt khi lặng > 1800s
- mức độ: high 28, medium 37, low 3

## Danh sách

| ID | Mức | Máy | Bắt đầu | Thời lượng | Event | Chuỗi tactic | Process chính | p max |
|---|---|---|---|---|---|---|---|---|
| A0001 | high | IEWIN7 | 2019-04-30 20:26:51 | 2s | 10 | lateral-movement → discovery → persistence → privilege-escalation → command-and-control | powershell.exe (4) | 1.00 |
| A0002 | high | IEWIN7 | 2019-04-30 20:35:11 | 2s | 8 | lateral-movement → persistence → defense-evasion → discovery | cmd.exe (3) | 1.00 |
| A0003 | high | IEWIN7 | 2019-04-29 20:59:14 | 41s | 7 | lateral-movement → discovery → privilege-escalation → persistence | system (2) | 1.00 |
| A0004 | high | IEWIN7 | 2019-06-20 08:07:42 | 16s | 9 | lateral-movement → privilege-escalation → execution | cmd.exe (2) | 1.00 |
| A0005 | high | IEWIN7 | 2019-05-14 01:29:00 | 4s | 2 | defense-evasion → execution | mshta.exe (2) | 1.00 |
| A0006 | high | PC01.example.corp | 2019-03-18 11:06:25 | 1258s | 9 | defense-evasion → privilege-escalation → persistence | wmic.exe (3) | 1.00 |
| A0007 | high | MSEDGEWIN10 | 2021-04-20 20:32:55 | 77s | 8 | lateral-movement → privilege-escalation → discovery → execution | powershell.exe (2) | 1.00 |
| A0008 | high | IEWIN7 | 2019-04-30 20:32:49 | 2s | 6 | lateral-movement → discovery | cmd.exe (3) | 1.00 |
| A0009 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-19 00:02:00 | 17s | 30 | defense-evasion → privilege-escalation → discovery → lateral-movement → execution | - (4) | 1.00 |
| A0010 | high | MSEDGEWIN10 | 2020-07-10 10:20:33 | 25s | 9 | lateral-movement → defense-evasion | explorer.exe (5) | 1.00 |
| A0011 | high | MSEDGEWIN10 | 2020-01-14 20:48:13 | 32s | 7 | lateral-movement → execution | wmiprvse.exe (2) | 1.00 |
| A0012 | high | DC1.insecurebank.local | 2019-05-16 01:31:36 | 0s | 3 | lateral-movement → defense-evasion | winrshost.exe (1) | 1.00 |
| A0013 | high | IEWIN7 | 2019-05-24 01:33:53 | 0s | 3 | privilege-escalation → discovery | cmd.exe (1) | 1.00 |
| A0014 | high | MSEDGEWIN10 | 2019-11-04 09:27:25 | 1s | 21 | lateral-movement → defense-evasion |  | 1.00 |
| A0015 | high | MSEDGEWIN10 | 2020-07-09 22:00:09 | 57s | 33 | lateral-movement → execution | explorer.exe (19) | 1.00 |
| A0016 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-18 22:15:49 | 0s | 6 | discovery → defense-evasion → lateral-movement → privilege-escalation | - (4) | 0.99 |
| A0017 | high | IEWIN7 | 2019-01-19 12:57:09 | 33s | 10 | discovery → lateral-movement |  | 0.99 |
| A0018 | high | MSEDGEWIN10 | 2020-07-09 22:05:55 | 24s | 6 | privilege-escalation → lateral-movement | explorer.exe (5) | 0.99 |
| A0019 | high | IEWIN7 | 2019-01-19 13:00:10 | 0s | 8 | lateral-movement → discovery |  | 0.99 |
| A0020 | high | MSEDGEWIN10 | 2020-12-09 22:45:33 | 0s | 2 | lateral-movement → persistence | <unknown process> (1) | 0.99 |
| A0021 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-19 00:41:28 | 0s | 2 | discovery → lateral-movement |  | 0.99 |
| A0022 | high | PC01.example.corp | 2019-02-16 17:54:26 | 14s | 4 | lateral-movement → discovery |  | 0.99 |
| A0023 | high | PC01.example.corp | 2019-02-16 17:55:47 | 14s | 4 | lateral-movement → discovery |  | 0.99 |
| A0024 | high | PC01.example.corp | 2019-02-16 17:57:41 | 14s | 4 | lateral-movement → discovery |  | 0.99 |
| A0025 | high | MSEDGEWIN10 | 2020-10-17 22:52:29 | 37s | 20 | lateral-movement → persistence → privilege-escalation | system (10) | 0.97 |
| A0026 | high | MSEDGEWIN10 | 2020-12-10 11:18:54 | 0s | 2 | persistence → lateral-movement | wmiprvse.exe (2) | 0.95 |
| A0027 | high | 02694w-win10.threebeesco.com | 2020-10-06 22:11:17 | 0s | 5 | lateral-movement → discovery → privilege-escalation | system (3) | 0.92 |
| A0028 | high | MSEDGEWIN10 | 2020-10-13 23:06:02 | 0s | 3 | lateral-movement | svchost.exe (3) | 0.92 |
| A0029 | medium | PC01.example.corp | 2019-03-18 14:23:22 | 48s | 869 | lateral-movement |  | 1.00 |
| A0030 | medium | MSEDGEWIN10 | 2020-12-15 15:00:14 | 0s | 2 | discovery | powershell.exe (2) | 1.00 |
| A0031 | medium | MSEDGEWIN10 | 2020-01-14 20:46:39 | 4s | 4 | lateral-movement | wmiprvse.exe (1) | 1.00 |
| A0032 | medium | MSEDGEWIN10 | 2020-01-14 20:44:46 | 5s | 4 | lateral-movement | wmiprvse.exe (1) | 1.00 |
| A0033 | medium | MSEDGEWIN10 | 2019-11-03 13:51:56 | 0s | 1 | persistence | cmd.exe (1) | 1.00 |
| A0034 | medium | MSEDGEWIN10 | 2020-07-09 22:02:42 | 0s | 1 | defense-evasion | mmc.exe (1) | 1.00 |
| A0035 | medium | MSEDGEWIN10 | 2020-07-09 22:07:33 | 0s | 1 | defense-evasion | mmc.exe (1) | 1.00 |
| A0036 | medium | MSEDGEWIN10 | 2020-11-13 11:40:43 | 96s | 17 | lateral-movement |  | 1.00 |
| A0037 | medium | MSEDGEWIN10 | 2020-11-13 11:47:42 | 97s | 10 | lateral-movement |  | 1.00 |
| A0038 | medium | MSEDGEWIN10 | 2020-11-13 11:09:07 | 59s | 8 | lateral-movement |  | 1.00 |
| A0039 | medium | MSEDGEWIN10 | 2020-11-13 11:20:28 | 13s | 5 | lateral-movement |  | 1.00 |
| A0040 | medium | alice.insecurebank.local | 2019-05-14 14:04:05 | 0s | 1 | persistence | mstsc.exe (1) | 1.00 |
| A0041 | medium | DC1.insecurebank.local | 2019-05-16 01:38:19 | 0s | 1 | lateral-movement | hostname.exe (1) | 0.99 |
| A0042 | medium | PC01.example.corp | 2019-02-16 18:19:18 | 0s | 18 | lateral-movement |  | 0.99 |
| A0043 | medium | 04246w-win10.threebeesco.com | 2020-08-27 11:40:56 | 0s | 2 | privilege-escalation | system (1) | 0.99 |
| A0044 | medium | IEWIN7 | 2019-05-20 15:54:31 | 1s | 6 | lateral-movement |  | 0.99 |
| A0045 | medium | MSEDGEWIN10 | 2019-09-01 11:54:22 | 0s | 1 | discovery |  | 0.98 |
| A0046 | medium | IEWIN7 | 2019-07-03 20:10:06 | 0s | 1 | execution | reg.exe (1) | 0.98 |
| A0047 | medium | MSEDGEWIN10 | 2020-07-09 21:49:03 | 49s | 4 | lateral-movement |  | 0.98 |
| A0048 | medium | MSEDGEWIN10 | 2020-07-09 21:55:18 | 46s | 4 | lateral-movement |  | 0.98 |
| A0049 | medium | MSEDGEWIN10 | 2020-07-09 21:28:47 | 37s | 3 | lateral-movement |  | 0.98 |
| A0050 | medium | MSEDGEWIN10 | 2020-07-09 19:47:00 | 0s | 1 | lateral-movement |  | 0.98 |
| A0051 | medium | MSEDGEWIN10 | 2020-07-09 20:06:31 | 0s | 1 | lateral-movement |  | 0.98 |
| A0052 | medium | MSEDGEWIN10 | 2020-07-09 20:43:29 | 0s | 1 | lateral-movement |  | 0.98 |
| A0053 | medium | MSEDGEWIN10 | 2020-07-09 21:07:05 | 0s | 1 | lateral-movement |  | 0.98 |
| A0054 | medium | MSEDGEWIN10 | 2020-07-09 21:30:53 | 0s | 1 | lateral-movement |  | 0.98 |
| A0055 | medium | IEWIN7 | 2019-05-14 00:32:19 | 15s | 2 | lateral-movement | explorer.exe (2) | 0.97 |
| A0056 | medium | IEWIN7 | 2019-05-14 00:29:48 | 0s | 1 | lateral-movement | explorer.exe (1) | 0.97 |
| A0057 | medium | MSEDGEWIN10 | 2020-01-23 19:09:33 | 0s | 3 | execution | sharprdp.exe (3) | 0.97 |
| A0058 | medium | MSEDGEWIN10 | 2019-08-30 23:16:28 | 0s | 1 | discovery | system (1) | 0.92 |
| A0059 | medium | WIN-77LTAPHIQ1R.example.corp | 2019-03-03 09:24:24 | 0s | 1 | lateral-movement |  | 0.89 |
| A0060 | medium | WIN-77LTAPHIQ1R.example.corp | 2019-03-03 09:20:28 | 0s | 1 | lateral-movement |  | 0.88 |
| A0061 | medium | PC04.example.corp | 2019-03-17 19:26:42 | 228s | 2 | defense-evasion → lateral-movement |  | 0.88 |
| A0062 | medium | MSEDGEWIN10 | 2020-12-04 22:41:04 | 0s | 3 | lateral-movement → privilege-escalation → persistence | svchost.exe (2) | 0.87 |
| A0063 | medium | MSEDGEWIN10 | 2020-02-28 22:35:55 | 13s | 4 | lateral-movement |  | 0.86 |
| A0064 | medium | DC1.insecurebank.local | 2019-05-16 01:33:54 | 0s | 1 | lateral-movement |  | 0.85 |
| A0065 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-02 11:47:39 | 9s | 3 | defense-evasion → privilege-escalation → lateral-movement | - (1) | 0.85 |
| A0066 | low | 02694w-win10.threebeesco.com | 2020-10-06 21:40:30 | 12s | 2 | lateral-movement | lsass.exe (2) | 0.79 |
| A0067 | low | LAPTOP-JU4M3I0E | 2020-08-03 08:11:51 | 0s | 1 | lateral-movement |  | 0.78 |
| A0068 | low | MSEDGEWIN10 | 2020-07-10 02:19:35 | 0s | 1 | lateral-movement | svchost.exe (1) | 0.62 |

## Chi tiết

### A0001 · high · IEWIN7

- thời gian: 2019-04-30 20:26:51 → 20:26:53 UTC, 10 event, 5 process
- tactic: lateral-movement (6); discovery (1); persistence (1); privilege-escalation (1); command-and-control (1)
- process: powershell.exe (4), services.exe (3), system (2), cmd.exe (1); user: SYSTEM
- file log: LM_sysmon_psexec_smb_meterpreter.evtx
- **vì sao báo:**
  - khoá cấu hình service (`k_services`, 3 event)
  - lệnh mã hoá base64 (`f_encoded`, 3 event)
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 3 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:26:52 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | "powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Obj |
| 20:26:51 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | powershell.exe  -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:w |
| 20:26:51 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]: |
| 20:26:52 | Sysmon 10 | powershell.exe | 1.00 | privilege-escalation |  |
| 20:26:52 | Sysmon 3 | powershell.exe | 0.95 | command-and-control |  |

### A0002 · high · IEWIN7

- thời gian: 2019-04-30 20:35:11 → 20:35:13 UTC, 8 event, 6 process
- tactic: lateral-movement (5); persistence (1); defense-evasion (1); discovery (1)
- process: cmd.exe (3), system (2), mmc.exe (2), whoami.exe (1); user: IEUser, SYSTEM
- file log: LM_impacket_docmexec_mmc_sysmon_01.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 4 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:35:12 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:13 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:13 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:11 | Sysmon 3 | mmc.exe | 1.00 | defense-evasion |  |
| 20:35:13 | Sysmon 1 | whoami.exe | 1.00 | lateral-movement | whoami  /all  |

### A0003 · high · IEWIN7

- thời gian: 2019-04-29 20:59:14 → 20:59:55 UTC, 7 event, 5 process
- tactic: lateral-movement (3); privilege-escalation (2); discovery (1); persistence (1)
- process: system (2), powershell.exe (2), whoami.exe (1), slui.exe (1); user: IEUser, SYSTEM
- file log: lm_sysmon_18_remshell_over_namedpipe.evtx
- **vì sao báo:**
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 2 event)
  - mở process với toàn quyền (`b_full_access`, 2 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 2 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:59:21 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -s -NoLogo -NoProfile |
| 20:59:22 | Sysmon 1 | whoami.exe | 1.00 | lateral-movement | "C:\Windows\system32\whoami.exe"  /all |
| 20:59:22 | Sysmon 10 | powershell.exe | 0.99 | persistence |  |
| 20:59:14 | Sysmon 3 | system | 0.92 | discovery |  |
| 20:59:14 | Sysmon 18 | system | 0.90 | lateral-movement |  |

### A0004 · high · IEWIN7

- thời gian: 2019-06-20 08:07:42 → 08:07:58 UTC, 9 event, 6 process
- tactic: lateral-movement (5); privilege-escalation (3); execution (1)
- process: cmd.exe (2), netstat.exe (1), powershell.exe (1), whoami.exe (1), systeminfo.exe (1); user: IEUser
- file log: powercat_revShell_sysmon_1_3.evtx
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 3 event)
  - mở process với toàn quyền (`b_full_access`, 3 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 08:07:48 | Sysmon 3 | powershell.exe | 1.00 | lateral-movement |  |
| 08:07:42 | Sysmon 1 | netstat.exe | 1.00 | lateral-movement | "C:\Windows\system32\NETSTAT.EXE"  -na |
| 08:07:52 | Sysmon 1 | whoami.exe | 1.00 | execution | whoami |
| 08:07:48 | Sysmon 1 | cmd.exe | 0.99 | lateral-movement | "cmd" |
| 08:07:48 | Sysmon 1 | cmd.exe | 0.99 | lateral-movement | "cmd" |

### A0005 · high · IEWIN7

- thời gian: 2019-05-14 01:29:00 → 01:29:04 UTC, 2 event, 1 process
- tactic: defense-evasion (1); execution (1)
- process: mshta.exe (2); user: IEUser
- file log: LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 01:29:00 | Sysmon 3 | mshta.exe | 1.00 | defense-evasion |  |
| 01:29:04 | Sysmon 1 | mshta.exe | 1.00 | execution | C:\Windows\System32\mshta.exe -Embedding |

### A0006 · high · PC01.example.corp

- thời gian: 2019-03-18 11:06:25 → 11:27:23 UTC, 9 event, 6 process
- tactic: privilege-escalation (4); defense-evasion (3); persistence (2)
- process: wmic.exe (3), svchost.exe (1), cmd.exe (1), conhost.exe (1), dllhost.exe (1); user: PC01$, user01
- file log: LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx, LM_WMIC_4648_rpcss.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:27:05 | Security 4688 | wmic.exe | 1.00 | defense-evasion |  |
| 11:06:29 | Security 4688 | cmd.exe | 1.00 | privilege-escalation |  |
| 11:06:29 | Security 4624 | svchost.exe | 1.00 | privilege-escalation |  |
| 11:27:23 | Security 4648 | wmic.exe | 0.99 | persistence |  |
| 11:27:23 | Security 4648 | wmic.exe | 0.99 | persistence |  |

### A0007 · high · MSEDGEWIN10

- thời gian: 2021-04-20 20:32:55 → 20:34:11 UTC, 8 event, 6 process
- tactic: lateral-movement (3); privilege-escalation (3); discovery (1); execution (1)
- process: powershell.exe (2), <unknown process> (2), - (1), system (1), cmd.exe (1); user: IEUser, user03
- file log: ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx
- **vì sao báo:**
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 2 event)
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:33:59 | Sysmon 3 | powershell.exe | 1.00 | privilege-escalation |  |
| 20:32:55 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile |
| 20:33:00 | Sysmon 1 | cmd.exe | 0.99 | lateral-movement | C:\Windows\System32\cmd.exe |
| 20:33:00 | Security 5145 |  | 0.97 | lateral-movement |  |
| 20:33:00 | Sysmon 18 | system | 0.95 | discovery |  |

### A0008 · high · IEWIN7

- thời gian: 2019-04-30 20:32:49 → 20:32:51 UTC, 6 event, 5 process
- tactic: lateral-movement (5); discovery (1)
- process: cmd.exe (3), system (2), whoami.exe (1); user: IEUser, SYSTEM
- file log: LM_wmiexec_impacket_sysmon_whoami.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 4 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 3 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:32:51 | Sysmon 1 | whoami.exe | 1.00 | lateral-movement | whoami  /all  |
| 20:32:51 | Sysmon 1 | cmd.exe | 0.98 | lateral-movement | cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1 |
| 20:32:51 | Sysmon 1 | cmd.exe | 0.98 | lateral-movement | cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1 |
| 20:32:51 | Sysmon 1 | cmd.exe | 0.98 | lateral-movement | cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656369.7 2>&1 |
| 20:32:51 | Sysmon 3 | system | 0.97 | discovery |  |

### A0009 · high · WIN-77LTAPHIQ1R.example.corp

- thời gian: 2019-03-19 00:02:00 → 00:02:17 UTC, 30 event, 7 process
- tactic: lateral-movement (9); discovery (8); privilege-escalation (7); defense-evasion (4); execution (2)
- process: - (4), lsass.exe (3), cmd.exe (1), conhost.exe (1), tasklist.exe (1), wmiprvse.exe (1); user: ANONYMOUS LOGON, Administrator, WIN-77LTAPHIQ1R$, administrator
- file log: LM_ScheduledTask_ATSVC_target_host.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 9 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 00:02:04 | Security 4688 | cmd.exe | 1.00 | privilege-escalation |  |
| 00:02:04 | Security 4688 | tasklist.exe | 1.00 | privilege-escalation |  |
| 00:02:17 | Security 4661 | lsass.exe | 1.00 | discovery |  |
| 00:02:17 | Security 4661 | lsass.exe | 1.00 | discovery |  |
| 00:02:04 | Security 4624 | - | 0.99 | defense-evasion |  |

### A0010 · high · MSEDGEWIN10

- thời gian: 2020-07-10 10:20:33 → 10:20:58 UTC, 9 event, 5 process
- tactic: lateral-movement (8); defense-evasion (1)
- process: explorer.exe (5), rdpclip.exe (1), a.exe (1), mmc.exe (1); user: IEUser
- file log: DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx, LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 10:20:58 | Sysmon 12 | mmc.exe | 1.00 | defense-evasion |  |
| 10:20:37 | Sysmon 1 | a.exe | 0.99 | lateral-movement | "\\tsclient\c\temp\stack\a.exe"  |
| 10:20:33 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 10:20:37 | Sysmon 13 | explorer.exe | 0.95 | lateral-movement |  |
| 10:20:37 | Sysmon 13 | explorer.exe | 0.94 | lateral-movement |  |

### A0011 · high · MSEDGEWIN10

- thời gian: 2020-01-14 20:48:13 → 20:48:45 UTC, 7 event, 6 process
- tactic: lateral-movement (6); execution (1)
- process: wmiprvse.exe (2), cmd.exe (2), explorer.exe (2), notepad.exe (1); user: IEUser
- file log: LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx
- **vì sao báo:**
  - khoá dùng để vượt UAC (`k_uac_bypass`, 2 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:48:17 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "cmd.exe" /c notepad.exe |
| 20:48:13 | Sysmon 13 | wmiprvse.exe | 0.99 | lateral-movement |  |
| 20:48:41 | Sysmon 13 | wmiprvse.exe | 0.99 | lateral-movement |  |
| 20:48:45 | Sysmon 1 | explorer.exe | 0.95 | execution | C:\Windows\explorer.exe /factory,{75dff2b7-6936-4c06-a8bb-676a7b00b24b} -Embedding |
| 20:48:17 | Sysmon 1 | notepad.exe | 0.94 | lateral-movement | notepad.exe |

### A0012 · high · DC1.insecurebank.local

- thời gian: 2019-05-16 01:31:36 → 01:31:36 UTC, 3 event, 3 process
- tactic: lateral-movement (2); defense-evasion (1)
- process: winrshost.exe (1), cmd.exe (1), ipconfig.exe (1); user: Administrator
- file log: LM_winrm_exec_sysmon_1_winrshost.evtx
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 01:31:36 | Sysmon 1 | winrshost.exe | 1.00 | lateral-movement | C:\Windows\system32\WinrsHost.exe -Embedding |
| 01:31:36 | Sysmon 1 | ipconfig.exe | 1.00 | defense-evasion | ipconfig |
| 01:31:36 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | C:\Windows\system32\cmd.exe /C ipconfig |

### A0013 · high · IEWIN7

- thời gian: 2019-05-24 01:33:53 → 01:33:53 UTC, 3 event, 3 process
- tactic: privilege-escalation (2); discovery (1)
- process: cmd.exe (1), net.exe (1), net1.exe (1); user: DefaultAppPool
- file log: LM_typical_IIS_webshell_sysmon_1_10_traces.evtx
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 01:33:53 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | "c:\windows\system32\cmd.exe" /c net user |
| 01:33:53 | Sysmon 1 | net.exe | 0.98 | privilege-escalation | net  user |
| 01:33:53 | Sysmon 1 | net1.exe | 0.83 | discovery | C:\Windows\system32\net1  user |

### A0014 · high · MSEDGEWIN10

- thời gian: 2019-11-04 09:27:25 → 09:27:27 UTC, 21 event, 1 process
- tactic: lateral-movement (17); defense-evasion (4)
- process: 
- file log: LM_xp_cmdshell_MSSQL_Events.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 09:27:26 | MSSQLSERVER 15457 |  | 1.00 | defense-evasion |  |
| 09:27:26 | MSSQLSERVER 15457 |  | 1.00 | defense-evasion |  |
| 09:27:26 | MSSQLSERVER 18454 |  | 1.00 | lateral-movement |  |
| 09:27:25 | MSSQLSERVER 18454 |  | 1.00 | lateral-movement |  |
| 09:27:25 | MSSQLSERVER 18454 |  | 1.00 | lateral-movement |  |

### A0015 · high · MSEDGEWIN10

- thời gian: 2020-07-09 22:00:09 → 22:01:06 UTC, 33 event, 9 process
- tactic: lateral-movement (27); execution (6)
- process: explorer.exe (19), svchost.exe (4), notepad.exe (4), cmd.exe (1), powershell.exe (1); user: IEUser, NETWORK SERVICE
- file log: DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx, LM_sysmon_3_12_13_1_SharpRDP.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:00:45 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\system32\cmd.exe"  |
| 22:01:03 | Sysmon 1 | powershell.exe | 0.99 | execution | "C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe"  |
| 22:00:17 | Sysmon 13 | explorer.exe | 0.99 | lateral-movement |  |
| 22:00:40 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 22:00:10 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |

### A0016 · high · WIN-77LTAPHIQ1R.example.corp

- thời gian: 2019-03-18 22:15:49 → 22:15:49 UTC, 6 event, 3 process
- tactic: discovery (2); lateral-movement (2); defense-evasion (1); privilege-escalation (1)
- process: - (4), wmiprvse.exe (1), calc.exe (1); user: Administrator, WIN-77LTAPHIQ1R$, user01
- file log: LM_WMI_4624_4688_TargetHost.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:15:49 | Security 4624 | - | 0.99 | defense-evasion |  |
| 22:15:49 | Security 4688 | calc.exe | 0.99 | privilege-escalation |  |
| 22:15:49 | Security 4624 | - | 0.98 | discovery |  |
| 22:15:49 | Security 4624 | - | 0.98 | discovery |  |
| 22:15:49 | Security 4688 | wmiprvse.exe | 0.96 | lateral-movement |  |

### A0017 · high · IEWIN7

- thời gian: 2019-01-19 12:57:09 → 12:57:42 UTC, 10 event, 1 process
- tactic: discovery (7); lateral-movement (3)
- process: ; user: IEUser
- file log: LM_renamed_psexecsvc_5145.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 10 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 12:57:40 | Security 5145 |  | 0.99 | lateral-movement |  |
| 12:57:30 | Security 5145 |  | 0.99 | lateral-movement |  |
| 12:57:09 | Security 5145 |  | 0.97 | discovery |  |
| 12:57:32 | Security 5145 |  | 0.94 | discovery |  |
| 12:57:41 | Security 5145 |  | 0.94 | discovery |  |

### A0018 · high · MSEDGEWIN10

- thời gian: 2020-07-09 22:05:55 → 22:06:20 UTC, 6 event, 2 process
- tactic: lateral-movement (5); privilege-escalation (1)
- process: explorer.exe (5), cmd.exe (1); user: SYSTEM
- file log: LM_sysmon_3_12_13_1_SharpRDP.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:05:55 | Sysmon 1 | cmd.exe | 0.99 | privilege-escalation | cmd.exe |
| 22:06:20 | Sysmon 13 | explorer.exe | 0.96 | lateral-movement |  |
| 22:06:20 | Sysmon 13 | explorer.exe | 0.95 | lateral-movement |  |
| 22:06:14 | Sysmon 12 | explorer.exe | 0.71 | lateral-movement |  |
| 22:06:20 | Sysmon 12 | explorer.exe | 0.71 | lateral-movement |  |

### A0019 · high · IEWIN7

- thời gian: 2019-01-19 13:00:10 → 13:00:10 UTC, 8 event, 1 process
- tactic: lateral-movement (6); discovery (2)
- process: ; user: IEUser
- file log: LM_renamed_psexecsvc_5145.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 8 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:00:10 | Security 5145 |  | 0.99 | lateral-movement |  |
| 13:00:10 | Security 5145 |  | 0.99 | lateral-movement |  |
| 13:00:10 | Security 5145 |  | 0.99 | lateral-movement |  |
| 13:00:10 | Security 5145 |  | 0.99 | lateral-movement |  |
| 13:00:10 | Security 5145 |  | 0.95 | discovery |  |

### A0020 · high · MSEDGEWIN10

- thời gian: 2020-12-09 22:45:33 → 22:45:33 UTC, 2 event, 1 process
- tactic: lateral-movement (1); persistence (1)
- process: <unknown process> (1), system (1)
- file log: lateral_movement_startup_3_11.evtx
- **vì sao báo:**
  - thư mục Startup (`k_startup_dir`, 1 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:45:33 | Sysmon 11 | system | 0.99 | persistence |  |
| 22:45:33 | Sysmon 3 | <unknown process> | 0.82 | lateral-movement |  |

### A0021 · high · WIN-77LTAPHIQ1R.example.corp

- thời gian: 2019-03-19 00:41:28 → 00:41:29 UTC, 2 event, 1 process
- tactic: discovery (1); lateral-movement (1)
- process: ; user: Administrator
- file log: LM_Remote_Service01_5145_svcctl.evtx, LM_Remote_Service02_7045.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 1 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 00:41:28 | Security 5145 |  | 0.99 | discovery |  |
| 00:41:29 | Service Control Manager 7045 |  | 0.70 | lateral-movement |  |

### A0022 · high · PC01.example.corp

- thời gian: 2019-02-16 17:54:26 → 17:54:41 UTC, 4 event, 1 process
- tactic: lateral-movement (3); discovery (1)
- process: ; user: IEUser
- file log: LM_REMCOM_5145_TargetHost.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 4 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:54:26 | Security 5145 |  | 0.99 | lateral-movement |  |
| 17:54:26 | Security 5145 |  | 0.99 | lateral-movement |  |
| 17:54:26 | Security 5145 |  | 0.92 | lateral-movement |  |
| 17:54:41 | Security 5145 |  | 0.92 | discovery |  |

### A0023 · high · PC01.example.corp

- thời gian: 2019-02-16 17:55:47 → 17:56:01 UTC, 4 event, 1 process
- tactic: lateral-movement (3); discovery (1)
- process: ; user: IEUser
- file log: LM_REMCOM_5145_TargetHost.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 4 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:55:47 | Security 5145 |  | 0.99 | lateral-movement |  |
| 17:55:47 | Security 5145 |  | 0.99 | lateral-movement |  |
| 17:55:47 | Security 5145 |  | 0.92 | lateral-movement |  |
| 17:56:01 | Security 5145 |  | 0.92 | discovery |  |

### A0024 · high · PC01.example.corp

- thời gian: 2019-02-16 17:57:41 → 17:57:55 UTC, 4 event, 1 process
- tactic: lateral-movement (3); discovery (1)
- process: ; user: IEUser
- file log: LM_REMCOM_5145_TargetHost.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 4 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:57:41 | Security 5145 |  | 0.99 | lateral-movement |  |
| 17:57:41 | Security 5145 |  | 0.99 | lateral-movement |  |
| 17:57:41 | Security 5145 |  | 0.92 | lateral-movement |  |
| 17:57:55 | Security 5145 |  | 0.92 | discovery |  |

### A0025 · high · MSEDGEWIN10

- thời gian: 2020-10-17 22:52:29 → 22:53:05 UTC, 20 event, 5 process
- tactic: lateral-movement (11); persistence (8); privilege-escalation (1)
- process: system (10), lsass.exe (7), cmd.exe (3); user: Administrator, SYSTEM
- file log: smbmap_upload_exec_sysmon.evtx
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 7 event) ⚠
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 3 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 3 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:52:34 | Sysmon 11 | system | 0.97 | persistence |  |
| 22:53:05 | Sysmon 1 | cmd.exe | 0.96 | lateral-movement | cmd.exe /Q /c cd  1> \\127.0.0.1\C$\WqEVwJZYOe 2>&1 |
| 22:53:05 | Sysmon 1 | cmd.exe | 0.96 | lateral-movement | cmd.exe /Q /c cd \ 1> \\127.0.0.1\C$\WqEVwJZYOe 2>&1 |
| 22:53:05 | Sysmon 1 | cmd.exe | 0.94 | lateral-movement | cmd.exe /Q /c c:\windows\system32\rundll32.exe c:\programdata\7okjer,#1 1> \\127.0.0.1\C$\WqEVwJZYOe |
| 22:53:04 | Sysmon 13 | lsass.exe | 0.94 | persistence |  |

### A0026 · high · MSEDGEWIN10

- thời gian: 2020-12-10 11:18:54 → 11:18:54 UTC, 2 event, 1 process
- tactic: persistence (1); lateral-movement (1)
- process: wmiprvse.exe (2); user: LOCAL SERVICE
- file log: wmi_remote_registry_sysmon.evtx
- **vì sao báo:**
  - khoá Run / RunOnce (`k_run`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:18:54 | Sysmon 1 | wmiprvse.exe | 0.95 | persistence | C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding |
| 11:18:54 | Sysmon 13 | wmiprvse.exe | 0.92 | lateral-movement |  |

### A0027 · high · 02694w-win10.threebeesco.com

- thời gian: 2020-10-06 22:11:17 → 22:11:17 UTC, 5 event, 2 process
- tactic: lateral-movement (3); discovery (1); privilege-escalation (1)
- process: system (3), svchost.exe (2); user: SYSTEM
- file log: LM_regsvc_DirectoryServiceExtPt_Lsass_NTDS_AdamXpn.evtx
- **vì sao báo:**
  - khoá cấu hình service (`k_services`, 2 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:11:17 | Sysmon 18 | system | 0.92 | discovery |  |
| 22:11:17 | Sysmon 13 | svchost.exe | 0.74 | lateral-movement |  |
| 22:11:17 | Sysmon 3 | system | 0.72 | lateral-movement |  |
| 22:11:17 | Sysmon 3 | system | 0.72 | lateral-movement |  |
| 22:11:17 | Sysmon 12 | svchost.exe | 0.62 | privilege-escalation |  |

### A0028 · high · MSEDGEWIN10

- thời gian: 2020-10-13 23:06:02 → 23:06:02 UTC, 3 event, 1 process
- tactic: lateral-movement (3)
- process: svchost.exe (3)
- file log: LM_NewShare_Added_Sysmon_12_13.evtx
- **vì sao báo:**
  - khoá cấu hình service (`k_services`, 3 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 2 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 23:06:02 | Sysmon 13 | svchost.exe | 0.92 | lateral-movement |  |
| 23:06:02 | Sysmon 13 | svchost.exe | 0.55 | lateral-movement |  |
| 23:06:02 | Sysmon 12 | svchost.exe | 0.51 | lateral-movement |  |

### A0029 · medium · PC01.example.corp

- thời gian: 2019-03-18 14:23:22 → 14:24:10 UTC, 869 event, 1 process
- tactic: lateral-movement (869)
- process: ; user: Administrator
- file log: LM_5145_Remote_FileCopy.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 869 event)
  - thư mục Startup (`k_startup_dir`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 14:23:23 | Security 5145 |  | 1.00 | lateral-movement |  |
| 14:23:25 | Security 5145 |  | 1.00 | lateral-movement |  |
| 14:23:25 | Security 5145 |  | 1.00 | lateral-movement |  |
| 14:23:23 | Security 5145 |  | 1.00 | lateral-movement |  |
| 14:23:23 | Security 5145 |  | 1.00 | lateral-movement |  |

### A0030 · medium · MSEDGEWIN10

- thời gian: 2020-12-15 15:00:14 → 15:00:14 UTC, 2 event, 1 process
- tactic: discovery (2)
- process: powershell.exe (2); user: IEUser
- file log: LM_sysmon_remote_task_src_powershell.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 15:00:14 | Sysmon 3 | powershell.exe | 1.00 | discovery |  |
| 15:00:14 | Sysmon 3 | powershell.exe | 1.00 | discovery |  |

### A0031 · medium · MSEDGEWIN10

- thời gian: 2020-01-14 20:46:39 → 20:46:43 UTC, 4 event, 4 process
- tactic: lateral-movement (4)
- process: wmiprvse.exe (1), rundll32.exe (1), cmd.exe (1), notepad.exe (1); user: IEUser
- file log: LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx
- **vì sao báo:**
  - khoá dùng để vượt UAC (`k_uac_bypass`, 1 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:46:43 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "cmd.exe" /c notepad.exe |
| 20:46:43 | Sysmon 1 | rundll32.exe | 0.99 | lateral-movement | rundll32 url.dll,OpenURL ms-browser:// |
| 20:46:39 | Sysmon 13 | wmiprvse.exe | 0.99 | lateral-movement |  |
| 20:46:43 | Sysmon 1 | notepad.exe | 0.94 | lateral-movement | notepad.exe |

### A0032 · medium · MSEDGEWIN10

- thời gian: 2020-01-14 20:44:46 → 20:44:51 UTC, 4 event, 4 process
- tactic: lateral-movement (4)
- process: wmiprvse.exe (1), rundll32.exe (1), cmd.exe (1), notepad.exe (1); user: IEUser
- file log: LM_wmi_PoisonHandler_Mr-Un1k0d3r_sysmon_1_13.evtx
- **vì sao báo:**
  - khoá dùng để vượt UAC (`k_uac_bypass`, 1 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:44:50 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "cmd.exe" /c notepad.exe |
| 20:44:46 | Sysmon 13 | wmiprvse.exe | 0.99 | lateral-movement |  |
| 20:44:50 | Sysmon 1 | rundll32.exe | 0.99 | lateral-movement | rundll32 url.dll,FileProtocolHandler ms-browser:// |
| 20:44:51 | Sysmon 1 | notepad.exe | 0.94 | lateral-movement | notepad.exe |

### A0033 · medium · MSEDGEWIN10

- thời gian: 2019-11-03 13:51:56 → 13:51:56 UTC, 1 event, 1 process
- tactic: persistence (1)
- process: cmd.exe (1); user: sqlsvc
- file log: sysmon_1_exec_via_sql_xpcmdshell.evtx
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:51:56 | Sysmon 1 | cmd.exe | 1.00 | persistence | "C:\Windows\system32\cmd.exe" /c set > c:\users\\public\netstat.txt |

### A0034 · medium · MSEDGEWIN10

- thời gian: 2020-07-09 22:02:42 → 22:02:42 UTC, 1 event, 1 process
- tactic: defense-evasion (1)
- process: mmc.exe (1)
- file log: LM_sysmon_3_12_13_1_SharpRDP.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:02:42 | Sysmon 12 | mmc.exe | 1.00 | defense-evasion |  |

### A0035 · medium · MSEDGEWIN10

- thời gian: 2020-07-09 22:07:33 → 22:07:33 UTC, 1 event, 1 process
- tactic: defense-evasion (1)
- process: mmc.exe (1)
- file log: LM_sysmon_3_12_13_1_SharpRDP.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:07:33 | Sysmon 12 | mmc.exe | 1.00 | defense-evasion |  |

### A0036 · medium · MSEDGEWIN10

- thời gian: 2020-11-13 11:40:43 → 11:42:19 UTC, 17 event, 1 process
- tactic: lateral-movement (17)
- process: 
- file log: dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 4 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:40:45 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:42:18 | RdpCoreTS 168 |  | 1.00 | lateral-movement |  |
| 11:42:19 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:40:43 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 11:41:05 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |

### A0037 · medium · MSEDGEWIN10

- thời gian: 2020-11-13 11:47:42 → 11:49:19 UTC, 10 event, 1 process
- tactic: lateral-movement (10)
- process: 
- file log: dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:47:44 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:49:18 | RdpCoreTS 168 |  | 1.00 | lateral-movement |  |
| 11:49:19 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:47:42 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 11:49:17 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |

### A0038 · medium · MSEDGEWIN10

- thời gian: 2020-11-13 11:09:07 → 11:10:05 UTC, 8 event, 1 process
- tactic: lateral-movement (8)
- process: 
- file log: dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:09:15 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:10:05 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:10:04 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 11:09:07 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 11:10:04 | RdpCoreTS 131 |  | 0.99 | lateral-movement |  |

### A0039 · medium · MSEDGEWIN10

- thời gian: 2020-11-13 11:20:28 → 11:20:41 UTC, 5 event, 1 process
- tactic: lateral-movement (5)
- process: 
- file log: dfir_rdpsharp_target_RdpCoreTs_168_68_131.evtx
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:20:40 | RdpCoreTS 168 |  | 1.00 | lateral-movement |  |
| 11:20:41 | RdpCoreTS 68 |  | 1.00 | lateral-movement |  |
| 11:20:28 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 11:20:38 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 11:20:38 | RdpCoreTS 131 |  | 0.99 | lateral-movement |  |

### A0040 · medium · alice.insecurebank.local

- thời gian: 2019-05-14 14:04:05 → 14:04:05 UTC, 1 event, 1 process
- tactic: persistence (1)
- process: mstsc.exe (1)
- file log: LM_tsclient_startup_folder.evtx
- **vì sao báo:**
  - thư mục Startup (`k_startup_dir`, 1 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 14:04:05 | Sysmon 11 | mstsc.exe | 1.00 | persistence |  |

### A0041 · medium · DC1.insecurebank.local

- thời gian: 2019-05-16 01:38:19 → 01:38:19 UTC, 1 event, 1 process
- tactic: lateral-movement (1)
- process: hostname.exe (1); user: Administrator
- file log: LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx
- **vì sao báo:**
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 01:38:19 | Sysmon 1 | hostname.exe | 0.99 | lateral-movement | "C:\Windows\system32\HOSTNAME.EXE" |

### A0042 · medium · PC01.example.corp

- thời gian: 2019-02-16 18:19:18 → 18:19:18 UTC, 18 event, 1 process
- tactic: lateral-movement (18)
- process: ; user: IEUser
- file log: LM_REMCOM_5145_TargetHost.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 18 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 6 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:19:18 | Security 5145 |  | 0.99 | lateral-movement |  |
| 18:19:18 | Security 5145 |  | 0.99 | lateral-movement |  |
| 18:19:18 | Security 5145 |  | 0.99 | lateral-movement |  |
| 18:19:18 | Security 5145 |  | 0.99 | lateral-movement |  |
| 18:19:18 | Security 5145 |  | 0.99 | lateral-movement |  |

### A0043 · medium · 04246w-win10.threebeesco.com

- thời gian: 2020-08-27 11:40:56 → 11:40:56 UTC, 2 event, 2 process
- tactic: privilege-escalation (2)
- process: system (1), psexesvc.exe (1); user: SYSTEM
- file log: remote_file_copy_system_proc_file_write_sysmon_11.evtx
- **vì sao báo:**
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:40:56 | Sysmon 1 | psexesvc.exe | 0.99 | privilege-escalation | C:\WINDOWS\PSEXESVC.exe |
| 11:40:56 | Sysmon 11 | system | 0.98 | privilege-escalation |  |

### A0044 · medium · IEWIN7

- thời gian: 2019-05-20 15:54:31 → 15:54:32 UTC, 6 event, 1 process
- tactic: lateral-movement (6)
- process: 
- file log: RemotePowerShell_MS_Windows-Remote_Management_EventID_169.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 15:54:31 | WinRM 169 |  | 0.99 | lateral-movement |  |
| 15:54:32 | WinRM 169 |  | 0.99 | lateral-movement |  |
| 15:54:32 | WinRM 169 |  | 0.99 | lateral-movement |  |
| 15:54:31 | WinRM 193 |  | 0.85 | lateral-movement |  |
| 15:54:32 | WinRM 193 |  | 0.85 | lateral-movement |  |

### A0045 · medium · MSEDGEWIN10

- thời gian: 2019-09-01 11:54:22 → 11:54:22 UTC, 1 event, 1 process
- tactic: discovery (1)
- process: ; user: IEUser
- file log: spoolsample_5145.evtx
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:54:22 | Security 5145 |  | 0.98 | discovery |  |

### A0046 · medium · IEWIN7

- thời gian: 2019-07-03 20:10:06 → 20:10:06 UTC, 1 event, 1 process
- tactic: execution (1)
- process: reg.exe (1)
- file log: LM_add_new_namedpipe_tp_nullsession_registry_turla_like_ttp.evtx
- **vì sao báo:**
  - khoá cấu hình service (`k_services`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:10:06 | Sysmon 13 | reg.exe | 0.98 | execution |  |

### A0047 · medium · MSEDGEWIN10

- thời gian: 2020-07-09 21:49:03 → 21:49:52 UTC, 4 event, 1 process
- tactic: lateral-movement (4)
- process: 
- file log: DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 21:49:03 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:49:20 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:49:32 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:49:52 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |

### A0048 · medium · MSEDGEWIN10

- thời gian: 2020-07-09 21:55:18 → 21:56:04 UTC, 4 event, 1 process
- tactic: lateral-movement (4)
- process: 
- file log: DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 21:55:18 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:55:33 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:55:49 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:56:04 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |

### A0049 · medium · MSEDGEWIN10

- thời gian: 2020-07-09 21:28:47 → 21:29:24 UTC, 3 event, 1 process
- tactic: lateral-movement (3)
- process: 
- file log: DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 21:28:47 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:29:04 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |
| 21:29:24 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |

### A0050 · medium · MSEDGEWIN10

- thời gian: 2020-07-09 19:47:00 → 19:47:00 UTC, 1 event, 1 process
- tactic: lateral-movement (1)
- process: 
- file log: DFIR_RDP_Client_TimeZone_RdpCoreTs_104_example.evtx

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 19:47:00 | RdpCoreTS 104 |  | 0.98 | lateral-movement |  |

_Còn 18 cảnh báo, xem alerts.csv._
