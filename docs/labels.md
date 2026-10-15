# Nhãn từng event

| Thư mục | Bộ dữ liệu | Script | Luật |
|---|---|---|---|
| `data/interim/labels/mordor/` | Mordor small/windows | `src/label_events.py` | `configs/label_seeds.yaml` |
| `data/interim/labels/evtx/` | EVTX-ATTACK-SAMPLES | `src/label_evtx.py` | `configs/label_seeds_evtx.yaml` |

```
python src/label_events.py --all data/interim/ossem/mordor --metadata data/raw/mordor/datasets/metadata --out data/interim/labels/mordor
python src/label_evtx.py --all data/interim/ossem/evtx --out data/interim/labels/evtx
```

Cả hai bộ dùng chung các cột nhãn bên dưới. Phần [EVTX](#evtx-attack-samples) ở cuối file mô tả cách gán riêng cho bộ EVTX.

## Cột nhãn (thêm vào mỗi event OSSEM)

| Cột | Giá trị |
|---|---|
| `label` | tactic của file (`lateral-movement`, `credential-access`…), hoặc `command-and-control`, `benign`, `uncertain` |
| `label_malicious` | `1` độc hại / `0` benign / `-1` không chắc (bị bỏ ở `build_dataset.py`) |
| `label_method` | lý do gán nhãn, xem bảng dưới |

| `label_method` | Ý nghĩa |
|---|---|
| `seed:*` | event / process khớp hạt giống (`cmd`, `script`, `event-rule`, `agent-metadata`, `powershell-host`) |
| `sysmon:process-guid` | event Sysmon của process độc hại (gồm process hạt giống, cha khởi chạy, con cháu, process bị inject) |
| `pid:ProcessId`, `pid:ExecutionProcessId` | event Security/PowerShell có PID của process độc hại trên cùng host, lúc process đó còn sống |
| `powershell:host-application` | PowerShell cổ điển có HostApplication là process độc hại |
| `logon-session` | event Security thuộc phiên đăng nhập của process độc hại |
| `network:flow-match` | kết nối mạng trùng 4-tuple với kết nối độc hại, kể cả ở máy bên kia |
| `uncertain:*` | có liên quan nhưng không nối chắc được (thiếu PID, phiên đăng nhập sát thời điểm) |
| `…\|c2:beacon` | PowerShell của vòng liên lạc agent (Start-Sleep, WebClient, RC4, kiểm tra MAC, dựng gói tin…) → `command-and-control` |
| `…\|c2:channel` | kết nối của implant tới cổng C2 (80/443/8080/8443), bind cổng (5158) → `command-and-control` |
| `…\|c2:implant-runtime` | hoạt động nền của implant: nạp DLL, khoá registry, DNS, handle/token, trừ khi chạm lsass/SAM/SECURITY/NTDS → `command-and-control` |
| `background` | không liên quan, nhãn `benign` |
| `file:curated` | (chỉ EVTX) event trong file mẫu đã lọc sẵn, mang tactic của file |
| `evtx:noise` | (chỉ EVTX) khớp luật nhiễu, nhãn `benign` |
| `evtx:lab-artifact` | (chỉ EVTX) dấu vết của người làm mẫu, chủ yếu là xoá log trước khi thử, nhãn `uncertain` |
| `evtx:uncertain-rule` | (chỉ EVTX) khớp luật `uncertain` riêng của file |
| `evtx:keep` | (chỉ EVTX) khớp luật `keep`, luôn mang tactic của file |

## Kết quả (Mordor)

580,520 event (100 file, bỏ 3 file). Thống kê từng file nằm trong `data/interim/labels/mordor/label_report.json`.

| Nhãn | Event |
|---|---|
| benign | 481,328 |
| credential-access | 43,614 |
| command-and-control | 26,457 |
| defense-evasion | 14,048 |
| lateral-movement | 10,643 |
| discovery | 1,561 |
| privilege-escalation | 1,472 |
| persistence | 618 |
| execution | 545 |
| uncertain | 222 |
| collection | 12 |

## Lưu ý khi dùng (Mordor)

- **Cách tách `command-and-control`:** chỉ áp dụng cho event của *implant*, gồm agent Empire (metadata hoặc launcher), Grunt của Covenant, và process bị implant inject. Mẫu nằm ở mục `c2:` trong `configs/label_seeds.yaml`. Hành động của kịch bản chạy *bên trong* agent vẫn giữ tactic gốc, ví dụ module Invoke-Mimikatz, lệnh `iex` chạy shell, truy cập lsass (Sysmon 10), ghi registry value (13), kết nối sang máy khác. Event tạo implant (Sysmon 1) cũng giữ tactic, ví dụ agent mới trên máy đích thì mang nhãn `lateral-movement`.
- **`credential-access` bị một module chiếm phần lớn:** khoảng 36K trên 44K event là code PowerShell của Invoke-Mimikatz, lặp lại ở khoảng 12 file. `build_dataset.py` khử trùng nên còn 5,085 dòng.
- **File có rất ít bằng chứng:** `msf_record_mic` (12), `covenant_copy_smb_CreateRequest` (11), `covenant_persiststartup` (1), `covenant_persistwmi` (3), vì thiếu log của máy bị tấn công.
- **File bị bỏ:**
  - `empire_mimikatz_lsadump_inject_protected_mode`: không có dấu vết attacker trong log.
  - `raccine_*`: chỉ có 3–6 event.
- **Hạt giống `cmd` chung được dùng cho mọi file**, như launcher Empire/Covenant, Grunt, mimikatz, Rubeus, PsExec… Thêm kịch bản mới thì chỉ cần thêm mục vào `configs/label_seeds.yaml`.
- **Nhãn được suy ra bằng luật,** chưa có nhãn chuẩn để đối chiếu.

## EVTX-ATTACK-SAMPLES

### Cách gán

Mỗi file EVTX là một mẫu đã được tác giả lọc, nên phần lớn event trong file là của kỹ thuật tấn công. Ví dụ, 201/278 file chỉ có ≤10 event. Vì vậy cách gán khác Mordor:

- **Mặc định (`mode: all`, 265 file):** mọi event mang tactic của thư mục (`file:curated`), trừ hai trường hợp:
  - **Nhiễu → `benign`.** Luật chung trong `noise:` của `configs/label_seeds_evtx.yaml`:
    - đăng nhập dịch vụ của SYSTEM/LOCAL/NETWORK SERVICE,
    - tài khoản máy của chính host tự đăng nhập,
    - DNS/NetBIOS/DHCP/LLMNR/SSDP/WSD/multicast,
    - host nói chuyện với chính nó qua fe80::,
    - process nền như UI0Detect, slui, RuntimeBroker, OneDrive, Opera/Google update, WMIADAP, svchost fdPHost/gpsvc,
    - Defender scheduled scan, file Recent,
    - Sysmon tự cài đặt.

    Ngoài ra, từng file có thể có thêm luật riêng.
  - **Dấu vết của người làm mẫu → `uncertain`.** Chủ yếu là event xoá log 1102/104 ở đầu file. Riêng các file về chủ đề xoá log thì 1102/104 vẫn mang tactic (`keep`).
- **`mode: seeds` (9 file lẫn nhiều nhiễu):** dùng cách hạt giống + lan nhãn như Mordor (`label_events.label_file`). Event không lan tới là `benign`.

  | File | Hạt giống |
  |---|---|
  | `CA_PetiPotam_etw_rpc_efsr_5_6` | lời gọi RPC MS-EFSR. Chỉ 2/29,109 event; còn lại là ETW RPC của cả máy |
  | `etw_rpc_zerologon` | lời gọi Netlogon + epmapper qua TCP (6/415) |
  | `bits_openvpn` | job BITS `xxxxxxxx.png` tải từ imgur do notepad (bị inject) tạo (28/1,537); còn lại là Google, OneDrive, Windows |
  | `rogue_msi_url_1040_1042` | gói MSI cài từ URL (2/351) |
  | `persistence_sysmon_11_13_1_shime_appfix` | sdbinst / AppCompatFlags / AppPatch\Custom. Process sót lại từ các bài thử khác (calc do services chạy, run key, malwr.vbs...) là `uncertain` |
  | `sysmon_13_1_persistence_via_winlogon_shell` | a.exe và shell độc hại; phần reboot là `benign` |
  | `privesc_unquoted_svc_sysmon_1_11` | tạo `C:\program.exe` và process đó; phần boot là `benign` |
  | `privesc_spoolsv_spl_file_write_sysmon11` | file spool, phoneinfo.dll, WerTrigger |
  | `execution_evasion_visual_studio_prebuild_event` | lệnh pre-build; phần build bình thường là `benign` |

  Với các file có reboot, tuỳ chọn `parent_launcher: false` tắt luật "process cha khởi chạy hạt giống". Nếu không tắt, `services.exe` / `userinit.exe` lúc boot sẽ bị coi là độc hại.
- **Đổi tactic:** `AutomatedTestingTools/Malware/*` và `Other/*` không phải tên tactic, nên được gán tay. Emotet và maldoc → `execution`; quét BlueKeep → `discovery`; các mẫu mã độc → `defense-evasion` / `persistence`. Cột `Tactic` trong file nhãn là tactic sau khi đổi.
- **File bị bỏ (4):**
  - `PanacheSysmon_vs_AtomicRedTeam01`, `panache_sysmon_vs_EDRTestingScript`: Atomic Red Team chạy hàng chục kỹ thuật thuộc nhiều tactic trong một file.
  - `WinDefender_Events_1117_1116_AtomicRedTeam`: chỉ có cảnh báo của Defender.
  - `UACME_59_Sysmon` ở thư mục gốc: trùng từng byte với bản trong `Privilege Escalation/`.

### Kết quả (EVTX)

36,659 event trong 274 file. Thống kê từng file nằm trong `data/interim/labels/evtx/label_report.json`; log chạy nằm trong `data/interim/labels/evtx/label_run.txt`.

| Nhãn | Event |
|---|---|
| benign | 32,205 |
| lateral-movement | 1,253 |
| privilege-escalation | 1,014 |
| discovery | 867 |
| defense-evasion | 340 |
| credential-access | 269 |
| persistence | 264 |
| command-and-control | 216 |
| execution | 173 |
| uncertain | 58 |

### Lưu ý khi dùng (EVTX)

- **Benign của EVTX gần như toàn đến từ 3 file:** PetitPotam ETW (29,107), BITS (1,509) và MSI (349). Đây là các loại log (RPC ETW, BITS, MsiInstaller) gần như không có ở Mordor. `build_dataset.py` khử trùng và `train.py` giới hạn trọng số `min(n_dup, 10)`.
- **Một vài file chiếm phần lớn một lớp:**
  - `LM_5145_Remote_FileCopy`: 869/1,253 event `lateral-movement`, toàn bộ là 5145 duyệt `C$`.
  - Quét BlueKeep: 733/867 event `discovery`.
  - `Sysmon_UACME_64`: 530/1,014 event `privilege-escalation`, chủ yếu là Sysmon 7.
- **`command-and-control` ở EVTX là tactic của thư mục** (RDP tunnel, plink, tunna, BITS). Ở Mordor, `command-and-control` là phần "nhịp tim" của implant. Hai nghĩa này khác nhau.
- **Mặc định `file:curated` nghĩa là tin vào việc lọc của tác giả.** Các file nhỏ chưa được loại nhiễu nếu không có luật khớp. Mỗi file đã được đọc lướt một lần để đặt luật, nhưng chưa có nhãn chuẩn nào để đối chiếu.
