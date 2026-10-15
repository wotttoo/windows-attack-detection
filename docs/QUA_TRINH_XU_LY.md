# Quá trình xử lý dữ liệu: EVTX-ATTACK-SAMPLES và Mordor

Tài liệu này mô tả quy trình xử lý hai bộ dữ liệu hành vi tấn công trên Windows, từ log gốc đến model phát hiện. Các bước:
- đưa cả hai bộ về **một định dạng chung (OSSEM)**;
- **gán nhãn cho từng event**;
- gộp thành bảng feature;
- train model 2 bước: độc hại hay benign, rồi tactic;
- dự đoán log mới;
- gộp các event bị báo độc hại thành cảnh báo.

Tài liệu chỉ ghi cách làm cuối cùng, tức là cách cho kết quả tốt nhất. Các thử nghiệm không cải thiện kết quả đã được bỏ.

```
data/raw/EVTX-ATTACK-SAMPLES/ ─(1) evtx2json.py─► data/interim/evtx_json/ ─┐
                                                                            ├─(2) ossem_normalize.py─► data/interim/ossem/
data/raw/mordor/datasets/ ──────────────────────────────────────────────────┘
                                                                                                   │
data/interim/ossem/mordor/ ─(3) label_events.py─► data/interim/labels/mordor/ ─┐                   │
data/interim/ossem/evtx/   ─(4) label_evtx.py───► data/interim/labels/evtx/   ─┴─(5) build_dataset.py─► data/processed/events.parquet
                                                                                                   │
                                                          (6) train.py (+ behavior.py)             ▼
                                                          results/report.md, models/{binary,tactic}.joblib
                                                                                                   │
log mới (.evtx / JSON) ──────────────────(7) predict.py────────────────────────────────────────────┴─► results/predict/<tên>/predictions.csv
                                                                                                   │
                                                          (8) alert.py                             ▼
                                                          results/predict/<tên>/alerts.md, alerts.csv
```

Các script nằm trong `src/`, luật gán nhãn và bảng map OSSEM trong `configs/`. Lệnh bên dưới chạy từ thư mục gốc của project.

Chạy lại toàn bộ:
```bash
python src/evtx2json.py data/raw/EVTX-ATTACK-SAMPLES data/interim/evtx_json
python src/ossem_normalize.py run --map configs/ossem_dd_windows.json --evtx data/interim/evtx_json --mordor data/raw/mordor/datasets --out data/interim/ossem
python src/label_events.py --all data/interim/ossem/mordor --metadata data/raw/mordor/datasets/metadata --out data/interim/labels/mordor
python src/label_evtx.py --all data/interim/ossem/evtx --out data/interim/labels/evtx
python src/build_dataset.py --view
python src/train.py
python src/alert.py <file hoặc thư mục .evtx / .json>     # chạy predict.py rồi gộp thành cảnh báo
```

---

## 0. Dữ liệu đầu vào

| | EVTX-ATTACK-SAMPLES | Mordor `small/windows` |
|---|---|---|
| Định dạng gốc | 278 file `.evtx` (định dạng nhị phân của Windows) | 106 file JSON lines |
| Quy mô | ~37K event | ~623K event |
| Tổ chức | `thư mục = tactic`, `tên file = kỹ thuật` | `tactic/host/<kịch bản>/<kịch bản>_<thời điểm>.json` |
| Metadata | không có | `datasets/metadata/SDWIN-*.yaml`: mã ATT&CK, công cụ, `adversary_view` (lệnh attacker đã chạy) |
| Đặc điểm | file "sạch", chủ yếu là event tấn công | mỗi file là một lần mô phỏng, có rất nhiều nhiễu nền giống môi trường thật |

**Điểm quan trọng:** cả hai bộ chỉ có nhãn ở mức file, không có nhãn cho từng event.

---

## 1. Chuyển `.evtx` sang JSON: `evtx2json.py`

File `.evtx` là nhị phân nên phải parse trước. Script làm như sau:

1. Đọc từng record bằng thư viện `python-evtx` và lấy record dưới dạng XML.
2. Tách XML của mỗi event thành các phần:
   - **`<System>`** (header chung): `EventID`, `Channel`, `Computer` → `Hostname`, `TimeCreated`, `Provider` → `SourceName`, `EventRecordID`, `Execution` → `ExecutionProcessID`/`ExecutionThreadID`, `Security` → `UserID`.
   - **`<EventData>`**: mỗi thẻ `<Data Name="X">` thành một trường `X`. Riêng log PowerShell kiểu cũ gộp nhiều tham số dạng `<string>…</string>` trong một thẻ, script tách ra thành `param1`, `param2`, `param3`.
   - **`<UserData>`**: cấu trúc khác nhau tùy provider, nên được làm phẳng bằng cách lấy các node lá.
3. Ghi ra **JSON lines** (mỗi dòng một event), giữ nguyên cấu trúc thư mục, và thêm nhãn `EVTX_Tactic` (tên thư mục) cùng `EVTX_FileName`.

Tên các trường header được đặt theo cách NXLog/Mordor đặt, để bước sau gộp hai bộ dễ hơn.

```bash
pip install python-evtx
python src/evtx2json.py data/raw/EVTX-ATTACK-SAMPLES data/interim/evtx_json
```

Kết quả: `data/interim/evtx_json/` gồm 278 file, 37,364 event.

> Mẹo xem file JSON lines: `jq -C . file.json | less -R`.

---

## 2. Chuẩn hoá về schema OSSEM: `ossem_normalize.py`

### Vì sao cần chuẩn hoá

Cùng một hành vi nhưng mỗi nguồn log đặt tên trường khác nhau. Ví dụ đường dẫn process là `Image` trong Sysmon 1 nhưng là `NewProcessName` trong Security 4688. Trong bộ EVTX có tới 417 tên trường khác nhau, và các file trong cùng một thư mục cũng không dùng chung bộ trường.

**OSSEM** (Open Source Security Events Metadata, do OTRF làm, cũng là nhóm làm ra Mordor) định nghĩa tên trường chuẩn như `ProcessFilePath`, `ProcessCommandLine`, `SrcIpAddr`, `UserName`… Dự án có kèm bộ từ điển **OSSEM-DD** map từ tên trường gốc sang tên chuẩn cho từng (provider, EventID).

### Các bước

1. **Tạo bảng map từ OSSEM-DD.** Script lấy bảng map từ repo `OTRF/OSSEM-DD` và lưu thành `configs/ossem_dd_windows.json` (230 cặp provider|EventID). Một số event có nhiều biến thể, ví dụ Security 4656 với registry và với service, nên tên chuẩn được chọn theo `ObjectType`.
2. **Nhận diện định dạng nguồn.** Script tự nhận diện 4 định dạng:
   - EVTX đã chuyển,
   - Mordor NXLog (`EventTime`, `Hostname`…),
   - Mordor Winlogbeat (`event_id`, `event_data{}`…),
   - Mordor dạng phẳng có `TimeCreated`.
3. **Header chung:**

   | Trường | Nội dung |
   |---|---|
   | `EventId` | số nguyên |
   | `EventTimestamp` | giờ UTC theo ISO-8601 |
   | `EventOriginalTime` | giá trị thời gian gốc |
   | `EventOriginalUid` | record number |
   | `EventSeverity` | mức độ |
   | `DvcHostname` | tên máy |
   | `Channel`, `Provider` | tên channel đã chuẩn hoá chữ hoa/thường, provider được suy ra từ channel nếu thiếu |
   | `ExecutionProcessId` | PID của process ghi log, cần để nối PowerShell 4103/4104 với process |

4. **Đổi tên trường dữ liệu theo OSSEM-DD.** Trường nào từ điển chưa map thì giữ tên gốc. Nếu tên gốc trùng với một tên chuẩn đã dùng thì thêm tiền tố `Raw`. Kết quả là 92% giá trị trường được map.
5. **Gộp các tên không nhất quán ngay trong OSSEM-DD:**
   - `ProcessPath` → `ProcessFilePath`, `ProcessParentPath` → `ProcessParentFilePath`, `TargetProcessPath` → `TargetProcessFilePath`,
   - `SrcPortNumber`/`DstPortNumber` (Sysmon) → `SrcPort`/`DstPort` (giống Security).
6. **Bổ sung phần OSSEM-DD chưa có**, theo quy ước tên `Powershell*` của từ điển:
   - PowerShell 4103: tách `ContextInfo` thành `PowershellHostApplication`, `PowershellCommandName`, `UserName`…; `Payload` → `PowershellPayload`.
   - PowerShell 4104: `ScriptBlockText` → `PowershellScriptBlockText`…
   - PowerShell 400/403/600/800: tách các dòng `key=value` trong thông điệp thành trường riêng; phần chi tiết pipeline → `PowershellPayload`.
   - `Hashes` của Sysmon → `ProcessHashSha256`… (EID 1), `ModuleHash*` (EID 7), `FileHash*` (các EID khác).
7. **Chuẩn hoá kiểu dữ liệu:** các trường `*ProcessId`, `*ThreadId`, `*Port`, `LogonType`, `UserSessionId` được đổi sang số nguyên. Giá trị hex `0x..` cũng được đổi.
8. **Chuẩn hoá thời gian về UTC:**
   - Sysmon: lấy `UtcTime`.
   - Nguồn khác: lấy timestamp gốc. Với NXLog thì dùng `EventTime`, vì `@timestamp` là lúc Logstash nhận log, trễ 1–3 giây. Sau đó cộng độ lệch múi giờ của file, tính bằng cách so với `UtcTime` của Sysmon trong cùng file.
   - Mordor dạng phẳng ghi `TimeCreated` theo đồng hồ 12 giờ, không có AM/PM, nên chọn bản ±12h gần với giờ Sysmon nhất.
9. **Nhãn từ metadata:** `Dataset`, `SourceFile`, `Tactic` (slug ATT&CK). Với Mordor có thêm `ScenarioId`, `ScenarioTitle`, `AttackTechniques`, `AttackTactics`, nối với file dữ liệu qua trường `link`.
10. **Làm sạch:**
    - bỏ các trường vận chuyển log như `host`, `port`, `tags`, `SourceModule*`…,
    - bỏ `Message` gốc (rất nặng), trừ khi event không còn trường nào khác,
    - bỏ 3 file Mordor trùng nhau từng byte (kiểm tra bằng md5).

```bash
git clone https://github.com/OTRF/OSSEM-DD
python src/ossem_normalize.py build-map OSSEM-DD configs/ossem_dd_windows.json
python src/ossem_normalize.py run --map configs/ossem_dd_windows.json \
    --evtx data/interim/evtx_json --mordor data/raw/mordor/datasets --out data/interim/ossem
```

Kết quả: `data/interim/ossem/evtx/` và `data/interim/ossem/mordor/`, tổng 619,117 event. Chi tiết nằm trong `docs/ossem.md` và `data/interim/ossem/report.json`.

---

## 3. Gán nhãn từng event cho bộ Mordor: `label_events.py` + `configs/label_seeds.yaml`

### Vấn đề

Nếu gán nhãn tactic của file cho mọi event trong file thì sai rất nhiều. Ví dụ file `empire_psremoting_stager` có 2,744 event, nhưng hơn 40% là hoạt động nền như `svchost`, Azure agent, `wmiprvse`… Cùng một event nền như vậy sẽ mang nhãn `lateral-movement` ở file này và `credential-access` ở file khác, nên model không học được gì có ý nghĩa.

Vì vậy phải **tách event tấn công khỏi event nền trong từng file**. Bộ nhãn cuối cùng là:

```
benign | command-and-control | execution | persistence | privilege-escalation | defense-evasion
       | credential-access | discovery | lateral-movement | collection | uncertain
```

### Bước 3.1: Hạt giống

Hạt giống là những event chắc chắn của attacker. Chúng được khai báo trong `configs/label_seeds.yaml`, dựa trên `adversary_view` của từng kịch bản:

- **Mẫu chung cho mọi file (`generic`):** launcher Empire (`-noP -sta -w 1 -enc`), PowerShell base64 dài, launcher Covenant (`DeflateStream…FromBase64String`), `Grunt*.exe`, mimikatz, Rubeus, Seatbelt, SharpView, PurpleSharp, PsExec, `reg save HKLM\SAM`…
- **Mẫu riêng cho từng kịch bản (`scenarios`)**, có 3 loại:
  - `cmd`: mẫu command line. Ví dụ `esentutl /y /vss`, `mshta javascript:`, `cmstp /s`, `wmic /node:`, UAC bypass qua `DllHost` CMSTPLUA.
  - `script`: mẫu nội dung PowerShell. Ví dụ `PromptForCredential`, `EventCacheManager`.
  - `events`: điều kiện trên event bất kỳ. Ví dụ DCSync bằng 4662 với GUID quyền replication trên DC, Zerologon bằng 4742 `ANONYMOUS LOGON`, PurpleSharp bằng 4625/4769, Taskmgr dump lsass bằng Sysmon 10/11, WMI persistence bằng Sysmon 19–21, truy cập `svcctl` từ xa bằng 5145. Có thể chỉ định so khớp trên một trường cụ thể (`field`) và đánh dấu luôn process sinh ra event (`process: true`).
- **Từ metadata Mordor:** bảng "Active agents" của Empire cho biết (máy, PID) của từng agent.
- **Từ log PowerShell:** event nào có `HostApplication` là launcher độc hại thì `ExecutionProcessId` của nó là PID của agent.

### Bước 3.2: Lan từ hạt giống

Script dựng **bảng process** từ Sysmon gồm GUID, PID, thời gian sống, command line và process cha. Một số file Mordor (NXLog) thiếu `ProcessId` trong Sysmon, nên PID được lấy lại từ các cặp GUID/PID khác (`ProcessParentGuid`/`ProcessParentId`, `TargetProcessGuid`/`TargetProcessId`) hoặc từ Security 4688 xảy ra cùng thời điểm.

Sau đó lan nhãn theo các quan hệ sau:

| Quan hệ | Ý nghĩa |
|---|---|
| Process cha khởi chạy hạt giống | cha được tạo ≤ 10 giây trước con, ví dụ `wsmprovhost`, `fodhelper` |
| Process con, cháu | theo `ProcessParentGuid` |
| Process bị inject | Sysmon 8 (CreateRemoteThread) từ process độc hại |
| Event Sysmon | cùng `ProcessGuid` với process độc hại |
| Event Security / PowerShell | `ProcessId` hoặc `ExecutionProcessId` trùng PID độc hại trên cùng máy, trong lúc process đó còn sống (cho phép lệch 2 giây) |
| PowerShell cổ điển (không có PID) | `HostApplication` khớp mẫu hoặc trùng command line của process độc hại |
| Phiên đăng nhập | event Security cùng `LogonId` với process độc hại (không tính các phiên dùng chung của SYSTEM/LOCAL/NETWORK SERVICE) |
| Kết nối mạng | cùng 4-tuple (IP:port hai đầu) với kết nối độc hại, kể cả event ghi ở máy bên kia |

Những gì có liên quan nhưng không nối chắc được thì gán **`uncertain`**, ví dụ process cùng tên với agent nhưng thiếu PID, hoặc đăng nhập khác của cùng user ngay sát thời điểm. Các event này bị bỏ ở bước 5 (`build_dataset.py`).

### Bước 3.3: Tách `command-and-control`

Agent C2 (Empire, Covenant) sinh ra rất nhiều event "nhịp tim" giống nhau ở mọi kịch bản. Nếu để chúng mang tactic của file thì model sẽ chỉ học cách nhận ra agent. Vì vậy, với event của **implant** (agent Empire, Grunt của Covenant, process bị implant inject), có 3 loại được gán `command-and-control`:

| Loại | Gồm |
|---|---|
| `c2:beacon` | PowerShell của vòng liên lạc: `Start-Sleep`, `WebClient` + headers, mã hoá RC4, kiểm tra MAC, dựng gói tin, định dạng kết quả gửi về |
| `c2:channel` | kết nối tới cổng C2 (80/443/8080/8443), bind cổng (5158) |
| `c2:implant-runtime` | hoạt động nền: nạp DLL, tạo/xoá khoá registry, DNS, handle/token; **trừ khi** chạm lsass/SAM/SECURITY/NTDS |

Hành động thật của kịch bản vẫn **giữ tactic gốc**, kể cả khi chạy bên trong agent: module Invoke-Mimikatz, lệnh shell (`iex`), truy cập/inject process, ghi registry value, kết nối sang máy khác, các process con. Các mẫu này nằm ở mục `c2:` trong `configs/label_seeds.yaml`.

### Cột nhãn

| Cột | Giá trị |
|---|---|
| `label` | một trong các nhãn ở trên |
| `label_malicious` | `1` độc hại / `0` benign / `-1` uncertain |
| `label_method` | lý do gán nhãn, ví dụ `sysmon:process-guid`, `pid:ProcessId`, `logon-session`, `pid:ExecutionProcessId\|c2:beacon` |

```bash
# xem chi tiết 1 file
python src/label_events.py data/interim/ossem/mordor/<...>.json --metadata data/raw/mordor/datasets/metadata
# gán nhãn cả bộ Mordor
python src/label_events.py --all data/interim/ossem/mordor --metadata data/raw/mordor/datasets/metadata --out data/interim/labels/mordor
```

### Kết quả (Mordor)

Tổng cộng 580,520 event trong 100 file. 3 file bị bỏ qua: `empire_mimikatz_lsadump_inject_protected_mode` không có dấu vết attacker, và `raccine_*` chỉ có vài event.

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

---

## 4. Gán nhãn từng event cho bộ EVTX: `label_evtx.py` + `configs/label_seeds_evtx.yaml`

### Khác gì Mordor

Bộ EVTX không có metadata, nhưng mỗi file là mẫu **đã được tác giả lọc**: 201/278 file chỉ có ≤10 event, và phần lớn event là của kỹ thuật tấn công. Vì vậy, thay vì bắt đầu từ hạt giống rồi lan ra, cách làm là **mặc định mọi event mang tactic của file, rồi loại nhiễu ra**. Từng file đã được đọc lướt một lần để đặt luật.

### Các bước

1. **Mặc định (`mode: all`):** event mang tactic của thư mục, `label_method = file:curated`.
2. **Loại nhiễu → `benign`** (`noise:` trong `configs/label_seeds_evtx.yaml`):

   | Loại nhiễu | Ví dụ |
   |---|---|
   | đăng nhập nền | SYSTEM/LOCAL/NETWORK SERVICE (logon type 5); tài khoản máy của chính host (`DC1$` trên DC1) |
   | mạng nền | DNS, NetBIOS, DHCP, LLMNR, SSDP, WSD, multicast; host nói chuyện với chính nó qua fe80:: |
   | process nền | UI0Detect, slui, RuntimeBroker, OneDrive, Opera/Google update, WMIADAP, TiWorker, svchost `-s fdPHost/gpsvc/wcncsvc` |
   | file / registry nền | Defender scheduled scan, file Recent, `DefaultSpoolDirectory`, `NetworkList\Profiles` |
   | Sysmon tự cài đặt | Sysmon 4/16, `Sysmon.exe` |

   Thêm luật riêng cho file khi cần. Ví dụ: 110 event 4663 của svchost đọc khoá `Lsa` trong file xoá log; event 1155/258/1136 lặp theo chu kỳ của dịch vụ RDP; DC tự đổi audit policy (4719).
3. **Dấu vết của người làm mẫu → `uncertain`:** event xoá log 1102/104 ở đầu file, do người làm mẫu chạy trước khi thử nghiệm. Riêng các file về chủ đề xoá log thì 1102/104 vẫn mang tactic (`keep`).
4. **File lẫn nhiều nhiễu dùng `mode: seeds`** (9 file): hạt giống + lan nhãn giống hệt Mordor (gọi lại `label_events.label_file`), phần không lan tới là `benign`. Ví dụ: PetitPotam (2/29,109 event là lời gọi MS-EFSR), Zerologon ETW, BITS (job `.png` tải từ imgur), MSI cài từ URL, các file có reboot (shim, Winlogon shell, unquoted service, spooler).

   Với file có reboot, đặt `parent_launcher: false` để không coi `services.exe`/`userinit.exe` lúc boot là "process cha khởi chạy hạt giống".
5. **Luật riêng cho 2 file lớn:**
   - `rdpcorets_148_mst120_bluekeep_rpdscan_full`: chỉ 3 event mở kênh `ms_t120` là dấu hiệu BlueKeep. 730 event còn lại là trạng thái phiên RDP bình thường, nên gán `uncertain`.
   - `Sysmon_UACME_64`: các event Sysmon 7 nạp DLL trong `system32`/`syswow64` có chữ ký Microsoft gán `benign`. Ở bước 5 (`build_dataset.py`), loại event này bị bỏ cho cả hai bộ.
6. **Đổi tactic** cho `AutomatedTestingTools/Malware` và `Other` (Emotet, maldoc → `execution`; quét BlueKeep → `discovery`...).
7. **Bỏ 4 file:**
   - 2 file Atomic Red Team: nhiều tactic trong một file, không tách được.
   - File chỉ có cảnh báo Defender.
   - `UACME_59_Sysmon` ở thư mục gốc: trùng từng byte với bản trong `Privilege Escalation/`.

```bash
# xem chi tiết 1 file: nhãn, lý do, các event benign/uncertain
python src/label_evtx.py "data/interim/ossem/evtx/Credential Access/<file>.json"
# gán nhãn cả bộ
python src/label_evtx.py --all data/interim/ossem/evtx --out data/interim/labels/evtx
```

### Kết quả (EVTX)

Tổng cộng 36,659 event trong 274 file.

| Nhãn | Event |
|---|---|
| benign | 32,705 |
| lateral-movement | 1,253 |
| privilege-escalation | 514 |
| defense-evasion | 340 |
| credential-access | 269 |
| persistence | 264 |
| command-and-control | 216 |
| execution | 173 |
| discovery | 137 |
| uncertain | 788 |

Khoảng 31K event benign đến từ 3 file: ETW RPC của PetitPotam, BITS và MSI. EVTX có khoảng 3.2K event độc hại.

---

## 5. Gộp hai bộ thành bảng để train: `build_dataset.py`

Gộp `data/interim/labels/mordor/` và `data/interim/labels/evtx/` thành một file **Parquet** (`data/processed/events.parquet`). Parquet là định dạng bảng lưu theo cột, có nén và có kiểu dữ liệu, đọc bằng `pd.read_parquet`. Mỗi dòng là một event.

1. **Bỏ event `uncertain`.**
2. **Bỏ Sysmon 7 nạp DLL hệ thống có chữ ký Microsoft** (hàm `sys_dll_load`; giữ lại bằng `--keep-sys-dll`). Đó là các event có `ModuleSignatureStatus` = Valid, `ModuleSignature` bắt đầu bằng "Microsoft", và DLL nằm trong `C:\Windows\{System32, SysWOW64, WinSxS, Microsoft.NET, assembly}`. Có 59,294 event bị bỏ. Event loại này không chứa dấu hiệu tấn công, và hai bộ gán nhãn nó ngược nhau: Mordor lan nhãn theo process nên `kernel32.dll` do process độc hại nạp cũng mang nhãn độc hại, còn EVTX gán benign. Bỏ đi thì nhãn hai bộ thống nhất và model không phải đoán qua tên process.
3. **Không đưa vào bảng các trường làm lộ nhãn hoặc lộ bộ dữ liệu:** hostname, IP, tên user/domain, timestamp, PID/GUID, `SourceFile`, `Tactic`, `Scenario*`. Chỉ giữ các cột meta (`dataset`, `group`, `label`, `label_malicious`, `label_method`) để chia tập dữ liệu và làm nhãn.
4. **Trích khoảng 40 cột feature cố định**, thay vì hơn 600 trường thô: loại event, tên process / process cha / process đích, kiểu tài khoản, logon type, quyền truy cập, chữ ký DLL, cổng và loại IP đích, văn bản (command line, PowerShell, registry, file, pipe, share...), và một số đặc trưng số (độ dài, entropy, có base64).
5. **Chuẩn hoá văn bản:** chữ thường; tên host / user / domain của các lab (thu thập từ chính dữ liệu) → `<host>`, `<user>`, `<domain>`; GUID, SID, IP, hex, số dài → token chung. Như vậy model không học thuộc tên máy của từng lab.
6. **Khử trùng lặp:** event giống hệt nhau sau chuẩn hoá, trong cùng kịch bản và cùng nhãn, chỉ giữ một dòng. Cột `n_dup` ghi số lần lặp. 616,169 event (không tính uncertain) bỏ 59,294 event nạp DLL hệ thống, còn **107,442 dòng**, 373 group. Mordor `credential-access` từ 43,614 event còn 5,085 dòng, vì phần lớn là code Invoke-Mimikatz lặp lại.

```bash
python src/build_dataset.py --view   # -> data/processed/events.parquet (2.8 MB) + events_summary.json
                                 #    --view: thêm bản CSV để xem bằng mắt: events_view.csv, view_by_event/<provider>_<event_id>.csv
```

Danh sách cột và số dòng theo nhãn nằm trong `docs/dataset.md`.

---

## 6. Train và đánh giá model: `train.py` + `behavior.py`

### Cách làm

**1. Feature hành vi (`behavior.py`).** Thay các giá trị đặc thù của từng lab bằng thuộc tính hành vi, để model không học thuộc tên công cụ:
- **Nhóm binary** cho process, process cha và process đích: shell, script host, LOLBin, công cụ quản trị, host thực thi từ xa, Office, trình duyệt, công cụ tự nâng quyền UAC, process nhạy cảm, compiler... Công cụ lạ được phân theo nơi chạy (`unknown_userland`...). Tên process không được đưa trực tiếp vào model.
- **Cặp cha→con** (`pc_pair`) và **vị trí chạy** (`img_loc`).
- **Nhóm cổng** (`port_class`) thay cho số cổng. Mã quyền truy cập được chuẩn hoá hex.
- **Cờ 0/1 lấy từ văn bản:**
  - tải về, mã hoá, PowerShell ẩn, `iex`, reflection;
  - service, scheduled task, ghi registry, WMI subscription;
  - các khoá Run/Services/Winlogon/IFEO/COM/UAC/LSA;
  - công cụ và file credential, shadow copy;
  - lệnh discovery;
  - thực thi từ xa, share quản trị, pipe RPC;
  - xoá log, can thiệp antivirus, inject;
  - binary bị đổi tên, truy cập lsass...
- **Che văn bản:** tên `.exe`, `harddiskvolumeN`, `syswow64`.

**2. Vector hoá** (fit lại trên phần train của mỗi lần chia):
- cột phân loại: one-hot, giá trị xuất hiện dưới 3 lần gộp thành "hiếm";
- cột số: log1p rồi MaxAbsScaler;
- văn bản: gộp thành 3 nhóm (`t_proc`: cmdline / parent / host app; `t_ps`: PowerShell; `t_obj`: đường dẫn, registry, pipe, share, service, dns, other_text), cắt 2,000 ký tự, TF-IDF char n-gram 3–5, tối đa 20,000 feature mỗi nhóm. Tổng khoảng 60,000 feature.

**3. Trọng số mẫu:** `min(n_dup, 10)` để event lặp nhiều lần không lấn át, rồi cân bằng để tổng trọng số mỗi lớp bằng nhau (benign chiếm khoảng 83%).

**4. Model 2 bước, Logistic Regression (liblinear):**
1. nhị phân: độc hại hay benign;
2. tactic: chỉ train trên dòng độc hại, 8 lớp, one-vs-rest.

**5. Đánh giá theo 2 cách.** Mỗi chỉ số tính ở 2 mức: theo dòng và theo event (trọng số `n_dup`).

| Tên | Train | Test | Trả lời câu hỏi |
|---|---|---|---|
| `cv` | GroupKFold 5 fold theo `group` (cả file / kịch bản nằm trọn ở train hoặc test) | fold còn lại | kịch bản chưa thấy, cùng môi trường |
| `mix` | toàn bộ Mordor + 4/5 file EVTX (StratifiedGroupKFold) | 1/5 file EVTX còn lại | file EVTX chưa thấy, khi tập train có cả hai bộ (giống model cuối) |

**6. Model cuối:** train trên toàn bộ dữ liệu (Mordor + EVTX), lưu ở `models/binary.joblib` và `models/tactic.joblib`. Mỗi file chứa featurizer và model.

```bash
python src/train.py                  # 2 cách đánh giá + model cuối (~26 phút, RAM ~3 GB)
python src/train.py --eval none      # chỉ train model cuối (~3 phút)
python src/train.py --eval mix --no-final
python src/train.py --report-only    # chỉ viết lại report.md từ results/pred_*.parquet (vài giây)
```

Kết quả: `results/report.md`, `results/metrics.json`, `results/pred_{cv,mix}.parquet` (dự đoán từng dòng để phân tích lỗi), `results/train_run.log`.

### Kết quả: `results/report.md`

Theo event, ngưỡng 0.5. "Báo nhầm" là tỉ lệ event benign bị báo độc hại.

| Đánh giá | Event độc hại | PR-AUC | Precision | Recall | F1 | Báo nhầm | Tactic macro-F1 |
|---|---|---|---|---|---|---|---|
| `cv` | 92,894 | 0.945 | 0.844 | 0.942 | **0.890** | 3.50% | 0.353 |
| `mix` | 3,123 | 0.832 | 0.669 | **0.826** | 0.739 | 3.97% | 0.284 |
| `mix`, không tính `bits_openvpn` | | | 0.942 | **0.825** | **0.879** | 0.51% | **0.287** |

F1 theo tactic (event):

| Tactic | cv | mix |
|---|---|---|
| command-and-control | 0.854 | 0.076 |
| credential-access | 0.629 | 0.230 |
| defense-evasion | 0.088 | 0.181 |
| discovery | 0.061 | 0.056 |
| execution | 0.085 | 0.293 |
| lateral-movement | 0.696 | 0.569 |
| persistence | 0.213 | 0.302 |
| privilege-escalation | 0.201 | 0.565 |

Nhận xét:
- **Phát hiện độc hại hay benign khá tốt:** CV có F1 0.89, recall 0.94. Với file EVTX chưa thấy (`mix`), recall là 0.83 và F1 0.88 (không tính `bits_openvpn`).
- **Gần như toàn bộ báo nhầm của `mix` nằm ở một file `bits_openvpn`** (1,119 event Bits-Client). Event Bits-Client benign chỉ có trong chính file này, còn 2 file BITS khác đều độc hại, nên khi file này nằm ở phần test model chỉ còn thấy "Bits-Client = độc hại". Đây là giới hạn của dữ liệu, không phải lỗi nhãn. Model cuối có học file này.
- **Tactic vẫn yếu:** discovery và defense-evasion gần như không phân biệt được, vì một event riêng lẻ (đọc registry, truy cập file) không đủ thông tin. Command-and-control ở hai bộ mang nghĩa khác nhau: Mordor là nhịp tim implant, EVTX là RDP tunnel, plink, tunna, BITS.
- **Báo nhầm khoảng 3.5%** trên event benign: chấp nhận được cho mục đích phát hiện và cảnh báo trong project. Khi dùng thật thì cần thấp hơn nhiều.
- **Kết quả `mix` vẫn lạc quan hơn môi trường thật sự mới,** vì các file EVTX cùng một người đóng góp, nhiều file dùng chung công cụ hay kịch bản.
- **Feature quan trọng nhất là hành vi:**
  - `img_class_uac_autoelevate`, `f_service_cfg` → privilege-escalation;
  - `img_class_remote_host`, `port_class_winrm` → lateral-movement;
  - `f_wmi_sub` → persistence;
  - `k_appinit_lsa`, `f_cred_dump_file` → credential-access.

---

## 7. Dự đoán log mới: `predict.py`

- Dùng model cuối: `models/binary.joblib` để quyết định độc hại hay benign, rồi `models/tactic.joblib` để gán tactic cho event bị báo độc hại.
- Đầu vào: file hoặc thư mục gồm
  - `.evtx` (cần `pip install python-evtx`);
  - JSON lines dạng evtx2json, NXLog hoặc Winlogbeat (Mordor gốc);
  - JSON đã chuẩn hoá OSSEM (`data/interim/ossem/`, `data/interim/labels/`).
- Các bước giống lúc train: OSSEM → `build_dataset.build_row` → `train.prepare` (hành vi + văn bản). Tên host / user / domain lấy từ chính dữ liệu đầu vào. Không khử trùng: mỗi event một dòng.
- Sysmon 7 nạp DLL hệ thống được gắn `out_of_scope=1`: không báo độc hại, không tính vào chỉ số, vì loại này không có trong tập train.
- Kết quả (mặc định `results/predict/<tên>/`):
  - `predictions.csv`: thời gian, host, loại event, process, command line, `p_malicious`, `malicious`, `tactic`, `p_tactic`, tactic thứ 2, `flags` (các cờ hành vi bật), và các khoá để `alert.py` nối event (`process_guid`, `parent_guid`, `target_guid`, `pid`, `exec_pid`, `logon_id`, `user`);
  - `summary.md`: tóm tắt theo file, 30 event điểm cao nhất, và chỉ số so với nhãn nếu đầu vào có nhãn.

```bash
python src/predict.py "data/raw/EVTX-ATTACK-SAMPLES/Lateral Movement"    # .evtx gốc, 47 file, ~20 giây
python src/predict.py data/interim/labels/evtx --threshold 0.5                       # có nhãn -> in thêm chỉ số
```

---

## 8. Gộp thành cảnh báo: `alert.py`

Tactic theo từng event còn yếu, và một cuộc tấn công sinh ra hàng chục đến hàng trăm event. Vì vậy các event bị báo độc hại được gộp thành **cảnh báo** theo chuỗi hành vi. Người xem đọc một cảnh báo thay vì từng event.

1. **Nối event độc hại trên cùng máy** khi có một trong các điểm chung:
   | Điểm nối | Lấy từ |
   |---|---|
   | cây process | cùng `ProcessGuid`; cha → con (Sysmon 1, `ProcessParentGuid`); process inject sang process khác (Sysmon 8, `TargetProcessGuid`) |
   | cùng process theo PID | `ProcessId` (Sysmon, Security); `ExecutionProcessId` (chỉ với PowerShell) |
   | phiên đăng nhập | `UserLogonId` / `TargetUserLogonId`, trừ phiên dùng chung của SYSTEM / LOCAL / NETWORK SERVICE |
   | thời gian | event liên tiếp trên cùng máy cách nhau ≤ `--window` giây (mặc định 60) |

   Process "trung tâm" của hệ thống (`services`, `svchost`, `explorer`, `wininit`, `lsass`...) không dùng làm điểm nối, vì nếu dùng thì mọi hoạt động trên máy sẽ dính vào nhau.
2. **Cắt cảnh báo** khi trong nhóm có khoảng lặng > `--max-gap` giây (mặc định 1800). Việc này tránh nối nhầm do PID bị dùng lại.
3. **Tóm tắt mỗi cảnh báo:** máy, thời gian, số event / process, chuỗi tactic theo thứ tự xuất hiện, process chính, user, file log, 5 event điểm cao nhất.
4. **Giải thích "vì sao báo"** bằng các cờ hành vi của `behavior.py`, kèm mô tả tiếng Việt (ví dụ `f_cred_dump_file` → "dump lsass / SAM / NTDS"). Cờ nguy hiểm được đánh dấu ⚠: credential, lsass, xoá log, can thiệp AV, shadow copy, AMSI, inject, WMI subscription, khoá LSA.
5. **Mức độ:**
   - `high`: p max ≥ 0.9 và (≥ 2 tactic hoặc có cờ ⚠);
   - `medium`: p max ≥ 0.8 hoặc ≥ 3 event;
   - `low`: còn lại.

```bash
python src/alert.py "data/raw/EVTX-ATTACK-SAMPLES/Lateral Movement"                 # chạy predict.py rồi gộp
python src/alert.py --predictions results/predict/<tên>/predictions.csv          # dùng kết quả predict.py có sẵn
```

Kết quả (cùng thư mục với `predictions.csv`):
- `alerts.md`: tóm tắt, danh sách, chi tiết 50 cảnh báo đầu;
- `alerts.csv`: mỗi cảnh báo 1 dòng;
- `alert_events.csv`: các event của từng cảnh báo.

Nếu đầu vào có nhãn thì có thêm chỉ số theo cảnh báo. Cảnh báo chỉ gồm event `uncertain` không được tính.

**Kết quả trên dữ liệu chưa thấy.** Model được train không có 1/5 số kịch bản (fold 1 của `cv`). Sau đó chạy `alert.py` trên log gốc của 75 kịch bản bị giữ lại (65,559 event, có cả nhiễu nền). Kết quả nằm ở `results/predict/holdout_cv_fold1/`:

| Chỉ số | Giá trị |
|---|---|
| event bị báo độc hại → cảnh báo | 8,251 → **103** |
| cảnh báo đúng (có ít nhất 1 event độc hại thật) | 91/103 (**0.88**) |
| event độc hại thật nằm trong cảnh báo | 0.94 |
| file có tấn công được cảnh báo | 72/75 |
| số cảnh báo cho mỗi file có tấn công | trung bình 1.3, đa số là 1 |

- 12 cảnh báo sai đều nằm trong file có tấn công. Đó là hoạt động nền chạy cùng lúc, ví dụ `wmiprvse`, `services`, `system`, hoặc process hệ thống sau reboot trong file shim.
- 3 file bị bỏ sót: PetitPotam ETW và Zerologon ETW (vài event tấn công lẫn trong 29K event RPC), và Memssp.
- Bộ dữ liệu không có log hoàn toàn benign, nên chưa đo được số cảnh báo sai mỗi ngày trên một máy bình thường.

---

## Phụ lục: các file trong project

| File / thư mục | Nội dung |
|---|---|
| `src/evtx2json.py` | (1) chuyển `.evtx` sang JSON lines |
| `src/ossem_normalize.py` | (2) chuẩn hoá cả hai bộ về OSSEM |
| `src/label_events.py` | (3) gán nhãn từng event cho Mordor: hạt giống và luật tách C2 |
| `src/label_evtx.py` | (4) gán nhãn từng event cho EVTX: mặc định tactic của file, loại nhiễu, hoặc dùng hạt giống |
| `src/build_dataset.py` | (5) gộp hai bộ đã gán nhãn thành bảng feature; bỏ uncertain và Sysmon 7 nạp DLL hệ thống; `--view` xuất CSV để xem |
| `src/behavior.py` | feature hành vi (nhóm binary, cặp cha→con, nhóm cổng, cờ hành vi), dùng bởi `train.py` và `predict.py` |
| `src/train.py` | (6) vector hoá + LR 2 bước; đánh giá `cv`, `mix`; train model cuối |
| `src/predict.py` | (7) dự đoán log mới (.evtx / JSON / OSSEM) |
| `src/alert.py` | (8) gộp event bị báo độc hại thành cảnh báo theo cây process / PID / phiên / thời gian, giải thích bằng cờ hành vi |
| `src/paths.py` | đường dẫn mặc định của project |
| `configs/label_seeds.yaml` | hạt giống Mordor, mẫu chung và luật tách C2 |
| `configs/label_seeds_evtx.yaml` | luật gán nhãn EVTX: nhiễu, uncertain, keep, `mode: seeds` |
| `configs/ossem_dd_windows.json` | bảng map trường gốc → tên chuẩn OSSEM (tạo từ OSSEM-DD) |
| `data/raw/` | hai bộ dữ liệu gốc (tải về, không nằm trong repo) |
| `data/interim/evtx_json/` | EVTX đã chuyển sang JSON |
| `data/interim/ossem/` | dữ liệu đã chuẩn hoá, kèm `report.json` |
| `data/interim/labels/{mordor,evtx}/` | dữ liệu đã gán nhãn, kèm `label_report.json`, `label_run.txt` |
| `data/processed/` | `events.parquet`, `events_summary.json`; `events_view.csv` và `view_by_event/` (chỉ để xem) |
| `models/` | model cuối: `binary.joblib`, `tactic.joblib` |
| `results/` | `report.md`, `metrics.json`, `pred_*.parquet`, `train_run.log`; `predict/<tên>/` chứa kết quả của `predict.py` và `alert.py` |
| `docs/` | tài liệu này; `ossem.md` (chuẩn hoá), `labels.md` (cột nhãn, cách gán), `dataset.md` (cột của `events.parquet`) |
