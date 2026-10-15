# EVTX-ATTACK-SAMPLES + Mordor small/windows — chuẩn hoá OSSEM

Dữ liệu ở `data/interim/ossem/`, tạo bởi `src/ossem_normalize.py` (map lấy từ OSSEM-DD, lưu ở `configs/ossem_dd_windows.json`).
Định dạng: JSON lines, mỗi dòng 1 event, phẳng.

```
evtx/<tactic>/<file>.json             278 file,  37,364 event
mordor/<tactic>/host/.../<file>.json  103 file, 581,753 event (đã bỏ 3 file trùng)
report.json                           thống kê từng file, độ lệch giờ, trường chưa map
```

## Trường chung

| Nhóm | Trường |
|---|---|
| Nhãn | `Dataset` (`evtx-attack-samples`/`mordor`), `SourceFile`, `Tactic` (slug ATT&CK, theo thư mục) |
| Nhãn Mordor | `ScenarioId`, `ScenarioTitle`, `AttackTechniques`, `AttackTactics` (từ `datasets/metadata/SDWIN-*.yaml`; 14 file không có metadata) |
| Header | `EventId` (int), `EventTimestamp` (UTC ISO-8601), `EventOriginalTime` (giá trị gốc), `EventOriginalUid` (record number), `EventSeverity`, `DvcHostname`, `Channel`, `Provider`, `ExecutionProcessId` (PID process ghi log) |
| Dữ liệu | tên OSSEM, ví dụ `ProcessFilePath`, `ProcessCommandLine`, `ProcessParentFilePath`, `ProcessId`, `TargetProcessFilePath`, `UserName`, `SrcIpAddr`, `DstPort`, `RegistryKeyPath`, `Powershell*`... |

`Channel`, `Provider`, `ExecutionProcessId` không có trong OSSEM-CDM, được giữ lại vì cần cho log Windows.

## Quy tắc chuẩn hoá

- Tên trường lấy từ OSSEM-DD theo cặp (provider, EventID); với Security 4656 thì chọn biến thể theo `ObjectType`.
- Trường mà OSSEM-DD chưa map thì **giữ nguyên tên gốc**. Nếu tên gốc trùng với một tên chuẩn đã dùng thì thêm tiền tố `Raw`. Tổng cộng 92% số giá trị trường được map.
- OSSEM-DD tự mâu thuẫn: Sysmon dùng `ProcessFilePath`, Security dùng `ProcessPath`. Script gộp cả hai về `*FilePath`. Tương tự `SrcPortNumber`/`DstPortNumber` (Sysmon) được gộp về `SrcPort`/`DstPort` (Security).
- Tự bổ sung phần OSSEM-DD chưa có:
  - PowerShell 4103: tách `ContextInfo` thành các trường riêng.
  - PowerShell 4104: `PowershellScriptBlockText`…
  - PowerShell 400/403/600/800: tách chuỗi `key=value` thành trường riêng, phần "Details" đưa vào `PowershellPayload`.
- `Hashes` của Sysmon được tách thành `ProcessHash*` (EID 1), `ModuleHash*` (EID 7) hoặc `FileHash*`.
- Các trường `*ProcessId`, `*ThreadId`, `*Port`, `LogonType`, `UserSessionId` được đổi sang int. Giá trị hex `0x..` cũng được đổi.
- `EventTimestamp`:
  - Sysmon: lấy từ `UtcTime`.
  - Các nguồn khác: lấy timestamp header (NXLog: `EventTime`, vì `@timestamp` là lúc ingest, trễ 1–3 giây) rồi cộng độ lệch của file, tính theo Sysmon.
  - 31 file Mordor ghi `TimeCreated` theo giờ địa phương, kiểu 12 giờ không có AM/PM, nên được chỉnh thêm ±12h cho khớp với Sysmon.
- Bỏ các trường vận chuyển của NXLog/Logstash/Winlogbeat như `host`, `port`, `tags`, `SourceModule*`, `EventReceivedTime`, `@metadata`…
- Bỏ `Message`, trừ khi event không còn trường dữ liệu nào. Chạy với `--keep-message` nếu muốn giữ lại.

## Chưa map

RPC ETW (PetitPotam/Zerologon), BITS, MsiInstaller, một số trường của Security 5156/5158 (`LayerName`, `FilterRTID`…). Danh sách đầy đủ nằm trong `report.json` → `top_unmapped`.
