# Bảng dữ liệu để train: `events.parquet`

Dữ liệu ở `data/processed/`, tạo bởi `src/build_dataset.py`, gộp `data/interim/labels/mordor/` và `data/interim/labels/evtx/`:

```bash
python src/build_dataset.py                    # -> data/processed/events.parquet + events_summary.json
python src/build_dataset.py --keep-uncertain   # giữ cả event uncertain
python src/build_dataset.py --no-dedup         # không khử trùng lặp
python src/build_dataset.py --view             # + bản CSV để xem: events_view.csv, view_by_event/<provider>_<event_id>.csv
```

Đọc bảng:

```python
import pandas as pd
df = pd.read_parquet("data/processed/events.parquet")
```

## Xử lý

- **Bỏ event `uncertain`**, trừ khi chạy với `--keep-uncertain`.
- **Bỏ Sysmon 7 nạp DLL hệ thống ký Microsoft** (`build_dataset.sys_dll_load`, từ 14/10), trừ khi chạy với `--keep-sys-dll`.
- **Không đưa vào bảng** các trường làm lộ nhãn hoặc lộ bộ dữ liệu: hostname, IP, tên user/domain, timestamp, PID/GUID/RecordID, `SourceFile`, `Tactic`, `Scenario*`, `Attack*`.
- **Chuẩn hoá văn bản:**

  - đổi về chữ thường,
  - tên host / user / domain của các lab (lấy từ dữ liệu: 69 host, 60 user, 24 domain) → `<host>`, `<user>`, `<domain>`,
  - GUID → `<guid>`, SID → `<sid>`, IP → `<ip>`, hex → `<hex>`, số ≥4 chữ số → `<num>`.

  Riêng `InterfaceUuid` của RPC giữ nguyên, vì đó là hằng số của giao thức chứ không phải định danh ngẫu nhiên.
- **Khử trùng lặp:** các event giống hệt nhau sau khi chuẩn hoá, trong cùng `group` và cùng nhãn, chỉ giữ 1 dòng. Cột `n_dup` là số event gốc mà dòng đó đại diện.

  Kết quả: 616,169 event, bỏ 59,294 event nạp DLL hệ thống, còn 107,442 dòng, 373 group. Riêng Mordor `credential-access` giảm từ 42,634 event xuống 4,222 dòng, vì Invoke-Mimikatz lặp lại rất nhiều.

## Các cột

| Nhóm                                     | Cột                                                                                                                                                       | Ghi chú                                                                                     |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **meta, không dùng làm feature** | `dataset`                                                                                                                                                | `mordor` / `evtx`                                                                        |
|                                           | `group`                                                                                                                                                  | `<dataset>:<kịch bản>`. Dùng cho `GroupKFold`; Mordor gộp các file cùng kịch bản |
|                                           | `label`                                                                                                                                                  | benign / tactic / command-and-control                                                        |
|                                           | `label_malicious`                                                                                                                                        | 1 / 0                                                                                        |
|                                           | `label_method`                                                                                                                                           | lý do gán nhãn                                                                            |
|                                           | `n_dup`                                                                                                                                                  | số event gốc trùng nhau                                                                   |
| loại event                               | `provider`, `event_id`                                                                                                                                 |                                                                                              |
| process                                   | `image`, `parent_image`, `target_image`                                                                                                              | tên file, chữ thường                                                                     |
|                                           | `image_path`                                                                                                                                             | thư mục của image, đã chuẩn hoá                                                       |
|                                           | `integrity_level`, `user_type`, `logon_type`                                                                                                         | `user_type`: system / service / anonymous / machine / virtual / admin / user               |
| quyền / đối tượng                    | `granted_access`, `access_mask`, `object_type`, `registry_event`, `module_signed`, `signature_status`, `auth_package`, `ticket_encryption` |                                                                                              |
| mạng                                     | `protocol`, `dst_port` (-1 nếu không có), `dst_ip_type`, `network_direction`                                                                    | `dst_ip_type`: loopback / linklocal_multicast / private / public                           |
| văn bản                                 | `cmdline`, `parent_cmdline`, `ps_host_app`, `ps_text`                                                                                              | `ps_text` = ScriptBlock + CommandLine + Payload của PowerShell, cắt ở 4,000 ký tự     |
|                                           | `registry`, `file_path`, `module_path`, `pipe`, `share`, `object_name`, `service`, `dns_query`                                             |                                                                                              |
|                                           | `other_text`                                                                                                                                             | các trường còn lại dạng `key=value` (RPC, BITS, RdpCoreTS, MSSQL...)                 |
| số                                       | `cmd_len`, `cmd_entropy`, `cmd_has_b64`, `ps_len`, `ps_has_b64`                                                                                  |                                                                                              |

Bảng mới chỉ chứa giá trị đã làm sạch, chưa vector hoá. Bước vector hoá làm lúc train: one-hot / target encoding cho cột phân loại, TF-IDF char n-gram hoặc hashing cho cột văn bản.

## Số dòng (events = tổng `n_dup`)

| Nhãn                | Mordor: dòng | Mordor: event | EVTX: dòng | EVTX: event |
| -------------------- | ------------- | ------------- | ----------- | ----------- |
| benign               | 88,280        | 431,779       | 1,380       | 32,202      |
| command-and-control  | 3,649         | 24,804        | 125         | 216         |
| credential-access    | 4,222         | 42,634        | 181         | 256         |
| defense-evasion      | 1,930         | 11,212        | 175         | 332         |
| lateral-movement     | 3,946         | 8,173         | 937         | 1,250       |
| discovery            | 911           | 1,337         | 84          | 137         |
| privilege-escalation | 476           | 944           | 465         | 504         |
| persistence          | 226           | 358           | 146         | 262         |
| execution            | 157           | 309           | 152         | 166         |

`collection` (12 dòng) không còn: toàn bộ là event nạp DLL hệ thống, đã bị bỏ.

## Khi train:

- **Chia train/test theo `group`** (`GroupKFold`), không chia random theo dòng.
- **Không dùng các cột meta làm feature.** `train.py` dùng `min(n_dup, 10)` làm `sample_weight` để vài event nền lặp hàng nghìn lần không lấn át.
