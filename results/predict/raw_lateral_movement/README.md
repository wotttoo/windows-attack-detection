# Kết quả trên file .evtx thô (Lateral Movement)

- Đầu vào: 47 file `.evtx` gốc trong `data/raw/EVTX-ATTACK-SAMPLES/Lateral Movement/`, chưa qua chuyển JSON, chuẩn hoá hay gán nhãn.
- Model: model cuối trong `models/`, train trên toàn bộ dataset (đã gồm các file này).
- Mục đích: chạy toàn bộ quy trình trên log Windows thật: `.evtx` → OSSEM → chấm từng event → gộp cảnh báo.
- Đầu vào không có nhãn, nên `predictions.csv` không có cột `true_label` / `true_malicious`, và `alerts.md` / `summary.md` không có phần so với nhãn.

```bash
python src/alert.py "data/raw/EVTX-ATTACK-SAMPLES/Lateral Movement" --out results/predict/raw_lateral_movement
```

| Chỉ số | Giá trị |
|---|---|
| event đầu vào | 1,288 (47 file) |
| ngoài phạm vi (Sysmon 7 nạp DLL hệ thống) | 3 |
| event bị báo độc hại | 1,235 |
| cảnh báo | 68 (high 28, medium 37, low 3) |

| File | Nội dung |
|---|---|
| `predictions.csv`, `summary.md` | kết quả `predict.py` theo từng event |
| `alerts.md` | 68 cảnh báo: tóm tắt và chi tiết |
| `alerts.csv` | mỗi cảnh báo 1 dòng |
| `alert_events.csv` | các event của từng cảnh báo |

`predictions.csv` và `alert_events.csv` không có trong repo vì dung lượng lớn; chạy lại lệnh ở trên để tạo.
