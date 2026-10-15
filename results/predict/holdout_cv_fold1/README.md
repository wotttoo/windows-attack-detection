# Kết quả trên dữ liệu chưa thấy (holdout)

Khác với các thư mục khác trong `results/predict/`, model dùng ở đây **không** phải model cuối trong `models/`:

- Model tạm được train trên dataset **bỏ ra 75 kịch bản** (fold 1 trong 5 fold GroupKFold của `train.py`, `random_state=0`).
- Sau đó `alert.py` chạy trên log đã gán nhãn của chính 75 kịch bản đó (65,559 event, có cả nhiễu nền).
- Model tạm không được lưu lại.

Vì model chưa thấy các kịch bản này, số liệu ở đây phản ánh cách hệ thống xử lý tấn công mới. Bảng tóm tắt nằm ở `QUA_TRINH_XU_LY.md` mục 8.

| File | Nội dung |
|---|---|
| `alerts.md` | 103 cảnh báo: tóm tắt, chỉ số so với nhãn, chi tiết |
| `alerts.csv` | mỗi cảnh báo 1 dòng (có cột `true_malicious_events` / `true_benign_events` để đối chiếu) |
| `alert_events.csv` | các event của từng cảnh báo, kèm nhãn thật |
| `predictions.csv`, `summary.md` | kết quả `predict.py` theo từng event |

`predictions.csv` và `alert_events.csv` chỉ có ở bản local, không có trong repo vì dung lượng lớn (model tạm dùng cho holdout không được lưu, nên không tạo lại được bằng một lệnh).

Tên file log có dạng `labels__mordor__<tactic>__...`: đường dẫn gốc trong `data/interim/labels/`, dấu `/` được thay bằng `__`.
