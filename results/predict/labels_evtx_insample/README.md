# Kết quả trên toàn bộ EVTX đã gán nhãn (in-sample)

- Đầu vào: `data/interim/labels/evtx/`: 274 file, 36,659 event, có nhãn từng event.
- Model: model cuối trong `models/`. Model này **đã được train trên chính các event này** (in-sample), nên số liệu ở đây cao hơn trên dữ liệu chưa thấy. Số liệu trên kịch bản chưa thấy nằm ở `../holdout_cv_fold1/`.

```bash
python src/alert.py data/interim/labels/evtx --out results/predict/labels_evtx_insample
```

| Chỉ số | Giá trị |
|---|---|
| event đầu vào | 36,659 (274 file) |
| ngoài phạm vi (Sysmon 7 nạp DLL hệ thống) | 546 |
| event bị báo độc hại | 3,794 |
| cảnh báo | 326 (high 123, medium 185, low 18) |
| cảnh báo đúng (có ít nhất 1 event độc hại thật) | 311/314 (0.99); 12 cảnh báo chỉ gồm event uncertain, không tính |
| event độc hại thật nằm trong cảnh báo | 0.943 (2,945/3,123) |
| file có tấn công được cảnh báo | 272/274 |

| File | Nội dung |
|---|---|
| `predictions.csv`, `summary.md` | kết quả `predict.py` theo từng event, kèm nhãn thật (`true_label`, `true_malicious`) |
| `alerts.md` | 326 cảnh báo: tóm tắt, chỉ số so với nhãn, chi tiết |
| `alerts.csv` | mỗi cảnh báo 1 dòng (có cột `true_malicious_events` / `true_benign_events` / `true_uncertain_events`) |
| `alert_events.csv` | các event của từng cảnh báo, kèm nhãn thật |

`predictions.csv` và `alert_events.csv` không có trong repo vì dung lượng lớn; chạy lại lệnh ở trên để tạo.

Tên file trong cột `file` / `files` là đường dẫn tương đối trong `data/interim/labels/evtx/` (`<tactic>/<file>.json`).
