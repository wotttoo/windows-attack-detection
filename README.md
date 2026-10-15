# Phát hiện hành vi tấn công trên log Windows

Model phát hiện event độc hại trong log Windows (Sysmon, Security, PowerShell…), đoán tactic MITRE ATT&CK, rồi gộp các event độc hại thành cảnh báo theo chuỗi hành vi. Dữ liệu train là hai bộ mô phỏng tấn công công khai: [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) và [Mordor](https://github.com/OTRF/mordor) (`small/windows`).

## Kết quả chính

Đánh giá trên kịch bản model chưa thấy lúc train (GroupKFold 5 fold theo kịch bản, cả hai bộ):

| Chỉ số (theo event)                          | Giá trị |
| ---------------------------------------------- | --------- |
| Recall: event tấn công bị phát hiện       | 0.942     |
| Precision: event bị báo là độc hại thật | 0.844     |
| F1                                             | 0.890     |
| Báo nhầm: event benign bị báo độc hại   | 3.5%      |
| Tactic macro-F1                                | 0.353     |

Gộp thành cảnh báo trên 75 kịch bản chưa thấy: 8,251 event bị báo → 103 cảnh báo, 91 cảnh báo đúng (0.88), 72/75 file có tấn công được cảnh báo.

Chi tiết: [`results/report.md`](results/report.md) và [`results/predict/holdout_cv_fold1/`](results/predict/holdout_cv_fold1/).

## Cấu trúc

```
.
├── src/                    code, chạy theo thứ tự (1)–(8)
│   ├── evtx2json.py        (1) .evtx → JSON lines
│   ├── ossem_normalize.py  (2) chuẩn hoá hai bộ về schema OSSEM
│   ├── label_events.py     (3) gán nhãn từng event cho Mordor
│   ├── label_evtx.py       (4) gán nhãn từng event cho EVTX
│   ├── build_dataset.py    (5) gộp thành bảng feature
│   ├── behavior.py             feature hành vi (dùng bởi train / predict)
│   ├── train.py            (6) train + đánh giá model 2 bước (Logistic Regression)
│   ├── predict.py          (7) dự đoán từng event của log mới
│   ├── alert.py            (8) gộp event độc hại thành cảnh báo
│   └── paths.py                đường dẫn mặc định
├── configs/                luật gán nhãn (label_seeds*.yaml), bảng map OSSEM
├── data/
│   ├── raw/                dữ liệu gốc (không có trong repo, xem mục Tải dữ liệu gốc)
│   ├── interim/            kết quả trung gian (1)–(4) (không có trong repo)
│   └── processed/          events.parquet: bảng feature để train
├── models/                 model cuối: binary.joblib, tactic.joblib
├── results/                report.md, metrics.json, dự đoán cv/mix, predict/<tên>/ (kết quả mẫu)
└── docs/                   tài liệu chi tiết
```

## Cài đặt

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Các lệnh dưới đây chạy từ thư mục gốc của project.

## Sử dụng

**Dự đoán và tạo cảnh báo cho log mới**, dùng model có sẵn trong `models/`:

```bash
python src/alert.py <file hoặc thư mục .evtx / .json>
# kết quả: results/predict/<tên>/predictions.csv, summary.md, alerts.md, alerts.csv
```

**Train lại** từ `data/processed/events.parquet` có sẵn:

```bash
python src/train.py                  # đánh giá cv + mix và train model cuối (~26 phút, RAM ~3 GB)
python src/train.py --eval none      # chỉ train model cuối (~3 phút)
python src/train.py --report-only    # viết lại results/report.md từ dự đoán đã lưu
```

**Chạy lại toàn bộ từ dữ liệu gốc** (cần [tải dữ liệu gốc](#tải-dữ-liệu-gốc) trước):

```bash
python src/evtx2json.py data/raw/EVTX-ATTACK-SAMPLES data/interim/evtx_json
python src/ossem_normalize.py run --evtx data/interim/evtx_json --mordor data/raw/mordor/datasets --out data/interim/ossem
python src/label_events.py --all data/interim/ossem/mordor --out data/interim/labels/mordor
python src/label_evtx.py --all data/interim/ossem/evtx --out data/interim/labels/evtx
python src/build_dataset.py
python src/train.py
```

## Tải dữ liệu gốc

```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES data/raw/EVTX-ATTACK-SAMPLES
git clone https://github.com/OTRF/mordor data/raw/mordor
# Mordor: giải nén các file .zip trong datasets/small/windows/ vào thư mục cùng tên
find data/raw/mordor/datasets/small/windows -name '*.zip' -execdir sh -c 'unzip -oq "$1" -d "${1%.zip}"' _ {} \;
```

## Tài liệu

| File                                                  | Nội dung                                                          |
| ----------------------------------------------------- | ------------------------------------------------------------------ |
| [`docs/QUA_TRINH_XU_LY.md`](docs/QUA_TRINH_XU_LY.md) | toàn bộ quy trình, lý do từng bước, kết quả               |
| [`docs/ossem.md`](docs/ossem.md)                     | chuẩn hoá OSSEM: trường chung, quy tắc                        |
| [`docs/labels.md`](docs/labels.md)                   | cột nhãn, ý nghĩa `label_method`, cách gán nhãn từng bộ |
| [`docs/dataset.md`](docs/dataset.md)                 | các cột của `events.parquet`                                  |
| [`results/report.md`](results/report.md)             | kết quả train và đánh giá                                    |

## Giới hạn

- Nhãn từng event được gán tự động theo luật (`configs/`), không phải nhãn do người gán tay.
- Báo nhầm khoảng 3.5% event benign; đoán tactic còn yếu (macro-F1 0.35).
- Hai bộ dữ liệu không có log thuần benign, nên chưa đo được số cảnh báo sai mỗi ngày trên một máy bình thường.

## Dữ liệu và giấy phép

EVTX-ATTACK-SAMPLES và Mordor dùng giấy phép GPL-3.0. Dữ liệu gốc không nằm trong repo; `data/processed/events.parquet` là dữ liệu dẫn xuất từ hai bộ này.
