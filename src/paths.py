"""Đường dẫn mặc định của project (tính từ thư mục gốc, nên chạy script từ đâu cũng được)."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIGS = os.path.join(ROOT, 'configs')
SEEDS = os.path.join(CONFIGS, 'label_seeds.yaml')            # hạt giống Mordor + mẫu chung
SEEDS_EVTX = os.path.join(CONFIGS, 'label_seeds_evtx.yaml')  # luật gán nhãn EVTX
OSSEM_MAP = os.path.join(CONFIGS, 'ossem_dd_windows.json')   # bảng map trường -> OSSEM

DATA = os.path.join(ROOT, 'data')
RAW_EVTX = os.path.join(DATA, 'raw', 'EVTX-ATTACK-SAMPLES')
RAW_MORDOR = os.path.join(DATA, 'raw', 'mordor', 'datasets')
MORDOR_METADATA = os.path.join(RAW_MORDOR, 'metadata')
EVTX_JSON = os.path.join(DATA, 'interim', 'evtx_json')
OSSEM = os.path.join(DATA, 'interim', 'ossem')
LABELS = os.path.join(DATA, 'interim', 'labels')
DATASET = os.path.join(DATA, 'processed', 'events.parquet')

MODELS = os.path.join(ROOT, 'models')
RESULTS = os.path.join(ROOT, 'results')
