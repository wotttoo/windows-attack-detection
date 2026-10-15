"""Train và đánh giá model trên data/processed/events.parquet (tạo bởi build_dataset.py).

Feature (prepare):
  - behavior.py: tên process / cổng / mã quyền -> nhóm hành vi + cờ hành vi, che tên .exe trong văn bản
  - one-hot cho cột phân loại, TF-IDF char n-gram (3-5) cho 3 nhóm văn bản (process / powershell / object),
    cột số qua log1p + MaxAbsScaler. Bộ vector hoá được fit lại trong mỗi lần chia, chỉ trên phần train.
Trọng số mẫu: min(n_dup, 10), sau đó cân bằng theo lớp.

Model 2 bước, Logistic Regression (liblinear):
  1. binary: độc hại (label_malicious=1) hay benign
  2. tactic: chỉ trên dòng độc hại, one-vs-rest, 8 lớp (lớp collection chỉ có 12 dòng, đều là Sysmon 7 nạp DLL hệ
     thống nên đã bị build_dataset bỏ; nếu còn, ví dụ khi dùng --keep-sys-dll, thì cũng bị bỏ ở đây)

Đánh giá (--eval, mặc định cả 2):
  - cv:   GroupKFold 5 fold theo group trên toàn bộ dữ liệu (cả file / kịch bản nằm trọn ở train hoặc test)
  - mix:  file EVTX chia 5 fold (StratifiedGroupKFold); train toàn bộ Mordor + 4 fold EVTX, test fold còn lại
          (file EVTX chưa thấy, tập train gồm cả hai bộ như model cuối).
Chỉ số tính theo dòng (sau khử trùng) và theo event gốc (trọng số n_dup); thêm tỉ lệ báo nhầm trên event benign.

Model cuối: train trên toàn bộ dữ liệu -> models/{binary,tactic}.joblib (featurizer + model), dùng bởi predict.py.
Kết quả: results/report.md, results/metrics.json, results/pred_<cv|mix>.parquet (dự đoán để phân tích lỗi).

Dùng:
  python src/train.py                  # 2 cách đánh giá + model cuối (~26 phút, RAM ~3 GB)
  python src/train.py --eval none      # chỉ train model cuối (~3 phút)
  python src/train.py --eval mix --no-final
  python src/train.py --report-only    # chỉ viết lại report.md từ results/pred_*.parquet (vài giây)
"""
import os, json, time, argparse, warnings
import numpy as np
import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import OneHotEncoder, MaxAbsScaler, FunctionTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
from sklearn.metrics import (average_precision_score, roc_auc_score, precision_recall_fscore_support,
                             f1_score, classification_report, confusion_matrix)
import sklearn

import behavior as B

sklearn.set_config(enable_metadata_routing=True)  # để OneVsRestClassifier nhận sample_weight

warnings.filterwarnings('ignore', category=UserWarning)
import paths

# tên process, cổng, mã quyền không vào trực tiếp: behavior.py thay bằng nhóm (BEH_CAT)
CAT = ['provider', 'event_id', 'integrity_level', 'user_type', 'logon_type', 'object_type', 'registry_event',
       'module_signed', 'signature_status', 'auth_package', 'ticket_encryption', 'protocol', 'dst_ip_type',
       'network_direction'] + B.BEH_CAT
NUM = ['cmd_len', 'cmd_entropy', 'cmd_has_b64', 'ps_len', 'ps_has_b64'] + B.BEH_FLAGS
TEXT = {
    't_proc': ['cmdline', 'parent_cmdline', 'ps_host_app'],
    't_ps': ['ps_text'],
    't_obj': ['image_path', 'registry', 'file_path', 'module_path', 'pipe', 'share', 'object_name', 'service',
              'dns_query', 'other_text'],
}
TEXT_LIMIT = 2000           # ký tự / nhóm văn bản đưa vào TF-IDF
MAX_TEXT_FEATURES = 20000   # feature TF-IDF / nhóm
DROP_TACTICS = {'collection'}
FOLDS = 5
EVALS = ('cv', 'mix')


def prepare(df):
    """Bảng từ build_dataset (hoặc predict.py) -> bảng sẵn sàng cho featurizer."""
    df = B.add(df)
    B.mask_text(df, sorted({c for cols in TEXT.values() for c in cols}))
    for c in CAT:
        df[c] = df[c].astype(str)
    for name, cols in TEXT.items():
        df[name] = df[cols].astype(str).agg(' | '.join, axis=1).str.slice(0, TEXT_LIMIT)
    return df


def load(path):
    df = prepare(pd.read_parquet(path))
    df['w'] = np.minimum(df['n_dup'], 10).astype(float)
    return df


def featurizer():
    tfidf = lambda: TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), min_df=3, max_features=MAX_TEXT_FEATURES,
                                    sublinear_tf=True, dtype=np.float32)
    return ColumnTransformer([
        ('cat', OneHotEncoder(handle_unknown='infrequent_if_exist', min_frequency=3, dtype=np.float32), CAT),
        ('num', make_pipeline(FunctionTransformer(np.log1p, feature_names_out='one-to-one'), MaxAbsScaler()), NUM),
        *[(name, tfidf(), name) for name in TEXT],
    ], sparse_threshold=1.0)


def make_model(multi, jobs):
    # one-vs-rest liblinear: saga đa lớp hội tụ rất chậm trên ma trận TF-IDF thưa
    lr = LogisticRegression(C=4.0, solver='liblinear')
    return OneVsRestClassifier(lr.set_fit_request(sample_weight=True), n_jobs=jobs) if multi else lr


def balanced(w, y):
    """Trọng số mẫu cân bằng theo lớp (tổng trọng số mỗi lớp như nhau)."""
    w = w.copy()
    tot = w.sum()
    classes = np.unique(y)
    for c in classes:
        m = y == c
        w[m] *= tot / (len(classes) * w[m].sum())
    return w


def tactic_rows(d):
    return (d['label_malicious'].values == 1) & ~d['label'].isin(DROP_TACTICS).values


def fit(dtr, jobs):
    """Fit featurizer + 2 model trên dtr."""
    feat = featurizer()
    X = feat.fit_transform(dtr)
    y, w = dtr['label_malicious'].values, dtr['w'].values
    mb = make_model(False, jobs)
    mb.fit(X, y, sample_weight=balanced(w, y))
    tm = tactic_rows(dtr)
    mt = make_model(True, jobs)
    mt.fit(X[tm], dtr['label'].values[tm], sample_weight=balanced(w[tm], dtr['label'].values[tm]))
    return feat, mb, mt


def run_split(df, tr, te, jobs):
    """tr, te: mảng bool. Trả về (xác suất độc hại, tactic dự đoán) cho các dòng te."""
    feat, mb, mt = fit(df[tr], jobs)
    Xte = feat.transform(df[te])
    return mb.predict_proba(Xte)[:, 1], mt.predict(Xte)


# ---------------------------------------------------------------- chỉ số
def binary_metrics(y, p, n_dup):
    pred = (p >= 0.5).astype(int)
    out = {}
    for tag, sw in (('row', None), ('event', n_dup)):
        w = np.ones(len(y)) if sw is None else sw
        pr, rc, f1, _ = precision_recall_fscore_support(y, pred, average='binary', sample_weight=sw, zero_division=0)
        out[tag] = dict(pr_auc=average_precision_score(y, p, sample_weight=sw),
                        roc_auc=roc_auc_score(y, p, sample_weight=sw) if len(set(y)) > 1 else float('nan'),
                        precision=pr, recall=rc, f1=f1,
                        fpr=w[(y == 0) & (pred == 1)].sum() / max(w[y == 0].sum(), 1))
    return out


def tactic_metrics(y, pred, n_dup, labels):
    out = {}
    for tag, sw in (('row', None), ('event', n_dup)):
        out[tag] = dict(macro_f1=f1_score(y, pred, labels=labels, average='macro', sample_weight=sw, zero_division=0),
                        weighted_f1=f1_score(y, pred, labels=labels, average='weighted', sample_weight=sw,
                                             zero_division=0))
    out['per_class'] = {k: v for k, v in classification_report(y, pred, labels=labels, output_dict=True,
                                                                sample_weight=n_dup, zero_division=0).items()
                        if k in labels}
    out['confusion'] = dict(labels=labels, matrix=confusion_matrix(y, pred, labels=labels).tolist())
    return out


def evaluate(pred, labels):
    """pred: bảng dự đoán (group, label, label_malicious, n_dup, p, tactic_pred)."""
    y, nd = pred['label_malicious'].values, pred['n_dup'].values
    tm = tactic_rows(pred)
    fp = pred[(y == 0) & (pred['p'].values >= 0.5)].groupby('group')['n_dup'].sum().sort_values(ascending=False)
    by_ds = {ds: dict(binary=binary_metrics(g['label_malicious'].values, g['p'].values, g['n_dup'].values),
                      n_groups=int(g['group'].nunique()),
                      n_mal_events=int(g.loc[g.label_malicious == 1, 'n_dup'].sum()),
                      n_benign_events=int(g.loc[g.label_malicious == 0, 'n_dup'].sum()))
             for ds, g in pred.groupby('dataset')}
    return dict(binary=binary_metrics(y, pred['p'].values, nd), by_dataset=by_ds,
                tactic=tactic_metrics(pred['label'].values[tm], pred['tactic_pred'].values[tm].astype(str), nd[tm],
                                      labels),
                n_mal_events=int(nd[y == 1].sum()), n_benign_events=int(nd[y == 0].sum()),
                top_fp_files=[(g, int(n)) for g, n in fp.head(5).items()])


# ---------------------------------------------------------------- 2 cách đánh giá
def splits(df, kind):
    """-> danh sách (tr, te) mảng bool."""
    n = len(df)
    is_e = (df['dataset'] == 'evtx').values
    out = []
    if kind == 'cv':
        for a, _ in GroupKFold(n_splits=FOLDS, shuffle=True, random_state=0).split(df, groups=df['group']):
            tr = np.zeros(n, bool); tr[a] = True
            out.append((tr, ~tr))
    else:  # mix
        eidx = np.where(is_e)[0]
        sgk = StratifiedGroupKFold(FOLDS, shuffle=True, random_state=0)
        for a, b in sgk.split(eidx, df['label'].values[eidx], df['group'].values[eidx]):
            tr = ~is_e; tr[eidx[a]] = True
            te = np.zeros(n, bool); te[eidx[b]] = True
            out.append((tr, te))
    return out


def run_eval(df, kind, jobs):
    sel = np.zeros(len(df), bool)
    p = np.full(len(df), np.nan)
    t = np.full(len(df), None, dtype=object)
    for i, (tr, te) in enumerate(splits(df, kind)):
        t0 = time.time()
        p[te], t[te] = run_split(df, tr, te, jobs)
        sel |= te
        print(f'  {kind} {i + 1}: train {tr.sum()} dòng, test {te.sum()} dòng, {time.time() - t0:.0f}s', flush=True)
    pred = df.loc[sel, ['dataset', 'group', 'label', 'label_malicious', 'n_dup', 'provider', 'event_id', 'image',
                        'cmdline']].copy()
    pred['p'], pred['tactic_pred'] = p[sel], t[sel]
    return pred


# ---------------------------------------------------------------- báo cáo
TITLES = {'cv': 'cv: kịch bản chưa thấy (cả hai bộ)',
          'mix': 'mix: file EVTX chưa thấy'}
DS_NAME = {'mordor': 'Mordor', 'evtx': 'EVTX'}
FEAT_PREFIX = [
    ('cat__<cột>_<giá trị>', 'cột phân loại mang giá trị đó, ví dụ `cat__event_id_4688` = event Security 4688, '
                             '`cat__img_class_office` = process thuộc nhóm Office (nhóm do behavior.py đặt)'),
    ('num__<tên>', 'feature số / cờ hành vi, ví dụ `num__f_encoded` = có lệnh mã hoá base64'),
    ('t_proc__<chuỗi>', 'đoạn ký tự 3–5 ký tự trong command line (của process và process cha)'),
    ('t_ps__<chuỗi>', 'đoạn ký tự trong nội dung PowerShell'),
    ('t_obj__<chuỗi>', 'đoạn ký tự trong đường dẫn file / registry / DLL / pipe / share / service / DNS'),
]


def _row(name, b, n_mal):
    return (f"| {name} | {n_mal:,} | {b['precision']:.3f} | {b['recall']:.3f} | {b['f1']:.3f} | "
            f"{b['pr_auc']:.3f} | {b['fpr']:.2%} |")


def fmt_report(metrics, df, labels):
    ev = [k for k in EVALS if k in metrics]
    ds_list = [d for d in ('mordor', 'evtx') if d in set(df['dataset'])]
    L = ['# Kết quả train và đánh giá model\n']

    # 1. tóm tắt
    if 'cv' in metrics:
        b, t = metrics['cv']['binary']['event'], metrics['cv']['tactic']['event']
        L += ['## 1. Tóm tắt\n',
              f"Trên các kịch bản model chưa thấy lúc train (đánh giá `cv`, gồm cả Mordor và EVTX):\n",
              f"- Model bắt được **{b['recall']:.0%}** event tấn công (recall {b['recall']:.3f}).",
              f"- Trong số event bị báo độc hại, **{b['precision']:.0%}** là độc hại thật (precision "
              f"{b['precision']:.3f}); F1 **{b['f1']:.3f}**.",
              f"- **{b['fpr']:.1%}** event benign bị báo nhầm là độc hại.",
              f"- Đoán đúng tactic còn yếu: macro-F1 **{t['macro_f1']:.3f}**. Tốt nhất ở "
              + ', '.join(f"{lab} ({v['f1-score']:.2f})" for lab, v in sorted(
                  metrics['cv']['tactic']['per_class'].items(), key=lambda kv: -kv[1]['f1-score'])[:3]) + '.']
        if 'mix' in metrics:
            m = metrics['mix']['binary']['event']
            L.append(f"- Trên file EVTX chưa thấy (đánh giá `mix`): recall {m['recall']:.3f}, precision "
                     f"{m['precision']:.3f}, F1 {m['f1']:.3f}, báo nhầm {m['fpr']:.1%}.")
        L.append('')

    # 2. dữ liệu
    L += ['## 2. Dữ liệu\n',
          '`data/processed/events.parquet`, tạo bởi `src/build_dataset.py`. Một **dòng** là một event sau khử trùng; '
          'cột `n_dup` ghi số **event** gốc giống hệt nhau mà dòng đó đại diện. '
          '**Group** là một kịch bản Mordor hoặc một file EVTX.\n',
          '| Bộ | Group | Dòng | Event | Event độc hại | Event benign |', '|---|---|---|---|---|---|']
    for d in ds_list + ['all']:
        g = df if d == 'all' else df[df['dataset'] == d]
        nd, y = g['n_dup'], g['label_malicious']
        L.append(f"| {'**Tổng**' if d == 'all' else DS_NAME[d]} | {g['group'].nunique()} | {len(g):,} | "
                 f"{int(nd.sum()):,} | {int(nd[y == 1].sum()):,} | {int(nd[y == 0].sum()):,} |")
    mal = df[df['label_malicious'] == 1]
    L += ['\nEvent độc hại theo tactic:\n', '| Tactic | Group có tactic | Dòng | Event |', '|---|---|---|---|']
    for lab in labels:
        g = mal[mal['label'] == lab]
        L.append(f"| {lab} | {g['group'].nunique()} | {len(g):,} | {int(g['n_dup'].sum()):,} |")

    # 3. model
    L += ['\n## 3. Model\n',
          '- Feature: nhóm hành vi và cờ hành vi (`behavior.py`), one-hot các cột phân loại, TF-IDF đoạn ký tự '
          '(3–5 ký tự) cho command line / PowerShell / đường dẫn, các cột số.',
          '- Logistic Regression 2 bước:',
          '  1. **binary**: event độc hại hay benign (báo độc hại khi xác suất ≥ 0.5);',
          f'  2. **tactic**: với event độc hại, đoán 1 trong {len(labels)} tactic.',
          '- Trọng số mẫu `min(n_dup, 10)`, rồi cân bằng để tổng trọng số mỗi lớp bằng nhau.',
          '- Tham số cố định (`C=4.0`, ngưỡng 0.5), không dò trên tập test.\n']

    # 4. cách đánh giá
    L += ['## 4. Cách đánh giá\n',
          'Không có tập test cố định. Dữ liệu được chia xoay vòng 5 lần; mỗi lần train trên một phần, test trên '
          'phần còn lại. Một group luôn nằm trọn ở train hoặc test, nên lúc test model chưa thấy kịch bản / file '
          'đó. Kết quả test của 5 lần được gộp lại thành các bảng dưới.\n',
          '| Đánh giá | Train mỗi lần | Test mỗi lần | Sau 5 lần đã test | Trả lời câu hỏi |', '|---|---|---|---|---|',
          '| `cv` | 4/5 số group (cả hai bộ) | 1/5 group còn lại | mọi group của cả hai bộ | phát hiện tấn công '
          'trong kịch bản mới, cùng môi trường |',
          '| `mix` | toàn bộ Mordor + 4/5 file EVTX | 1/5 file EVTX còn lại | mọi file EVTX | phát hiện trên file '
          'EVTX chưa thấy khi train gồm cả hai bộ |',
          '\n**Model cuối** (`models/binary.joblib`, `models/tactic.joblib`) được train trên toàn bộ dữ liệu; '
          'độ chính xác của nó được ước lượng bằng các số `cv` / `mix` ở đây.\n',
          'Đánh giá **cảnh báo** (gộp event thành cảnh báo bằng `alert.py`) trên 75 group của lần 1 trong `cv`: '
          'xem `results/predict/holdout_cv_fold1/`.\n']

    # 5. cách đọc chỉ số
    L += ['## 5. Cách đọc chỉ số\n',
          '| Chỉ số | Ý nghĩa |', '|---|---|',
          '| Precision | trong các event bị báo độc hại, bao nhiêu phần là độc hại thật |',
          '| Recall | trong các event độc hại thật, bao nhiêu phần bị báo |',
          '| F1 | trung bình điều hoà của precision và recall |',
          '| PR-AUC | chất lượng xếp hạng theo xác suất độc hại, không phụ thuộc ngưỡng 0.5 (1 là tốt nhất) |',
          '| Báo nhầm | tỉ lệ event benign bị báo độc hại |',
          '| Macro-F1 tactic | trung bình F1 của các tactic, mỗi tactic nặng như nhau; tính trên mọi event độc hại '
          'thật, không phụ thuộc bước binary có báo event đó hay không |',
          '\nCác bảng chính tính **theo event** (mỗi dòng nhân với `n_dup`). Bảng theo dòng nằm ở phụ lục.\n']

    # 6. binary
    hdr = ['| Phần dữ liệu test | Event độc hại | Precision | Recall | F1 | PR-AUC | Báo nhầm |',
           '|---|---|---|---|---|---|---|']
    L += ['## 6. Phát hiện độc hại / benign\n'] + hdr
    for k in ev:
        L.append(_row(f'**{TITLES[k]}**', metrics[k]['binary']['event'], metrics[k]['n_mal_events']))
        bd = metrics[k].get('by_dataset', {})
        if len(bd) > 1:
            for d in ds_list:
                if d in bd:
                    L.append(_row(f'&nbsp;&nbsp;↳ phần {DS_NAME[d]} ({bd[d]["n_groups"]} group)',
                                  bd[d]['binary']['event'], bd[d]['n_mal_events']))
    L.append('\n`cv` gồm phần lớn là event Mordor, nên số tổng của `cv` gần với số của phần Mordor.\n')

    # 7. tactic
    L += ['## 7. Đoán tactic\n',
          'F1 của từng tactic (theo event). Cột "Event" là số event độc hại thật của tactic đó trong phần test.\n',
          '| Tactic | ' + ' | '.join(f'F1 {k} | Event {k}' for k in ev) + ' |', '|---|' + '---|---|' * len(ev)]
    for lab in labels:
        cells = []
        for k in ev:
            v = metrics[k]['tactic']['per_class'].get(lab, {})
            cells += [f"{v.get('f1-score', 0):.3f}", f"{int(v.get('support', 0)):,}"]
        L.append(f'| {lab} | ' + ' | '.join(cells) + ' |')
    L.append('| **macro-F1** | ' + ' | '.join(f"**{metrics[k]['tactic']['event']['macro_f1']:.3f}** | "
                                             for k in ev) + ' |\n')

    # 8. báo nhầm
    L += ['## 8. Group có nhiều event báo nhầm nhất\n',
          'Số trong ngoặc là số event benign của group đó bị báo độc hại.\n']
    for k in ev:
        L.append(f'- **{k}:** ' + ', '.join(f'`{g}` ({n:,})' for g, n in metrics[k]['top_fp_files']))
    L.append('')

    # 9. feature
    if 'importance' in metrics:
        L += ['## 9. Feature quan trọng nhất của model cuối\n',
              'Các feature có hệ số dương lớn nhất trong Logistic Regression, tức là đẩy dự đoán về phía độc hại '
              '(binary) hoặc về phía tactic đó. Cách đọc tên feature:\n',
              '| Dạng tên | Ý nghĩa |', '|---|---|'] + [f'| `{a}` | {b} |' for a, b in FEAT_PREFIX] + ['']
        for task, items in metrics['importance'].items():
            L.append(f'**{task}:** ' + ', '.join(f'`{n}`' for n, _ in items[:15]) + '\n')

    # phụ lục
    L += ['## Phụ lục: chỉ số theo dòng (sau khử trùng, không nhân `n_dup`)\n',
          '| Đánh giá | PR-AUC | ROC-AUC | Precision | Recall | F1 | Tactic macro-F1 |', '|---|---|---|---|---|---|---|']
    for k in ev:
        r, t = metrics[k]['binary']['row'], metrics[k]['tactic']['row']
        L.append(f"| {k} | {r['pr_auc']:.3f} | {r['roc_auc']:.3f} | {r['precision']:.3f} | {r['recall']:.3f} | "
                 f"{r['f1']:.3f} | {t['macro_f1']:.3f} |")
    return '\n'.join(L) + '\n'


def lr_importance(task, m, names, k=40):
    """Hệ số dương lớn nhất của LR (đẩy về độc hại / về từng tactic)."""
    if hasattr(m, 'estimators_'):
        return {f'{task}:{c}': [(str(names[i]), float(e.coef_[0][i])) for i in np.argsort(e.coef_[0])[::-1][:k]]
                for c, e in zip(m.classes_, m.estimators_)}
    w = m.coef_[0]
    return {task: [(str(names[i]), float(w[i])) for i in np.argsort(w)[::-1][:k]]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default=paths.DATASET)
    ap.add_argument('--results', default=paths.RESULTS)
    ap.add_argument('--models', default=paths.MODELS)
    ap.add_argument('--eval', default=','.join(EVALS), help='cv,mix hoặc none')
    ap.add_argument('--no-final', action='store_true', help='không train model cuối trên toàn bộ dữ liệu')
    ap.add_argument('--jobs', type=int, default=4, help='số tiến trình cho LR one-vs-rest (tăng thì tốn RAM hơn)')
    ap.add_argument('--report-only', action='store_true',
                    help='không train: tính lại chỉ số từ results/pred_*.parquet và viết lại report.md')
    cfg = ap.parse_args()
    evals = [e for e in cfg.eval.split(',') if e in EVALS]
    os.makedirs(cfg.results, exist_ok=True)

    if cfg.report_only:
        df = pd.read_parquet(cfg.data, columns=['dataset', 'group', 'label', 'label_malicious', 'n_dup'])
        labels = sorted(set(df.loc[df.label_malicious == 1, 'label']) - DROP_TACTICS)
        mpath = os.path.join(cfg.results, 'metrics.json')
        old = json.load(open(mpath)) if os.path.exists(mpath) else {}
        metrics = {k: evaluate(pd.read_parquet(os.path.join(cfg.results, f'pred_{k}.parquet')), labels)
                   for k in evals if os.path.exists(os.path.join(cfg.results, f'pred_{k}.parquet'))}
        if 'importance' in old:
            metrics['importance'] = old['importance']
        json.dump(metrics, open(mpath, 'w'), indent=1, ensure_ascii=False,
                  default=lambda o: o.item() if hasattr(o, 'item') else str(o))
        open(os.path.join(cfg.results, 'report.md'), 'w').write(fmt_report(metrics, df, labels))
        print(f'-> {os.path.relpath(cfg.results, paths.ROOT)}/report.md')
        return

    df = load(cfg.data)
    labels = sorted(set(df.loc[df.label_malicious == 1, 'label']) - DROP_TACTICS)
    print(f'{len(df)} dòng, {df.group.nunique()} group, tactic: {labels}', flush=True)
    metrics = {}
    for kind in evals:
        t0 = time.time()
        pred = run_eval(df, kind, cfg.jobs)
        pred.to_parquet(os.path.join(cfg.results, f'pred_{kind}.parquet'), index=False)
        metrics[kind] = evaluate(pred, labels)
        b = metrics[kind]['binary']['event']
        print(f'{kind}: F1 {b["f1"]:.3f}, báo nhầm {b["fpr"]:.2%}, tactic '
              f'{metrics[kind]["tactic"]["event"]["macro_f1"]:.3f} ({time.time() - t0:.0f}s)', flush=True)

    if not cfg.no_final:
        t0 = time.time()
        feat, mb, mt = fit(df, cfg.jobs)
        os.makedirs(cfg.models, exist_ok=True)
        meta = dict(featurizer=feat, data=os.path.relpath(cfg.data, paths.ROOT), trained=time.strftime('%Y-%m-%d %H:%M'))
        joblib.dump(dict(meta, model=mb), os.path.join(cfg.models, 'binary.joblib'))
        joblib.dump(dict(meta, model=mt, labels=labels), os.path.join(cfg.models, 'tactic.joblib'))
        names = feat.get_feature_names_out()
        metrics['importance'] = {**lr_importance('binary', mb, names), **lr_importance('tactic', mt, names)}
        print(f'model cuối -> {os.path.relpath(cfg.models, paths.ROOT)} ({time.time() - t0:.0f}s)', flush=True)

    json.dump(metrics, open(os.path.join(cfg.results, 'metrics.json' if evals else 'metrics_final.json'), 'w'),
              indent=1, ensure_ascii=False, default=lambda o: o.item() if hasattr(o, 'item') else str(o))
    if evals:
        report = fmt_report(metrics, df, labels)
        open(os.path.join(cfg.results, 'report.md'), 'w').write(report)
        print('\n' + report)


if __name__ == '__main__':
    main()
