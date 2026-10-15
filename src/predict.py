"""Dự đoán từng event của log Windows mới bằng model cuối của train.py:

  1. nhị phân (độc hại / benign): models/binary.joblib
  2. tactic (chỉ cho event bị báo độc hại): models/tactic.joblib

Đầu vào: file hoặc thư mục (đệ quy) gồm
  - .evtx (cần `pip install python-evtx`),
  - .json / .jsonl: JSON lines dạng evtx2json.py, NXLog, Winlogbeat (Mordor) hoặc đã chuẩn hoá OSSEM
    (data/interim/ossem/, data/interim/labels/). Nếu có cột nhãn (labels/) thì in thêm chỉ số so với nhãn.
Các bước giống lúc train: OSSEM (ossem_normalize.py) -> feature (build_dataset.py) -> hành vi + văn bản
(train.prepare). Tên host / user / domain được lấy từ chính dữ liệu đầu vào để thay bằng token.

Kết quả (--out, mặc định results/predict/<tên đầu vào>/):
  predictions.csv  mỗi event 1 dòng: file, thời gian, loại event, process, p_malicious, tactic, cờ hành vi (flags),
                   và các khoá để alert.py gộp event thành cảnh báo (GUID / PID process, LogonId, user)
  summary.md       tóm tắt theo file, các event điểm cao nhất, chỉ số (nếu có nhãn)

Dùng:
  python src/predict.py "data/raw/EVTX-ATTACK-SAMPLES/Lateral Movement/xxx.evtx"
  python src/predict.py data/interim/labels/evtx --threshold 0.5

Sysmon 7 nạp DLL hệ thống ký Microsoft không được chấm (out_of_scope=1, tactic=out_of_scope): loại event này
đã bị bỏ khỏi tập train vì bản thân nó không chứa dấu hiệu tấn công (build_dataset.sys_dll_load).
"""
import os, sys, json, glob, argparse
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths
OSSEM_MAP = paths.OSSEM_MAP
EXTS = ('.evtx', '.json', '.jsonl')


def list_inputs(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += [(f, os.path.relpath(f, p)) for f in sorted(glob.glob(os.path.join(p, '**', '*'), recursive=True))
                      if f.lower().endswith(EXTS) and os.path.basename(f) != 'label_report.json']
        else:
            files.append((p, os.path.basename(p)))
    return files


def read_records(path):
    """-> (records, fmt): fmt = 'ossem' nếu đã chuẩn hoá, ngược lại là định dạng cho ossem_normalize."""
    import ossem_normalize as O
    if path.lower().endswith('.evtx'):
        try:
            from Evtx.Evtx import Evtx
        except ImportError:
            sys.exit('Cần python-evtx để đọc .evtx: pip install python-evtx')
        import evtx2json
        recs = []
        with Evtx(path) as log:
            for r in log.records():
                try:
                    recs.append(evtx2json.record_to_dict(r.xml()))
                except Exception:
                    continue
        return recs, 'evtx'
    recs = list(O.read_jsonl(path))
    if not recs:
        return recs, None
    r = recs[0]
    if 'EventTimestamp' in r and 'Provider' in r:
        return recs, 'ossem'
    if 'TimeCreated' in r and 'SourceName' in r:  # evtx2json.py
        return recs, 'evtx'
    return recs, O.detect_fmt(r)


def to_ossem(files):
    import ossem_normalize as O
    norm = O.Normalizer(json.load(open(OSSEM_MAP)))
    events = []
    for path, rel in files:
        recs, fmt = read_records(path)
        if fmt is None:
            continue
        if fmt == 'ossem':
            for e in recs:
                e['SourceFile'] = rel
            events += recs
            print(f'  {rel}: {len(recs)} event (OSSEM)', flush=True)
            continue
        offset, _ = O.file_offset(norm, recs, fmt)
        labels = dict(Dataset='input', SourceFile=rel)
        events += [norm.normalize(r, fmt, labels, offset, False) for r in recs]
        print(f'  {rel}: {len(recs)} event ({fmt})', flush=True)
    return events


def build_features(events):
    """Event OSSEM -> bảng feature giống data/processed/events.parquet (không khử trùng)."""
    import build_dataset as BD
    hosts, users, domains = BD.collect_vocab(None, events)
    norm = BD.Normalizer(hosts, users, domains)
    rows, info = [], []
    for e in events:
        r = BD.build_row('input', e, norm)
        r['n_dup'] = 1
        rows.append(r)
        info.append(dict(file=e.get('SourceFile'), time=e.get('EventTimestamp'), host=e.get('DvcHostname'),
                         record_id=e.get('EventOriginalUid'),
                         process=e.get('ProcessFilePath') or e.get('ProcessName') or '',
                         parent=e.get('ProcessParentFilePath') or '', target=e.get('TargetProcessFilePath') or '',
                         command_line=str(e.get('ProcessCommandLine') or '')[:500],
                         user=e.get('UserName') or e.get('TargetUserName') or '',
                         process_guid=e.get('ProcessGuid'), parent_guid=e.get('ProcessParentGuid'),
                         target_guid=e.get('TargetProcessGuid'), pid=e.get('ProcessId'),
                         ppid=e.get('ProcessParentId'), exec_pid=e.get('ExecutionProcessId'),
                         logon_id=e.get('UserLogonId') or e.get('TargetUserLogonId'),
                         true_label=e.get('label'), true_malicious=e.get('label_malicious'),
                         out_of_scope=int(BD.sys_dll_load(e))))
    return pd.DataFrame(rows), pd.DataFrame(info)


def summarize(out, thr, has_labels):
    lines = [f'# Kết quả dự đoán\n', f'- {len(out):,} event, {out.file.nunique()} file, ngưỡng nhị phân {thr}',
             f'- ngoài phạm vi (Sysmon 7 nạp DLL hệ thống ký Microsoft, không chấm): {int(out.out_of_scope.sum()):,} event',
             f'- báo độc hại: {int(out.malicious.sum()):,} event\n']
    lines += ['## Theo file\n', '| File | Event | Báo độc hại | Tactic dự đoán (số event) |', '|---|---|---|---|']
    for f, g in out.groupby('file', sort=True):
        m = g[g.malicious == 1]
        tac = ', '.join(f'{t} ({n})' for t, n in m.tactic.value_counts().items())
        lines.append(f'| {f} | {len(g)} | {len(m)} | {tac} |')
    lines += ['\n## 30 event điểm cao nhất\n', '| File | Event | Process | p | Tactic | Command line |',
              '|---|---|---|---|---|---|']
    for _, r in out.sort_values('p_malicious', ascending=False).head(30).iterrows():
        cmd = str(r.command_line).replace('|', '\\|').replace('\n', ' ')[:120]
        lines.append(f'| {r.file} | {r.provider} {r.event_id} | {os.path.basename(str(r.process).replace(chr(92), "/"))} '
                     f'| {r.p_malicious:.2f} | {r.tactic} ({r.p_tactic:.2f}) | {cmd} |')
    if has_labels:
        from sklearn.metrics import precision_recall_fscore_support, average_precision_score, f1_score
        e = out[out.true_malicious.isin([0, 1]) & (out.out_of_scope == 0)]
        y = e.true_malicious.astype(int).values
        p, r, f, _ = precision_recall_fscore_support(y, e.malicious, average='binary', zero_division=0)
        lines += ['\n## So với nhãn (bỏ uncertain và event ngoài phạm vi)\n',
                  f'- nhị phân: precision {p:.3f}, recall {r:.3f}, F1 {f:.3f}, PR-AUC {average_precision_score(y, e.p_malicious):.3f}']
        t = e[(e.true_malicious == 1) & (e.malicious == 1)]
        if len(t):
            lines.append(f'- tactic (event độc hại được báo đúng): accuracy {(t.tactic == t.true_label).mean():.3f}, '
                         f'macro-F1 {f1_score(t.true_label, t.tactic, average="macro", zero_division=0):.3f}')
    return '\n'.join(lines) + '\n'


def add_args(ap, inputs_required=True):
    ap.add_argument('inputs', nargs='+' if inputs_required else '*', help='file/thư mục .evtx, .json, .jsonl')
    ap.add_argument('--models', default=paths.MODELS, help='thư mục chứa binary.joblib, tactic.joblib')
    ap.add_argument('--threshold', type=float, default=0.5, help='ngưỡng p_malicious để báo độc hại')
    ap.add_argument('--out', help='thư mục kết quả (mặc định results/predict/<tên đầu vào>)')


def run(a):
    """Dự đoán + ghi predictions.csv, summary.md. -> (bảng dự đoán, thư mục kết quả)."""
    import train
    import behavior as B
    mb, mt = (joblib.load(os.path.join(a.models, f)) for f in ('binary.joblib', 'tactic.joblib'))

    files = list_inputs(a.inputs)
    if not files:
        sys.exit('không tìm thấy file .evtx / .json / .jsonl')
    print(f'Đọc {len(files)} file ...', flush=True)
    events = to_ossem(files)
    print(f'Tạo feature cho {len(events):,} event ...', flush=True)
    df, info = build_features(events)
    del events

    print('Dự đoán ...', flush=True)
    d = train.prepare(df)
    p = mb['model'].predict_proba(mb['featurizer'].transform(d))[:, 1]
    P = mt['model'].predict_proba(mt['featurizer'].transform(d))
    classes = np.asarray(mt['model'].classes_)
    order = np.argsort(-P, axis=1)
    out = pd.concat([info, df[['provider', 'event_id']]], axis=1)
    out['p_malicious'] = p.round(4)
    # Sysmon 7 nạp DLL hệ thống ký Microsoft: không có trong tập train (build_dataset.sys_dll_load) -> không báo
    out['malicious'] = ((p >= a.threshold) & (out.out_of_scope == 0)).astype(int)
    out['tactic'] = np.where(out.malicious == 1, classes[order[:, 0]],
                             np.where(out.out_of_scope == 1, 'out_of_scope', 'benign'))
    out['p_tactic'] = P[np.arange(len(P)), order[:, 0]].round(4)
    out['tactic_2'] = classes[order[:, 1]]
    out['p_tactic_2'] = P[np.arange(len(P)), order[:, 1]].round(4)
    F = d[B.BEH_FLAGS].values.astype(bool)
    out['flags'] = [' '.join(np.asarray(B.BEH_FLAGS)[row]) for row in F]
    has_labels = out.true_malicious.notna().any()
    if not has_labels:
        out = out.drop(columns=['true_label', 'true_malicious'])

    name = os.path.splitext(os.path.basename(os.path.normpath(a.inputs[0])))[0].replace(' ', '_')
    od = a.out or os.path.join(paths.RESULTS, 'predict', name)
    os.makedirs(od, exist_ok=True)
    out.to_csv(os.path.join(od, 'predictions.csv'), index=False)
    rep = summarize(out, a.threshold, has_labels)
    open(os.path.join(od, 'summary.md'), 'w').write(rep)
    head, _, rest = rep.partition('\n## 30 event')
    print('\n' + head[:4000] + (rest[rest.find('\n## So với nhãn'):] if '## So với nhãn' in rest else ''))
    print(f'\n-> {od}/predictions.csv, summary.md')
    return out, od


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_args(ap)
    run(ap.parse_args())


if __name__ == '__main__':
    main()
