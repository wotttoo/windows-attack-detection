"""Gán nhãn từng event cho bộ EVTX-ATTACK-SAMPLES đã chuẩn hoá OSSEM (data/interim/ossem/evtx/).

Khác Mordor: mỗi file EVTX là mẫu đã được tác giả lọc, phần lớn event là của kỹ thuật tấn công, nên mặc định
mọi event mang tactic của thư mục (label_method = file:curated), trừ event khớp luật nhiễu (-> benign) hoặc
dấu vết của người làm mẫu (-> uncertain). File lẫn nhiều nhiễu dùng mode: seeds -> chạy label_events.label_file
(hạt giống + lan theo cây process / PID / phiên đăng nhập / kết nối mạng), phần không lan tới là benign.
Luật nằm trong configs/label_seeds_evtx.yaml.

Dùng:
  1 file (in chi tiết): python src/label_evtx.py "data/interim/ossem/evtx/Credential Access/<file>.json"
  cả bộ:                python src/label_evtx.py --all data/interim/ossem/evtx --out data/interim/labels/evtx
"""
import os, re, json, glob, argparse, collections
import yaml
import label_events as L

import paths


def compile_rule(r):
    r = dict(r)
    r.pop('note', None)
    m, img = r.pop('match', None), r.pop('image', None)
    return dict(eid=set(r.pop('eid', None) or []), own_machine=r.pop('own_machine', False),
                self_link_local=r.pop('self_link_local', False),
                match=re.compile(m, re.I) if m else None, image=re.compile(img, re.I) if img else None,
                fields={k: re.compile(str(v), re.I) for k, v in r.items()})


def image(e):
    return re.split(r'[\\/]', e.get('ProcessFilePath') or '')[-1]


def rule_match(r, e):
    if r['eid'] and e.get('EventId') not in r['eid']:
        return False
    if r['image'] and not r['image'].search(image(e)):
        return False
    if r['own_machine']:
        u = (e.get('UserName') or '').split('\\')[-1].lower()
        if not (u.endswith('$') and u[:-1] == L.host(e)):
            return False
    if r['self_link_local']:
        src, dst = str(e.get('SrcIpAddr') or '').lower(), str(e.get('DstIpAddr') or '').lower()
        if not (src.startswith('fe80:') and src == dst):
            return False
    for k, rx in r['fields'].items():
        if e.get(k) is None or not rx.search(str(e[k])):
            return False
    return not r['match'] or bool(r['match'].search(L.event_text(e)))


def first_match(rules, e):
    return next((r for r in rules if rule_match(r, e)), None)


def load_config(path):
    cfg = yaml.safe_load(open(path, encoding='utf-8'))
    comp = lambda xs: [compile_rule(r) for r in xs or []]
    files = {}
    for key, c in (cfg.get('files') or {}).items():
        c = c or {}
        files[key] = dict(tactic=c.get('tactic'), skip=bool(c.get('skip')), mode=c.get('mode', 'all'),
                          note=c.get('note'), scen=L.compile_scenario(c),
                          keep=comp(c.get('keep')), noise=comp(c.get('noise')), uncertain=comp(c.get('uncertain')))
    return dict(noise=comp(cfg.get('noise')), lab=comp(cfg.get('lab')), files=files)


def file_config(cfg, rel):
    key = os.path.splitext(rel)[0]
    return cfg['files'].get(key) or cfg['files'].get(os.path.basename(key)) or \
        dict(tactic=None, skip=False, mode='all', note=None, scen=L.compile_scenario({}), keep=[], noise=[], uncertain=[])


def label_evtx_file(events, fc, cfg, generic):
    tactic = fc['tactic'] or events[0].get('Tactic')
    for e in events:
        e['Tactic'] = tactic
    if fc['mode'] == 'seeds':
        L.label_file(events, generic, fc['scen'])
    noise = fc['noise'] + cfg['noise']
    for e in events:
        if first_match(fc['keep'], e):
            e['label'], e['label_malicious'], e['label_method'] = tactic, 1, 'evtx:keep'
            continue
        if fc['mode'] == 'seeds' and e['label_malicious'] != 1:   # không lan tới từ hạt giống
            if e['label_malicious'] == 0 and first_match(fc['uncertain'], e):
                e['label'], e['label_malicious'], e['label_method'] = 'uncertain', -1, 'evtx:uncertain-rule'
            continue
        why = e['label_method'] if fc['mode'] == 'seeds' else 'file:curated'
        if first_match(noise, e):
            e['label'], e['label_malicious'], e['label_method'] = 'benign', 0, 'evtx:noise'
        elif first_match(cfg['lab'], e):
            e['label'], e['label_malicious'], e['label_method'] = 'uncertain', -1, 'evtx:lab-artifact'
        elif first_match(fc['uncertain'], e):
            e['label'], e['label_malicious'], e['label_method'] = 'uncertain', -1, 'evtx:uncertain-rule'
        elif fc['mode'] != 'seeds':
            e['label'], e['label_malicious'], e['label_method'] = tactic, 1, why
    return events


def short(e):
    d = next((str(e[k]) for k in ('ProcessCommandLine', 'TargetProcessFilePath', 'RegistryKeyPath', 'FileName',
                                  'ModulePath', 'DstIpAddr', 'PipeName', 'ShareRelativeTargetName', 'UserName',
                                  'InterfaceUuid', 'jobTitle', 'name', 'param1') if e.get(k)), '')
    prov = (e.get('Provider') or '').replace('Microsoft-Windows-', '')
    return f"{prov}:{e.get('EventId')} [{image(e)}] {re.sub(r'\s+', ' ', d)[:100]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?')
    ap.add_argument('--all', help='thư mục ossem/evtx')
    ap.add_argument('--config', default=paths.SEEDS_EVTX)
    ap.add_argument('--seeds', default=paths.SEEDS, help='hạt giống chung (generic, c2)')
    ap.add_argument('--out')
    a = ap.parse_args()
    cfg = load_config(a.config)
    generic, _ = L.load_seeds(a.seeds)

    if a.file:
        base = os.path.join(a.file.split('ossem/evtx/')[0], 'ossem/evtx') if 'ossem/evtx/' in a.file else os.path.dirname(a.file)
        rel = os.path.relpath(a.file, base)
        fc = file_config(cfg, rel)
        events = L.read(a.file)
        if fc['skip']:
            print(f'skip: {fc["note"]}')
            return
        label_evtx_file(events, fc, cfg, generic)
        print(f'File: {rel}  ({len(events)} event, mode={fc["mode"]}, tactic={events[0]["Tactic"]})')
        print('== Nhãn:', dict(collections.Counter(e['label'] for e in events)))
        print('== Lý do:', dict(collections.Counter(e['label_method'] for e in events)))
        for lab in ('benign', 'uncertain'):
            c = collections.Counter(short(e) for e in events if e['label'] == lab)
            if c:
                print(f'\n== {lab}')
                for s, n in c.most_common(40):
                    print(f'  {n:5} {s}')
        if a.out:
            L.write(a.out, events)
        return

    rows, tot = [], collections.Counter()
    for f in sorted(glob.glob(os.path.join(a.all, '**', '*.json'), recursive=True)):
        rel = os.path.relpath(f, a.all)
        fc = file_config(cfg, rel)
        events = L.read(f)
        if not events:
            continue
        if fc['skip']:
            rows.append(dict(file=rel, events=len(events), status='skip', note=fc['note']))
            continue
        label_evtx_file(events, fc, cfg, generic)
        c = collections.Counter(e['label_malicious'] for e in events)
        rows.append(dict(file=rel, tactic=events[0]['Tactic'], mode=fc['mode'], events=len(events),
                         malicious=c[1], uncertain=c[-1], benign=c[0], malicious_ratio=round(c[1] / len(events), 3),
                         methods=dict(collections.Counter(e['label_method'] for e in events)),
                         status='NO_MALICIOUS' if c[1] == 0 else 'ok'))
        tot.update(e['label'] for e in events)
        if a.out:
            L.write(os.path.join(a.out, rel), events)
    for r in rows:
        print(f"{r['status']:12} {r['events']:6} mal={r.get('malicious', 0):6} unc={r.get('uncertain', 0):4} "
              f"ben={r.get('benign', 0):6} {r.get('mode', ''):5} {r['file']}")
    print(f"\nTổng: {sum(tot.values())} event, {len([r for r in rows if r['status'] != 'skip'])} file "
          f"(bỏ {len([r for r in rows if r['status'] == 'skip'])})")
    for k, n in tot.most_common():
        print(f'  {k:22} {n}')
    if a.out:
        json.dump(rows, open(os.path.join(a.out, 'label_report.json'), 'w'), indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
