"""Chuyển .evtx -> JSON lines (mỗi dòng 1 event), schema phẳng giống Mordor 2020 (NXLog).

Dùng: python src/evtx2json.py data/raw/EVTX-ATTACK-SAMPLES data/interim/evtx_json
Giữ nguyên cấu trúc thư mục; thêm 2 trường nhãn EVTX_Tactic, EVTX_FileName.
"""
import sys, os, re, glob, json
import xml.etree.ElementTree as ET
from Evtx.Evtx import Evtx

NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'
STRING_RX = re.compile(r'<string>(.*?)</string>', re.S)


def strip(tag):
    return tag.split('}', 1)[-1]


def record_to_dict(xml):
    root = ET.fromstring(xml)
    ev = {}
    sysn = root.find(NS + 'System')
    for el in sysn:
        tag = strip(el.tag)
        if tag == 'Provider':
            ev['SourceName'] = el.get('Name')
            if el.get('Guid'):
                ev['ProviderGuid'] = el.get('Guid')
        elif tag == 'TimeCreated':
            ev['TimeCreated'] = el.get('SystemTime')
        elif tag == 'Execution':
            # đặt tên như NXLog/Mordor để không trùng với trường ProcessID trong EventData
            ev['ExecutionProcessID'] = el.get('ProcessID')
            ev['ExecutionThreadID'] = el.get('ThreadID')
        elif tag == 'Security':
            if el.get('UserID'):
                ev['UserID'] = el.get('UserID')
        elif tag == 'Correlation':
            if el.get('ActivityID'):
                ev['ActivityID'] = el.get('ActivityID')
        elif tag == 'Computer':
            ev['Hostname'] = el.text
        else:  # EventID, Version, Level, Task, Opcode, Keywords, EventRecordID, Channel
            ev[tag] = el.text
    if ev.get('EventID') is not None:
        ev['EventID'] = int(ev['EventID'])

    # EventData: <Data Name="X">v</Data>; Data không có Name -> Data_0, Data_1...
    ed = root.find(NS + 'EventData')
    if ed is not None:
        for i, d in enumerate(ed):
            # log PowerShell cổ điển: 1 Data chứa "<string>p1</string><string>p2</string>..." -> param1..N
            parts = STRING_RX.findall(d.text or '') if not d.get('Name') else []
            if parts:
                for j, p in enumerate(parts, 1):
                    ev[f'param{j}'] = p
                continue
            name = d.get('Name') or f'{strip(d.tag)}_{i}'
            ev[name] = d.text
    # UserData: cấu trúc tuỳ provider -> làm phẳng các node lá
    ud = root.find(NS + 'UserData')
    if ud is not None:
        for leaf in ud.iter():
            if len(leaf) == 0 and leaf is not ud:
                ev[strip(leaf.tag)] = leaf.text
    return ev


def convert(src_root, dst_root):
    files = sorted(glob.glob(os.path.join(src_root, '**', '*.evtx'), recursive=True))
    total = bad = 0
    for f in files:
        rel = os.path.relpath(f, src_root)
        tactic = rel.split(os.sep)[0] if os.sep in rel else ''
        out = os.path.join(dst_root, os.path.splitext(rel)[0] + '.json')
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with Evtx(f) as log, open(out, 'w', encoding='utf-8') as fo:
            for r in log.records():
                try:
                    ev = record_to_dict(r.xml())
                except Exception:
                    bad += 1
                    continue
                ev['EVTX_Tactic'] = tactic
                ev['EVTX_FileName'] = os.path.basename(f)
                fo.write(json.dumps(ev, ensure_ascii=False) + '\n')
                total += 1
    print(f'{len(files)} files, {total} events, {bad} record lỗi bỏ qua')


if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2])
