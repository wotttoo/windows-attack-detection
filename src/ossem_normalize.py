"""Chuẩn hoá EVTX-ATTACK-SAMPLES (data/interim/evtx_json/) và Mordor small/windows về schema OSSEM.

Bước 1 - tạo bảng map từ OSSEM-DD (đã có sẵn ở configs/ossem_dd_windows.json, chỉ chạy lại nếu muốn cập nhật):
    git clone https://github.com/OTRF/OSSEM-DD
    python src/ossem_normalize.py build-map OSSEM-DD configs/ossem_dd_windows.json
Bước 2 - chuẩn hoá (--map mặc định configs/ossem_dd_windows.json):
    python src/ossem_normalize.py run --evtx data/interim/evtx_json --mordor data/raw/mordor/datasets \
        --out data/interim/ossem

Output: JSON lines, mỗi dòng 1 event, phẳng.
  - Nhãn:    Dataset, SourceFile, Tactic, (Mordor) ScenarioId, ScenarioTitle, AttackTechniques, AttackTactics
  - Header:  EventId, EventTimestamp (UTC), EventOriginalTime, EventOriginalUid, EventSeverity,
             DvcHostname, Channel, Provider (2 trường cuối không có trong CDM, giữ lại cho Windows)
  - Dữ liệu: tên chuẩn OSSEM nếu OSSEM-DD (hoặc bảng bổ sung bên dưới) có map,
             còn lại giữ tên gốc (trùng tên chuẩn thì thêm tiền tố "Raw").
"""
import sys, os, re, json, glob, hashlib, argparse, collections
import paths
from datetime import datetime, timedelta, timezone

# OSSEM-DD tự mâu thuẫn: Sysmon dùng *FilePath, Security dùng *Path -> gộp về một tên
HARMONIZE = {
    'ProcessPath': 'ProcessFilePath',
    'ProcessParentPath': 'ProcessParentFilePath',
    'TargetProcessPath': 'TargetProcessFilePath',
    'SrcPortNumber': 'SrcPort',  # Sysmon 3 dùng *PortNumber, Security dùng *Port
    'DstPortNumber': 'DstPort',
}
# Security 4656 có biến thể map theo ObjectType
VARIANT_OBJECTTYPE = {'registry': 'Key', 'service': 'SERVICE OBJECT'}

ATTACK_TACTICS = {
    'TA0043': 'reconnaissance', 'TA0042': 'resource-development', 'TA0001': 'initial-access',
    'TA0002': 'execution', 'TA0003': 'persistence', 'TA0004': 'privilege-escalation',
    'TA0005': 'defense-evasion', 'TA0006': 'credential-access', 'TA0007': 'discovery',
    'TA0008': 'lateral-movement', 'TA0009': 'collection', 'TA0011': 'command-and-control',
    'TA0010': 'exfiltration', 'TA0040': 'impact',
}

# PowerShell: OSSEM-DD chưa map 4103/4104/800 -> bổ sung theo quy ước "Powershell*" của DD (event 400)
PS_MANUAL = {
    'Microsoft-Windows-PowerShell|4103': {'payload': 'PowershellPayload'},
    'Microsoft-Windows-PowerShell|4104': {
        'scriptblocktext': 'PowershellScriptBlockText', 'scriptblockid': 'PowershellScriptBlockId',
        'path': 'PowershellScriptName', 'messagenumber': 'PowershellScriptBlockMessageNumber',
        'messagetotal': 'PowershellScriptBlockMessageTotal'},
}
CANON_CHANNELS = {c.lower(): c for c in [
    'Security', 'System', 'Application', 'Windows PowerShell',
    'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational']}
CHANNEL_PROVIDER = {
    'microsoft-windows-sysmon/operational': 'Microsoft-Windows-Sysmon',
    'security': 'Microsoft-Windows-Security-Auditing',
    'microsoft-windows-powershell/operational': 'Microsoft-Windows-PowerShell',
    'windows powershell': 'PowerShell',
}

# Trường header của từng định dạng nguồn (không coi là dữ liệu event)
HDR_EVTX = {'SourceName', 'ProviderGuid', 'EventID', 'Version', 'Level', 'Task', 'Opcode', 'Keywords',
            'TimeCreated', 'EventRecordID', 'ExecutionProcessID', 'ExecutionThreadID', 'Channel',
            'Hostname', 'UserID', 'ActivityID', 'EVTX_Tactic', 'EVTX_FileName'}
HDR_NXLOG = {'@timestamp', '@version', 'Category', 'Channel', 'EventID', 'EventReceivedTime', 'EventTime',
             'EventType', 'ExecutionProcessID', 'Hostname', 'Keywords', 'Message', 'Opcode', 'OpcodeValue',
             'RecordNumber', 'Severity', 'SeverityValue', 'SourceModuleName', 'SourceModuleType',
             'SourceName', 'Task', 'ThreadID', 'host', 'port', 'tags', 'type', 'ProviderGuid', 'Version',
             'AccountName', 'AccountType', 'Domain', 'UserID', 'ActivityID', 'RelatedActivityID',
             'ERROR_EVT_UNRESOLVED'}
HDR_FLAT = {'@timestamp', 'Channel', 'EventID', 'Hostname', 'Keywords', 'Level', 'Message', 'ProviderGuid',
            'SourceName', 'Task', 'TimeCreated', 'type', 'ERROR_EVT_UNRESOLVED'}

INT_SUFFIXES = ('ProcessId', 'ProcessParentId', 'ThreadId', 'Port')
INT_NAMES = {'LogonType', 'UserSessionId'}


# ----------------------------------------------------------------------------- build-map
def build_map(dd_root, out):
    import yaml
    files = []
    for sub in ('sysmon', 'powershell', 'etw-providers'):
        files += glob.glob(os.path.join(dd_root, 'windows', sub, '**', 'events', '*.yml'), recursive=True)
    # base -> _v1 -> _v2: bản mới hơn ghi đè bản cũ
    files.sort(key=lambda f: (os.path.basename(f).split('_v')[-1] if '_v' in f else '0', f))
    table = collections.defaultdict(lambda: {'default': {}, 'variants': {}})
    for f in files:
        try:
            d = yaml.safe_load(open(f, encoding='utf-8'))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        key = f"{d.get('log_source')}|{d.get('event_id')}"
        base = os.path.basename(f)
        variant = next((v for k, v in VARIANT_OBJECTTYPE.items() if f'_{k}_' in base), None)
        target = table[key]['variants'].setdefault(variant, {}) if variant else table[key]['default']
        for x in d.get('event_fields') or []:
            sn = x.get('standard_name')
            if sn in (None, '', 'TBD') or not x.get('name'):
                continue
            target[x['name'].lower()] = HARMONIZE.get(sn, sn)
    table = {k: v for k, v in table.items() if v['default'] or v['variants']}
    json.dump({'harmonized': HARMONIZE, 'events': table}, open(out, 'w'), indent=1, sort_keys=True)
    print(f'{len(table)} cặp (provider|EventID) có map -> {out}')


# ----------------------------------------------------------------------------- helpers
def parse_time(s):
    if s in (None, ''):
        return None
    s = str(s).strip().replace('Z', '+00:00')
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def iso(t):
    return t.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ') if t else None


def to_int(v):
    if v is None or isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 16) if s.lower().startswith('0x') else int(s)
    except ValueError:
        return None


def slug(s):
    s = re.sub(r'(?<=[a-z])(?=[A-Z])', ' ', s)  # AutomatedTestingTools -> Automated Testing Tools
    return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')


KV_EQ = re.compile(r'^\s*([A-Za-z][\w]*)=(.*)$')
KV_SP = re.compile(r'^\s*([A-Za-z][\w ]*?)\s+=\s+(.*)$')


def ps_name(k):
    k = re.sub(r'\s+', '', k)
    k = re.sub(r'ID$', 'Id', k)
    return 'UserName' if k == 'User' else 'Powershell' + k


def parse_ps_text(text, rx, mapping):
    out = {}
    for line in str(text).splitlines():
        m = rx.match(line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            out[mapping.get(k.lower(), ps_name(k))] = v
    return out


# ----------------------------------------------------------------------------- normalizer
class Normalizer:
    def __init__(self, table):
        self.t = table['events']
        self.stats = collections.Counter()
        self.unmapped = collections.Counter()

    def lookup(self, provider, eid, raw):
        e = self.t.get(f'{provider}|{eid}')
        manual = PS_MANUAL.get(f'{provider}|{eid}', {})
        if not e:
            return manual
        m = dict(e['default'])
        otype = raw.get('ObjectType')
        if otype in e['variants']:  # variants được lưu theo giá trị ObjectType
            m.update(e['variants'][otype])
        m.update(manual)
        return m

    def split(self, rec, fmt):
        """-> (header dict chuẩn hoá thô, data dict gốc)"""
        if fmt == 'winlogbeat':
            data = dict(rec.get('event_data') or {})
            for k, v in (rec.get('user_data') or {}).items():
                if not isinstance(v, (dict, list)):
                    data[k] = v
            if rec.get('message') and not data:
                data['Message'] = rec['message']
            h = dict(eid=rec.get('event_id'), provider=rec.get('source_name'), channel=rec.get('log_name'),
                     host=rec.get('computer_name'), time=rec.get('@timestamp'), uid=rec.get('record_number'),
                     sev=rec.get('level'), msg=rec.get('message'),
                     usersid=(rec.get('user') or {}).get('identifier'), execpid=rec.get('process_id'))
            return h, data
        hdr = {'evtx': HDR_EVTX, 'nxlog': HDR_NXLOG, 'flat': HDR_FLAT}[fmt]
        data = {k: v for k, v in rec.items() if k not in hdr}
        # NXLog: @timestamp là lúc Logstash nhận (trễ 1-3s) -> dùng EventTime (giờ địa phương, độ lệch tự chỉnh theo Sysmon)
        time = rec.get('TimeCreated') if fmt in ('evtx', 'flat') else rec.get('EventTime') or rec.get('@timestamp')
        h = dict(eid=rec.get('EventID'), provider=rec.get('SourceName'), channel=rec.get('Channel'),
                 host=rec.get('Hostname'), time=time,
                 uid=rec.get('EventRecordID') or rec.get('RecordNumber'),
                 sev=rec.get('Level') or rec.get('Severity'), msg=rec.get('Message'),
                 usersid=rec.get('UserID'), execpid=rec.get('ExecutionProcessID') or rec.get('ExecutionProcessId'))
        return h, data

    def normalize(self, rec, fmt, labels, offset, keep_message):
        h, raw = self.split(rec, fmt)
        channel = h['channel'] or ''
        channel = CANON_CHANNELS.get(channel.lower(), channel) or None
        provider = h['provider'] or CHANNEL_PROVIDER.get((channel or '').lower())
        eid = to_int(h['eid'])
        is_sysmon = provider == 'Microsoft-Windows-Sysmon'

        if 'EventTypeOrignal' in raw:  # NXLog đổi tên EventType của Sysmon để tránh trùng header
            raw['EventType'] = raw.pop('EventTypeOrignal')

        out = dict(labels)
        ts = parse_time(raw.get('UtcTime')) if is_sysmon else None
        orig = parse_time(h['time'])
        if ts is None and orig is not None:
            delta, anchor = offset
            ts = orig + delta
            if fmt == 'flat' and anchor:  # TimeCreated dạng 12 giờ không có AM/PM -> chọn bản gần Sysmon nhất
                ts = min((ts + timedelta(hours=12 * k) for k in (-1, 0, 1)), key=lambda t: abs(t - anchor))
        out.update(EventId=eid, EventTimestamp=iso(ts), EventOriginalTime=h['time'],
                   EventOriginalUid=str(h['uid']) if h['uid'] is not None else None,
                   EventSeverity=h['sev'], DvcHostname=h['host'], Channel=channel, Provider=provider,
                   ExecutionProcessId=to_int(h['execpid']) or None)  # PID process ghi log (vd powershell của 4103/4104)

        mapping = self.lookup(provider, eid, raw)
        data = {}
        # PowerShell: dữ liệu nằm trong chuỗi key=value
        if provider == 'PowerShell':
            params = [str(v) for k, v in sorted(((k, v) for k, v in raw.items() if re.match(r'(param|Data_)\d+$', k)),
                                                key=lambda kv: int(re.sub(r'\D', '', kv[0]))) if v]
            text = '\n'.join(params) or h['msg'] or ''
            data.update(parse_ps_text(text, KV_EQ, mapping))
            if 'Details:' in text:
                data['PowershellPayload'] = text.split('Details:', 1)[1].strip()
            elif eid == 800 and len(params) >= 3:  # param3 của event 800 = chi tiết pipeline
                data['PowershellPayload'] = params[-1].strip()
            raw = {k: v for k, v in raw.items() if not re.match(r'(param|Data_)\d+$', k)}
        if provider == 'Microsoft-Windows-PowerShell' and raw.get('ContextInfo'):
            data.update(parse_ps_text(raw.pop('ContextInfo'), KV_SP, {}))

        if raw.get('Hashes') and isinstance(raw['Hashes'], str) and '=' in raw['Hashes']:
            pre = {1: 'Process', 7: 'Module'}.get(eid, 'File') if is_sysmon else 'File'
            for part in raw.pop('Hashes').split(','):
                if '=' in part:
                    a, v = part.split('=', 1)
                    data[f'{pre}Hash{a.strip().capitalize()}'] = v.strip()

        leftovers = {}
        for k, v in raw.items():
            sn = mapping.get(k.lower())
            if sn and sn not in data:
                data[sn] = v
                self.stats['mapped'] += 1
            else:
                leftovers[k] = v
                self.stats['unmapped'] += 1
                self.unmapped[(provider, eid, k)] += 1
        for k, v in leftovers.items():
            if k in data and str(data[k]) == str(v):  # bản sao (NXLog nhân đôi SourceProcessId thành ProcessId)
                self.stats['unmapped'] -= 1
                self.stats['duplicate'] += 1
                self.unmapped[(provider, eid, k)] -= 1
                continue
            name = k if k not in data and k not in out else 'Raw' + k
            data[name] = v
        if h['usersid'] and 'UserReporterSid' not in data:
            data['UserReporterSid'] = h['usersid']
        for k in list(data):
            if k.endswith(INT_SUFFIXES) or k in INT_NAMES:
                data[k] = to_int(data[k])
        if keep_message or (not data and h['msg']):
            out['EventMessage'] = h['msg']
        out.update(data)
        return out


def detect_fmt(rec):
    if 'event_data' in rec or 'log_name' in rec:
        return 'winlogbeat'
    if 'EventTime' in rec or 'SourceModuleType' in rec:
        return 'nxlog'
    return 'flat'


def read_jsonl(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def file_offset(norm, records, fmt):
    """Độ lệch giữa timestamp header và UtcTime của Sysmon (Mordor có file ghi giờ địa phương kèm 'Z')."""
    diffs, utcs = [], []
    for r in records:
        h, raw = norm.split(r, fmt)
        prov = h['provider'] or CHANNEL_PROVIDER.get((h['channel'] or '').lower())
        if prov != 'Microsoft-Windows-Sysmon':
            continue
        a, b = parse_time(raw.get('UtcTime')), parse_time(h['time'])
        if a and b:
            diffs.append((a - b).total_seconds())
            utcs.append(a)
        if len(diffs) >= 500:
            break
    if not diffs:
        return (timedelta(0), None), False
    diffs.sort()
    utcs.sort()
    med = diffs[len(diffs) // 2]
    # làm tròn 15 phút để bỏ độ trễ ingest; với TimeCreated 12 giờ chỉ giữ phần dư theo 12h
    delta = timedelta(minutes=round(med / 900) * 15)
    return (delta, utcs[len(utcs) // 2]), True


def load_mordor_meta(meta_dir):
    import yaml
    meta = {}
    for f in glob.glob(os.path.join(meta_dir, 'SDWIN-*.yaml')):
        d = yaml.safe_load(open(f, encoding='utf-8'))
        techs, tactics = [], set()
        for m in d.get('attack_mappings') or []:
            t = m.get('technique')
            if t:
                techs.append(f"{t}.{m['sub-technique']}" if m.get('sub-technique') else t)
            tactics.update(ATTACK_TACTICS.get(x, x) for x in m.get('tactics') or [])
        info = dict(ScenarioId=d.get('id'), ScenarioTitle=d.get('title'),
                    AttackTechniques=sorted(set(techs)), AttackTactics=sorted(tactics))
        for fl in d.get('files') or []:
            if fl.get('type') == 'Host' and fl.get('link'):
                parts = fl['link'].split('/datasets/small/windows/')[-1].split('/')
                stem = re.sub(r'\.(zip|tar\.gz|tgz)$', '', parts[-1])
                meta[(parts[0], stem)] = info
                meta.setdefault(('*', stem), info)
    return meta


def process_file(norm, src, dst, fmt_hint, labels, keep_message):
    records = list(read_jsonl(src))
    if not records:
        return 0, None
    fmt = fmt_hint or detect_fmt(records[0])
    offset, has_sysmon = file_offset(norm, records, fmt)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, 'w', encoding='utf-8') as fo:
        for r in records:
            fo.write(json.dumps(norm.normalize(r, fmt if fmt_hint else detect_fmt(r), labels, offset,
                                               keep_message), ensure_ascii=False) + '\n')
    return len(records), (fmt, offset[0].total_seconds() / 3600, has_sysmon)


def run(args):
    norm = Normalizer(json.load(open(args.map)))
    report = {'files': []}
    n_total = 0
    if args.evtx:
        for f in sorted(glob.glob(os.path.join(args.evtx, '**', '*.json'), recursive=True)):
            rel = os.path.relpath(f, args.evtx)
            tactic = slug(rel.split(os.sep)[0]) if os.sep in rel else None
            labels = dict(Dataset='evtx-attack-samples', SourceFile=rel, Tactic=tactic)
            n, info = process_file(norm, f, os.path.join(args.out, 'evtx', rel), 'evtx', labels, args.keep_message)
            n_total += n
            report['files'].append(dict(dataset='evtx', file=rel, events=n))
    if args.mordor:
        meta = load_mordor_meta(os.path.join(args.mordor, 'metadata'))
        root = os.path.join(args.mordor, 'small', 'windows')
        seen = {}
        files = sorted(glob.glob(os.path.join(root, '**', '*.json'), recursive=True),
                       key=lambda p: (-p.count(os.sep), p))  # ưu tiên bản trong thư mục con kịch bản
        for f in files:
            rel = os.path.relpath(f, root)
            md5 = hashlib.md5(open(f, 'rb').read()).hexdigest()
            if md5 in seen:
                report['files'].append(dict(dataset='mordor', file=rel, skipped=f'trùng với {seen[md5]}'))
                continue
            seen[md5] = rel
            folder = rel.split(os.sep)[0]
            stem = re.sub(r'_\d{4}-\d{2}-\d{2}T?\d*$', '', os.path.splitext(os.path.basename(f))[0])
            info = meta.get((folder, stem)) or meta.get(('*', stem)) or {}
            labels = dict(Dataset='mordor', SourceFile=rel, Tactic=slug(folder), **info)
            n, finfo = process_file(norm, f, os.path.join(args.out, 'mordor', rel), None, labels, args.keep_message)
            n_total += n
            rep = dict(dataset='mordor', file=rel, events=n, scenario=info.get('ScenarioId'))
            if finfo:
                rep.update(format=finfo[0], time_offset_hours=finfo[1], offset_from_sysmon=finfo[2])
            report['files'].append(rep)
    s = norm.stats
    report['events'] = n_total
    report['field_mapping'] = dict(mapped=s['mapped'], unmapped=s['unmapped'],
                                   ratio=round(s['mapped'] / max(1, s['mapped'] + s['unmapped']), 3))
    report['top_unmapped'] = [dict(provider=p, event_id=e, field=k, count=c)
                              for (p, e, k), c in norm.unmapped.most_common(100)]
    os.makedirs(args.out, exist_ok=True)
    json.dump(report, open(os.path.join(args.out, 'report.json'), 'w'), indent=1, ensure_ascii=False)
    print(f"{n_total} events | trường map được {s['mapped']}/{s['mapped'] + s['unmapped']} "
          f"({report['field_mapping']['ratio']:.1%}) | báo cáo: {args.out}/report.json")


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    b = sp.add_parser('build-map')
    b.add_argument('dd_root')
    b.add_argument('out')
    r = sp.add_parser('run')
    r.add_argument('--map', default=paths.OSSEM_MAP)
    r.add_argument('--evtx')
    r.add_argument('--mordor', help='thư mục data/raw/mordor/datasets')
    r.add_argument('--out', required=True)
    r.add_argument('--keep-message', action='store_true', help='giữ trường Message gốc (rất nặng)')
    a = ap.parse_args()
    build_map(a.dd_root, a.out) if a.cmd == 'build-map' else run(a)
