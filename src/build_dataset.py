"""Gộp nhãn của Mordor (data/interim/labels/mordor/) và EVTX (data/interim/labels/evtx/) thành 1 bảng Parquet để train model.

Mỗi dòng là 1 event, gồm:
  - cột meta (KHÔNG dùng làm feature): dataset, group, label, label_malicious, label_method, n_dup
  - cột feature đã làm sạch: loại event, tên process, kiểu tài khoản, quyền truy cập, văn bản đã chuẩn hoá...

Bỏ hẳn các trường làm lộ nhãn hoặc lộ bộ dữ liệu: hostname, IP, tên user/domain, timestamp, PID/GUID, SourceFile,
Tactic, Scenario*. Văn bản được chuẩn hoá: chữ thường; tên host / user / domain của lab, GUID, SID, IP, hex, số dài
-> token chung (<host>, <user>, <guid>...).

Event uncertain bị bỏ (trừ khi --keep-uncertain). Sysmon 7 nạp DLL hệ thống ký Microsoft bị bỏ (sys_dll_load,
trừ khi --keep-sys-dll). Event giống hệt nhau (sau chuẩn hoá) trong cùng file chỉ giữ 1 dòng, cột n_dup là số lần
lặp (tắt bằng --no-dedup).

Dùng:
  python src/build_dataset.py            # -> data/processed/events.parquet + events_summary.json
  python src/build_dataset.py --view     # + bản CSV để xem: data/processed/events_view.csv, view_by_event/
"""
import os, re, json, glob, math, argparse, collections
import pandas as pd

import paths

# trường không bao giờ đưa vào feature (lộ nhãn / lộ bộ dữ liệu / định danh ngẫu nhiên)
LEAK = {'Dataset', 'SourceFile', 'Tactic', 'ScenarioId', 'ScenarioTitle', 'AttackTechniques', 'AttackTactics',
        'label', 'label_malicious', 'label_method', 'DvcHostname', 'EventMessage'}
SKIP_KEY = re.compile(r'Guid|Hash|Id$|ID$|Time|Timestamp|Sid$|Uid$|Hostname|HostName|IpAddr|Port$|PortName|Domain|'
                      r'UserName|User$|Version|Severity|Sequence|Count|Total|Number|Handle|Address|Index|^Ip|Weight|'
                      r'CallTrace|^Event(Original|Creation)|^Execution|Keywords|Opcode|^Task$|^Level$|RuleName|^Tag$|'
                      r'^File(Version|Product|Company|Description)$|Signature$|^Channel$|^Provider$|^EventId$')

# trường đã có cột riêng -> không lặp lại trong other_text
USED = {'ProcessFilePath', 'ProcessName', 'processPath', 'ProcessParentFilePath', 'TargetProcessFilePath',
        'ProcessCommandLine', 'ProcessParentCommandLine', 'PowershellScriptBlockText', 'PowershellPayload',
        'PowershellCommandLine', 'PowershellHostApplication', 'RegistryKeyPath', 'RegistryValueData', 'FileName',
        'ModulePath', 'PipeName', 'ShareName', 'ShareRelativeTargetName', 'ObjectName', 'ObjectType',
        'ProcessGrantedAccess', 'ObjectAccessMask', 'ShareAccessMask', 'LogonType', 'ProcessIntegrityLevel',
        'ModuleIsSigned', 'ModuleSignatureStatus', 'EventType', 'RegistryEventType', 'NetworkProtocol', 'DstPort',
        'DstIpAddr', 'Direction', 'NetworkInitiated', 'ServiceName', 'ServiceFileName', 'TicketEncryptionType',
        'TicketEncryption', 'LogonAuthenticationPackageName', 'LogonProcessName', 'QueryName'}

BUILTIN_USERS = {'system', 'administrator', 'administrators', 'guest', 'local service', 'network service',
                 'anonymous logon', 'defaultaccount', 'krbtgt', 'users', 'everyone', 'nt authority', 'builtin',
                 'workgroup', 'window manager', 'font driver host', 'iis apppool', 'defaultapppool', '-', ''}

RX_GUID = re.compile(r'\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?')
RX_SID = re.compile(r's-1-5-21(-\d+){3,4}')
RX_IPV4 = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')
RX_IPV6 = re.compile(r'\b(fe80|ff02|::ffff)(:[0-9a-f]{0,4}){2,7}(%\d+)?')
RX_HEX = re.compile(r'\b0x[0-9a-f]+\b')
RX_LONGHEX = re.compile(r'\b[0-9a-f]{12,}\b')
RX_NUM = re.compile(r'\b\d{4,}\b')
RX_B64 = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
RX_WS = re.compile(r'\s+')


def base(p):
    return re.split(r'[\\/]', str(p or ''))[-1].lower()


def entropy(s):
    if not s:
        return 0.0
    c = collections.Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


class Normalizer:
    """Thay tên host / user / domain của các lab (thu thập từ dữ liệu) + định danh ngẫu nhiên bằng token."""

    def __init__(self, hosts, users, domains):
        def rx(words):
            words = sorted({w for w in words if len(w) >= 3}, key=len, reverse=True)
            return re.compile(r'(?<![a-z0-9])(' + '|'.join(map(re.escape, words)) + r')(?![a-z0-9])') if words else None
        self.rx_host, self.rx_user, self.rx_domain = rx(hosts), rx(users), rx(domains)

    def __call__(self, s, keep_guid=False, limit=None):
        if s is None or s == '':
            return ''
        s = str(s).lower()
        if limit:
            s = s[:limit]
        s = s.replace('\\\\', '\\')
        if not keep_guid:
            s = RX_GUID.sub('<guid>', s)
        s = RX_SID.sub('<sid>', s)
        s = RX_IPV4.sub('<ip>', s)
        s = RX_IPV6.sub('<ip>', s)
        if self.rx_domain:
            s = self.rx_domain.sub('<domain>', s)
        if self.rx_host:
            s = self.rx_host.sub('<host>', s)
        if self.rx_user:
            s = self.rx_user.sub('<user>', s)
        s = RX_HEX.sub('<hex>', s)
        s = RX_LONGHEX.sub('<hex>', s)
        s = RX_NUM.sub('<num>', s)
        return RX_WS.sub(' ', s).strip()


RX_SYS_DIR = re.compile(r'^c:\\windows\\(system32|syswow64|winsxs|microsoft\.net|assembly)\\', re.I)


def sys_dll_load(e):
    """Sysmon 7 nạp DLL hệ thống có chữ ký Microsoft hợp lệ. Bản thân event không chứa dấu hiệu tấn công: nhãn
    chỉ suy ra được từ process đã nạp nó (Mordor gán theo process, EVTX gán benign) -> bỏ khỏi train / đánh giá
    (giữ lại bằng --keep-sys-dll)."""
    return (e.get('EventId') == 7 and 'Sysmon' in (e.get('Provider') or '')
            and str(e.get('ModuleSignatureStatus') or '').lower() == 'valid'
            and str(e.get('ModuleSignature') or '').lower().startswith('microsoft')
            and bool(RX_SYS_DIR.match(str(e.get('ModulePath') or ''))))


def iter_events(dirs, keep_uncertain):
    for name, d in dirs:
        for f in sorted(glob.glob(os.path.join(d, '**', '*.json'), recursive=True)):
            if os.path.basename(f) == 'label_report.json':
                continue
            for line in open(f, encoding='utf-8'):
                if not line.strip():
                    continue
                e = json.loads(line)
                if e.get('label_malicious') == -1 and not keep_uncertain:
                    continue
                yield name, e


def collect_vocab(dirs, events=None):
    """Lượt 1: tên host / user / domain xuất hiện trong dữ liệu (để thay bằng token). events: list event OSSEM
    dùng thay cho dirs (predict.py)."""
    hosts, users, domains = set(), set(), set()
    for e in (events if events is not None else (e for _, e in iter_events(dirs, True))):
        h = (e.get('DvcHostname') or '').lower()
        if h:
            hosts.add(h.split('.')[0])
            domains.update(p for p in h.split('.')[1:] if p not in ('local', 'com', 'corp', 'internal', 'home'))
        for k in ('UserName', 'TargetUserName', 'SubjectUserName', 'UserDomain', 'TargetUserDomain', 'SrcHostName',
                  'SrcDvcHostname', 'DstDvcHostname', 'TargetHostName'):
            v = str(e.get(k) or '').lower()
            for part in re.split(r'[\\@]', v):
                part = part.strip().rstrip('$')
                if not part or part in BUILTIN_USERS:
                    continue
                if 'Domain' in k:
                    domains.add(part.split('.')[0])
                elif 'Host' in k:
                    hosts.add(part.split('.')[0])
                else:
                    users.add(part)
    hosts = {h for h in hosts if h not in BUILTIN_USERS}
    return hosts, users - hosts, domains - BUILTIN_USERS


def user_type(e):
    sid = str(e.get('UserSid') or e.get('TargetUserSid') or '')
    name = str(e.get('UserName') or e.get('TargetUserName') or '').split('\\')[-1].lower()
    if sid == 'S-1-5-18' or name == 'system':
        return 'system'
    if sid in ('S-1-5-19', 'S-1-5-20') or name in ('local service', 'network service'):
        return 'service'
    if sid == 'S-1-5-7' or name == 'anonymous logon':
        return 'anonymous'
    if name.endswith('$'):
        return 'machine'
    if name.startswith('dwm-') or name.startswith('umfd-') or 'apppool' in str(e.get('UserName') or '').lower():
        return 'virtual'
    if name in ('administrator', 'admin') or sid.endswith('-500'):
        return 'admin'
    return 'user' if name or sid else ''


def ip_type(ip):
    ip = str(ip or '').lower()
    if not ip or ip == '-':
        return ''
    if ip.startswith(('127.', '::1', '0:0:0:0:0:0:0:1')):
        return 'loopback'
    if ip.startswith(('fe80', 'ff02', '224.', '239.', '255.')) or ip.endswith('.255'):
        return 'linklocal_multicast'
    if re.match(r'(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::ffff:(10|172|192)\.)', ip):
        return 'private'
    return 'public'


def to_int(v):
    try:
        return int(str(v), 0) if str(v).startswith('0x') else int(v)
    except (TypeError, ValueError):
        return -1


def build_row(dataset, e, norm):
    cmd = str(e.get('ProcessCommandLine') or '')
    ps = '\n'.join(str(e.get(k) or '') for k in ('PowershellScriptBlockText', 'PowershellCommandLine',
                                                  'PowershellPayload') if e.get(k))
    other = ' '.join(f'{k}={norm(v, keep_guid=(k == "InterfaceUuid"), limit=200)}' for k, v in sorted(e.items())
                     if k not in LEAK and k not in USED and not SKIP_KEY.search(k)
                     and isinstance(v, (str, int)) and str(v) not in ('', '-', 'NULL', 'None'))
    stem = os.path.splitext(os.path.basename(e.get('SourceFile') or ''))[0]
    if dataset == 'mordor':
        stem = re.sub(r'_\d{4}-\d{2}-\d{2}T?\d*$', '', stem)
    return dict(
        # ---- meta (không dùng làm feature)
        dataset=dataset, group=f'{dataset}:{stem}', label=e.get('label'),
        label_malicious=e.get('label_malicious'), label_method=e.get('label_method'),
        # ---- loại event
        provider=(e.get('Provider') or '').replace('Microsoft-Windows-', ''), event_id=to_int(e.get('EventId')),
        # ---- process
        image=base(e.get('ProcessFilePath') or e.get('ProcessName') or e.get('processPath')),
        parent_image=base(e.get('ProcessParentFilePath')),
        target_image=base(e.get('TargetProcessFilePath')),
        image_path=norm(os.path.dirname(str(e.get('ProcessFilePath') or '').replace('\\', '/'))),
        integrity_level=str(e.get('ProcessIntegrityLevel') or '').lower(),
        user_type=user_type(e),
        logon_type=to_int(e.get('LogonType')),
        # ---- quyền / đối tượng
        granted_access=str(e.get('ProcessGrantedAccess') or '').lower(),
        access_mask=str(e.get('ObjectAccessMask') or e.get('ShareAccessMask') or '').lower(),
        object_type=str(e.get('ObjectType') or '').lower(),
        registry_event=str(e.get('RegistryEventType') or e.get('EventType') or '').lower(),
        module_signed=str(e.get('ModuleIsSigned') or '').lower(),
        signature_status=str(e.get('ModuleSignatureStatus') or '').lower(),
        auth_package=str(e.get('LogonAuthenticationPackageName') or e.get('LogonProcessName') or '').strip().lower(),
        ticket_encryption=str(e.get('TicketEncryptionType') or e.get('TicketEncryption') or '').lower(),
        # ---- mạng
        protocol=str(e.get('NetworkProtocol') or '').lower(),
        dst_port=to_int(e.get('DstPort')),
        dst_ip_type=ip_type(e.get('DstIpAddr')),
        network_direction=str(e.get('Direction') or e.get('NetworkInitiated') or '').lower(),
        # ---- văn bản đã chuẩn hoá
        cmdline=norm(cmd, limit=2000),
        parent_cmdline=norm(e.get('ProcessParentCommandLine'), limit=2000),
        ps_host_app=norm(e.get('PowershellHostApplication'), limit=2000),
        ps_text=norm(ps, limit=4000),
        registry=norm(' '.join(str(e.get(k) or '') for k in ('RegistryKeyPath', 'RegistryValueData'))),
        file_path=norm(e.get('FileName')),
        module_path=norm(e.get('ModulePath')),
        pipe=norm(e.get('PipeName')),
        share=norm(' '.join(str(e.get(k) or '') for k in ('ShareName', 'ShareRelativeTargetName'))),
        object_name=norm(e.get('ObjectName'), limit=500),
        service=norm(' '.join(str(e.get(k) or '') for k in ('ServiceName', 'ServiceFileName'))),
        dns_query=norm(e.get('QueryName')),
        other_text=other[:1000],
        # ---- số
        cmd_len=len(cmd), cmd_entropy=round(entropy(cmd), 3), cmd_has_b64=int(bool(RX_B64.search(cmd))),
        ps_len=len(ps), ps_has_b64=int(bool(RX_B64.search(ps))),
    )


META = ['dataset', 'group', 'label', 'label_malicious', 'label_method']


def write_view(df, out):
    """Bản CSV chỉ để xem bằng mắt (Excel đọc được UTF-8): toàn bảng + mỗi loại event (provider, event_id) 1 file."""
    d = os.path.dirname(os.path.abspath(out))
    df.to_csv(os.path.join(d, 'events_view.csv'), index=False, encoding='utf-8-sig')
    vd = os.path.join(d, 'view_by_event')
    os.makedirs(vd, exist_ok=True)
    for f in glob.glob(os.path.join(vd, '*.csv')):
        os.remove(f)
    for (prov, eid), g in df.groupby(['provider', 'event_id']):
        name = re.sub(r'[^A-Za-z0-9]+', '_', f'{prov}_{eid}').strip('_')
        g.to_csv(os.path.join(vd, name + '.csv'), index=False, encoding='utf-8-sig')
    print(f'Ghi bản xem: {d}/events_view.csv, {vd}/ ({df.groupby(["provider", "event_id"]).ngroups} file)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mordor', default=os.path.join(paths.LABELS, 'mordor'))
    ap.add_argument('--evtx', default=os.path.join(paths.LABELS, 'evtx'))
    ap.add_argument('--out', default=paths.DATASET)
    ap.add_argument('--keep-uncertain', action='store_true')
    ap.add_argument('--no-dedup', action='store_true')
    ap.add_argument('--keep-sys-dll', action='store_true',
                    help='giữ Sysmon 7 nạp DLL hệ thống ký Microsoft (mặc định bỏ, xem sys_dll_load)')
    ap.add_argument('--view', action='store_true', help='ghi thêm bản CSV để xem (events_view.csv, view_by_event/)')
    a = ap.parse_args()
    dirs = [('mordor', a.mordor), ('evtx', a.evtx)]

    print('Lượt 1: thu thập tên host / user / domain ...')
    hosts, users, domains = collect_vocab(dirs)
    print(f'  {len(hosts)} host, {len(users)} user, {len(domains)} domain')
    norm = Normalizer(hosts, users, domains)

    print('Lượt 2: tạo feature ...')
    rows, seen, n_in, n_sys = [], {}, 0, 0
    for dataset, e in iter_events(dirs, a.keep_uncertain):
        n_in += 1
        if not a.keep_sys_dll and sys_dll_load(e):
            n_sys += 1
            continue
        r = build_row(dataset, e, norm)
        if a.no_dedup:
            r['n_dup'] = 1
            rows.append(r)
            continue
        key = (r['group'], r['label'], tuple(v for k, v in r.items() if k not in META))
        if key in seen:
            rows[seen[key]]['n_dup'] += 1
        else:
            seen[key] = len(rows)
            r['n_dup'] = 1
            rows.append(r)
    df = pd.DataFrame(rows)
    del rows, seen
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    df.to_parquet(a.out, index=False)
    if a.view:
        write_view(df, a.out)

    print(f'Bỏ {n_sys} event Sysmon 7 nạp DLL hệ thống ký Microsoft')
    print(f'\nĐọc {n_in} event -> {len(df)} dòng ({"không khử trùng" if a.no_dedup else "đã khử trùng trong từng file"})')
    print(f'Ghi {a.out} ({os.path.getsize(a.out) / 1e6:.1f} MB), {len(df.columns)} cột, {df["group"].nunique()} group')
    summary = df.groupby(['label', 'dataset']).agg(rows=('n_dup', 'size'), events=('n_dup', 'sum')).unstack(fill_value=0)
    print('\n', summary.to_string())
    by_label = df.groupby(['dataset', 'label'])['n_dup'].agg(['size', 'sum'])
    stats = dict(input_events=n_in, sys_dll_dropped=n_sys, rows=len(df), groups=int(df['group'].nunique()), columns=list(df.columns),
                 hosts=len(hosts), users=len(users), domains=len(domains),
                 by_label={f'{d}|{l}': dict(rows=int(r['size']), events=int(r['sum'])) for (d, l), r in by_label.iterrows()})
    json.dump(stats, open(os.path.splitext(a.out)[0] + '_summary.json', 'w'), indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
