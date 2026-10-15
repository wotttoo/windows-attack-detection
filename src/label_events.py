"""Gán nhãn từng event cho file đã chuẩn hoá OSSEM: <tactic> nếu thuộc hành vi tấn công, "benign" nếu không,
"uncertain" nếu không đủ bằng chứng.

Cách làm: tìm event "hạt giống" chắc chắn của attacker (configs/label_seeds.yaml + metadata Mordor), rồi lan:
  - process cha khởi chạy hạt giống (cha được tạo <= PARENT_WINDOW giây trước con, vd wsmprovhost, fodhelper)
  - process con cháu (ProcessParentGuid) và process bị inject (Sysmon 8 CreateRemoteThread)
  - event Sysmon cùng ProcessGuid
  - event Security / PowerShell có ProcessId / ExecutionProcessId trùng PID độc hại trên cùng host, lúc process còn sống
  - PowerShell cổ điển (không có PID): HostApplication khớp mẫu hoặc trùng command line process độc hại
  - event Security cùng phiên đăng nhập (LogonId) với process độc hại
  - kết nối mạng cùng 4-tuple với kết nối độc hại (cả ở máy bên kia)

Dùng:
  1 file (in chi tiết): python src/label_events.py <file.json>
  cả thư mục:           python src/label_events.py --all data/interim/ossem/mordor --out data/interim/labels/mordor
  (--metadata mặc định data/raw/mordor/datasets/metadata)
"""
import sys, re, os, json, glob, argparse, collections
import paths
from datetime import datetime, timedelta

PARENT_WINDOW = timedelta(seconds=10)
START_SLACK = timedelta(seconds=2)  # Security 4688 thường ghi trước Sysmon 1 vài ms
SYSMON = 'Microsoft-Windows-Sysmon'
NET_EIDS = {(SYSMON, 3), ('Microsoft-Windows-Security-Auditing', 5156)}
SHARED_LOGONS = {0x3e7, 0x3e4, 0x3e5, 0}  # SYSTEM / NETWORK SERVICE / LOCAL SERVICE: dùng chung, không gán theo
LOGON_EIDS = {4624, 4627, 4634, 4647, 4672}
LOGON_WINDOW = timedelta(seconds=10)
LABEL_FIELDS = {'Dataset', 'SourceFile', 'Tactic', 'ScenarioId', 'ScenarioTitle', 'AttackTechniques', 'AttackTactics'}
PS_TEXT_FIELDS = ('PowershellScriptBlockText', 'PowershellCommandLine', 'PowershellPayload', 'PowershellHostApplication')


def host(e):
    return (e.get('DvcHostname') or '').split('.')[0].lower()


def ts(e):
    t = e.get('EventTimestamp')
    return datetime.fromisoformat(t.replace('Z', '+00:00')) if t else None


def logon_id(v):
    try:
        return int(str(v), 16) if v not in (None, '', '-') else None
    except ValueError:
        return None


def user(e):
    return (e.get('UserName') or '').split('\\')[-1].lower()


def flow(e):
    k = (e.get('SrcIpAddr'), e.get('SrcPort'), e.get('DstIpAddr'), e.get('DstPort'))
    return k if all(x not in (None, '') for x in k) else None


def any_match(patterns, *texts):
    return any(p.search(t) for p in patterns for t in texts if t)


def event_text(e):
    return ' | '.join(str(v) for k, v in e.items() if k not in LABEL_FIELDS and isinstance(v, (str, int)))


def scenario_name(e):
    stem = os.path.splitext(os.path.basename(e.get('SourceFile') or ''))[0]
    return re.sub(r'_\d{4}-\d{2}-\d{2}T?\d*$', '', stem)


def compile_scenario(s):
    """Mục cấu hình 1 kịch bản (cmd / script / events / skip) -> regex đã biên dịch."""
    s = s or {}
    comp = lambda xs: [re.compile(x, re.I) for x in xs or []]
    return dict(cmd=comp(s.get('cmd')), script=comp(s.get('script')), skip=bool(s.get('skip')),
                parent_launcher=s.get('parent_launcher', True),
                events=[dict(eid=set(r.get('eid') or []), provider=re.compile(r.get('provider', ''), re.I),
                             host=re.compile(r.get('host', ''), re.I),
                             match=re.compile(r.get('match', ''), re.I), process=bool(r.get('process')),
                             field=r.get('field'))
                        for r in s.get('events') or []])


def load_seeds(path):
    import yaml
    cfg = yaml.safe_load(open(path, encoding='utf-8'))
    comp = lambda xs: [re.compile(x, re.I) for x in xs or []]
    g = cfg.get('generic') or {}
    scen = {name: compile_scenario(s) for name, s in (cfg.get('scenarios') or {}).items()}
    c2 = cfg.get('c2') or {}
    return dict(cmd=comp(g.get('cmd')), script=comp(g.get('script')), c2_implant=comp(c2.get('implant')),
                c2_beacon=[re.compile(x, re.I | re.M) for x in c2.get('beacon') or []],
                c2_ports=set(c2.get('ports') or []),
                c2_runtime={(prov, eid) for prov, eids in (c2.get('runtime') or {}).items() for eid in eids},
                c2_sensitive=re.compile(c2.get('sensitive') or r'(?!x)x', re.I)), scen


def agents_from_metadata(meta_dir, scenario_id):
    """Bảng 'Active agents' của Empire trong adversary_view -> {(host, pid, process)}."""
    if not meta_dir or not scenario_id:
        return set()
    import yaml
    f = os.path.join(meta_dir, f'{scenario_id}.yaml')
    if not os.path.exists(f):
        return set()
    view = (yaml.safe_load(open(f, encoding='utf-8')).get('simulation') or {}).get('adversary_view') or ''
    rx = re.compile(r'^\s*[A-Z0-9]{8}\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+(\S+)\s+\*?\S+\s+(\S+)\s+(\d+)\s', re.M)
    return {(m.group(1).lower(), int(m.group(3)), m.group(2).lower()) for m in rx.finditer(view)}


def label_file(events, generic, scen, meta_dir=None):
    tactic = events[0].get('Tactic')
    cmd_pats = generic['cmd'] + scen.get('cmd', [])
    script_pats = generic['script'] + scen.get('script', [])
    agent_rows = agents_from_metadata(meta_dir, events[0].get('ScenarioId'))
    agent_images = {(h, name) for h, _, name in agent_rows}
    pid_seeds = {(h, pid): 'seed:agent-metadata' for h, pid, _ in agent_rows}

    # --- bảng process
    procs = {}

    def proc(g, e):
        return procs.setdefault(g, dict(host=host(e), pid=None, start=None, end=None, image=None, cmd=None, parent=None))

    for e in events:
        if e.get('Provider') != SYSMON:
            continue
        if e.get('ProcessGuid'):
            p = proc(e['ProcessGuid'], e)
            p['image'] = p['image'] or e.get('ProcessFilePath')
            if e.get('EventId') == 1:
                p.update(start=ts(e), cmd=e.get('ProcessCommandLine'), parent=e.get('ProcessParentGuid'))
            elif e.get('EventId') == 5:
                p['end'] = ts(e)
        if e.get('EventId') == 1 and e.get('ProcessParentGuid'):
            par = proc(e['ProcessParentGuid'], e)
            par['image'] = par['image'] or e.get('ProcessParentFilePath')
            par['cmd'] = par['cmd'] or e.get('ProcessParentCommandLine')
    # Mordor (NXLog) có file mất ProcessId của Sysmon -> lấy lại PID từ các cặp GUID/PID khác
    for e in events:
        if e.get('Provider') != SYSMON:
            continue
        for gk, pk in (('ProcessGuid', 'ProcessId'), ('ProcessParentGuid', 'ProcessParentId'),
                       ('TargetProcessGuid', 'TargetProcessId')):
            g, pid = e.get(gk), e.get(pk)
            if g and pid is not None:
                p = proc(g, e)
                p['pid'] = p['pid'] if p['pid'] is not None else pid
    # ... hoặc từ Security 4688 cùng host, cùng file, cách nhau <= 2 giây
    created = collections.defaultdict(list)
    for e in events:
        if e.get('EventId') == 4688 and e.get('ProcessId') is not None:
            created[(host(e), (e.get('ProcessFilePath') or '').lower())].append((ts(e), e['ProcessId']))
    for p in procs.values():
        if p['pid'] is None and p['start'] and p['image']:
            for t, pid in created.get((p['host'], p['image'].lower()), []):
                if t and abs((t - p['start']).total_seconds()) <= 2:
                    p['pid'] = pid
                    break

    # --- hạt giống từ event: script PowerShell, HostApplication, luật events
    direct = {}
    for i, e in enumerate(events):
        h = host(e)
        if any_match(script_pats, *(e.get(f) for f in PS_TEXT_FIELDS)):
            direct[i] = 'seed:script'
            if e.get('ExecutionProcessId'):
                pid_seeds.setdefault((h, e['ExecutionProcessId']), 'seed:script')
        elif e.get('ExecutionProcessId') and any_match(cmd_pats, e.get('PowershellHostApplication')):
            pid_seeds.setdefault((h, e['ExecutionProcessId']), 'seed:powershell-host')
        for r in scen.get('events', []):
            if (r['eid'] and e.get('EventId') not in r['eid']) or not r['provider'].search(e.get('Provider') or '') \
                    or not r['host'].search(e.get('DvcHostname') or '') \
                    or not r['match'].search(str(e.get(r['field']) or '') if r['field'] else event_text(e)):
                continue
            direct[i] = 'seed:event-rule'
            if r['process']:
                if e.get('Provider') == SYSMON and e.get('ProcessGuid'):
                    procs[e['ProcessGuid']]['seed_rule'] = True
                elif e.get('ProcessId') is not None:
                    pid_seeds.setdefault((h, e['ProcessId']), 'seed:event-rule')

    reason = {}
    for g, p in procs.items():
        if p.get('seed_rule'):
            reason[g] = 'seed:event-rule'
        elif any_match(cmd_pats, p['cmd'], p['image']):
            reason[g] = 'seed:cmd'
        elif (p['host'], p['pid']) in pid_seeds:
            reason[g] = pid_seeds[(p['host'], p['pid'])]
    for g in list(reason) if scen.get('parent_launcher', True) else []:  # process cha khởi chạy hạt giống
        par = procs.get(procs[g]['parent'])
        if par and par['start'] and procs[g]['start'] and \
                timedelta(0) <= procs[g]['start'] - par['start'] <= PARENT_WINDOW:
            reason.setdefault(procs[g]['parent'], 'parent-launcher')
    injections = [(e['ProcessGuid'], e['TargetProcessGuid']) for e in events
                  if e.get('Provider') == SYSMON and e.get('EventId') == 8
                  and e.get('ProcessGuid') and e.get('TargetProcessGuid')]
    changed = True
    while changed:  # con cháu + process bị inject
        changed = False
        for g, p in procs.items():
            if g not in reason and p['parent'] in reason:
                reason[g] = 'child-process'
                changed = True
        for src, dst in injections:
            if src in reason and dst not in reason and dst in procs:
                reason[dst] = 'injected-target'
                changed = True

    bad_pids = collections.defaultdict(list)
    for g in reason:
        p = procs[g]
        if p['pid'] is not None:
            bad_pids[(p['host'], p['pid'])].append((p['start'], p['end']))
    for k in pid_seeds:
        bad_pids.setdefault(k, [(None, None)])
    bad_cmds = {(procs[g]['host'], procs[g]['cmd']) for g in reason if procs[g]['cmd']}
    bad_logons = set()
    for i in direct:  # phiên đăng nhập dùng cho truy cập độc hại (vd 5145 svcctl từ máy attacker)
        e = events[i]
        lid = logon_id(e.get('UserLogonId'))
        if e.get('Provider') != SYSMON and lid is not None and lid not in SHARED_LOGONS:
            bad_logons.add((host(e), lid))
    for e in events:
        if e.get('Provider') == SYSMON and e.get('EventId') == 1 and e.get('ProcessGuid') in reason:
            lid = logon_id(e.get('UserLogonId'))
            if lid is not None and lid not in SHARED_LOGONS:
                bad_logons.add((host(e), lid))

    def pid_alive(h, pid, t):
        for s, e in bad_pids.get((h, pid), []):
            if (s is None or t is None or t >= s - START_SLACK) and (e is None or t is None or t <= e + START_SLACK):
                return True
        return False

    out = []
    for i, e in enumerate(events):
        h, t, why = host(e), ts(e), direct.get(i)
        if not why and e.get('Provider') == SYSMON:
            why = reason.get(e.get('ProcessGuid')) and 'sysmon:process-guid'
            p = procs.get(e.get('ProcessGuid'))
            img = os.path.splitext(re.split(r'[\\/]', (p or {}).get('image') or '')[-1].lower())[0]
            if not why and p and p['pid'] is None and (h, img) in agent_images:
                why = 'uncertain:agent-image-no-pid'
        elif not why:
            for f in ('ProcessId', 'ExecutionProcessId'):
                if e.get(f) is not None and pid_alive(h, e[f], t):
                    why = f'pid:{f}'
                    break
            if not why and (h, logon_id(e.get('UserLogonId'))) in bad_logons:
                why = 'logon-session'
            app = e.get('PowershellHostApplication')
            if not why and app and (any_match(cmd_pats, app) or (h, app) in bad_cmds):
                why = 'powershell:host-application'
        out.append(why)
    bad_flows = set()
    for e, why in zip(events, out):
        if why and not why.startswith('uncertain') and (e.get('Provider'), e.get('EventId')) in NET_EIDS and flow(e):
            f = flow(e)
            bad_flows |= {f, (f[2], f[3], f[0], f[1])}
    for i, e in enumerate(events):
        if not out[i] and (e.get('Provider'), e.get('EventId')) in NET_EIDS and flow(e) in bad_flows:
            out[i] = 'network:flow-match'
    anchors = [(host(e), user(e), ts(e)) for e, why in zip(events, out)
               if why == 'logon-session' and e.get('EventId') == 4624]
    for i, e in enumerate(events):
        if not out[i] and e.get('EventId') in LOGON_EIDS and (e.get('Provider') or '').endswith('Security-Auditing'):
            if any(h == host(e) and u == user(e) and t and ts(e) and abs(ts(e) - t) <= LOGON_WINDOW
                   for h, u, t in anchors):
                out[i] = 'uncertain:nearby-logon-same-user'

    # --- implant C2: process là agent/Grunt (+ process bị implant inject)
    implant = {g for g, p in procs.items() if g in reason and
               (reason[g] in ('seed:agent-metadata', 'seed:powershell-host') or
                any_match(generic['c2_implant'], p['cmd'], p['image']))}
    changed = True
    while changed:
        changed = False
        for src, dst in injections:
            if src in implant and dst not in implant and dst in procs:
                implant.add(dst)
                changed = True
    implant_pids = {(procs[g]['host'], procs[g]['pid']) for g in implant if procs[g]['pid'] is not None}
    implant_pids |= {k for k, v in pid_seeds.items() if v in ('seed:agent-metadata', 'seed:powershell-host')}

    def is_implant(e):
        h = host(e)
        if e.get('Provider') == SYSMON:
            return e.get('ProcessGuid') in implant
        if any((h, e.get(f)) in implant_pids for f in ('ProcessId', 'ExecutionProcessId') if e.get(f) is not None):
            return True
        return any_match(generic['c2_implant'], e.get('PowershellHostApplication'))

    def c2_kind(e):
        if (e.get('Provider') or '').endswith('PowerShell'):
            text = '\n'.join(str(e.get(f) or '') for f in ('PowershellCommandName', 'PowershellCommandLine',
                                                           'PowershellPayload', 'PowershellScriptBlockText'))
            return 'c2:beacon' if any_match(generic['c2_beacon'], text) else None
        eid = e.get('EventId')
        if (e.get('Provider'), eid) in NET_EIDS and e.get('DstPort') in generic['c2_ports']:
            return 'c2:channel'
        if eid == 5158:  # bind cổng nguồn cho kết nối ra ngoài
            return 'c2:channel'
        if (e.get('Provider'), eid) in generic['c2_runtime'] and not generic['c2_sensitive'].search(event_text(e)):
            return 'c2:implant-runtime'
        return None

    for i, (e, why) in enumerate(zip(events, out)):
        if why and not why.startswith('uncertain') and is_implant(e):
            kind = c2_kind(e)
            if kind:
                out[i] = f'{why}|{kind}'

    for e, why in zip(events, out):
        unsure = bool(why) and why.startswith('uncertain')
        if why and '|c2:' in why:
            e['label'], e['label_malicious'], e['label_method'] = 'command-and-control', 1, why
            continue
        e['label'] = 'uncertain' if unsure else (tactic if why else 'benign')
        e['label_malicious'] = -1 if unsure else int(bool(why))
        e['label_method'] = why or 'background'
    return events, reason, procs


def read(path):
    return [json.loads(l) for l in open(path, encoding='utf-8') if l.strip()]


def write(path, events):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fo:
        for e in events:
            fo.write(json.dumps(e, ensure_ascii=False) + '\n')


def print_detail(path, events, reason, procs):
    print(f'File: {path}\nTổng: {len(events)} event\n\n== Process độc hại ({len(reason)})')
    for g, why in sorted(reason.items(), key=lambda kv: str(procs[kv[0]]['start'])):
        p = procs[g]
        print(f"  {str(p['start'] or '')[11:19] or '?':8} {p['host']:13} pid={p['pid']!s:6} {why:20} "
              f"{(p['cmd'] or p['image'] or '')[:90]}")
    print('\n== Nhãn:', dict(collections.Counter(e['label'] for e in events)))
    print('== Lý do:', dict(collections.Counter(e['label_method'] for e in events if e['label_malicious'] != 0)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file', nargs='?')
    ap.add_argument('--all', help='thư mục ossem/<dataset> để gán nhãn toàn bộ')
    ap.add_argument('--seeds', default=paths.SEEDS)
    ap.add_argument('--metadata', default=paths.MORDOR_METADATA)
    ap.add_argument('--out')
    a = ap.parse_args()
    generic, scenarios = load_seeds(a.seeds)

    if a.file:
        events = read(a.file)
        scen = scenarios.get(scenario_name(events[0]), {})
        events, reason, procs = label_file(events, generic, scen, a.metadata)
        print_detail(a.file, events, reason, procs)
        if a.out:
            write(a.out, events)
        return

    rows = []
    for f in sorted(glob.glob(os.path.join(a.all, '**', '*.json'), recursive=True)):
        events = read(f)
        if not events:
            continue
        name = scenario_name(events[0])
        scen = scenarios.get(name)
        rel = os.path.relpath(f, a.all)
        if scen is None:
            print(f'!! chưa có cấu hình hạt giống: {name}')
            scen = {}
        if scen.get('skip'):
            rows.append(dict(file=rel, scenario=name, events=len(events), status='skip'))
            continue
        events, reason, procs = label_file(events, generic, scen, a.metadata)
        c = collections.Counter(e['label_malicious'] for e in events)
        rows.append(dict(file=rel, scenario=name, tactic=events[0].get('Tactic'), events=len(events),
                         malicious=c[1], uncertain=c[-1], benign=c[0], malicious_ratio=round(c[1] / len(events), 3),
                         bad_processes=len(reason),
                         methods=dict(collections.Counter(e['label_method'] for e in events if e['label_malicious'])),
                         status='NO_MALICIOUS' if c[1] == 0 else 'ok'))
        if a.out:
            write(os.path.join(a.out, rel), events)
    tot = collections.Counter()
    for r in rows:
        print(f"{r['status']:12} {r['events']:6} mal={r.get('malicious', 0):6} unc={r.get('uncertain', 0):4} "
              f"({r.get('malicious_ratio', 0):.0%}) proc={r.get('bad_processes', 0):3}  {r['scenario']}")
        for k in ('events', 'malicious', 'uncertain', 'benign'):
            tot[k] += r.get(k, 0) if r['status'] != 'skip' else 0
    print(f"\nTổng: {dict(tot)}")
    if a.out:
        json.dump(rows, open(os.path.join(a.out, 'label_report.json'), 'w'), indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
