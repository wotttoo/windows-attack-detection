"""Gộp các event bị predict.py báo độc hại thành cảnh báo, kèm giải thích bằng cờ hành vi.

Một event riêng lẻ ít thông tin (tactic theo event còn yếu), nên người xem cần cảnh báo ở mức "chuỗi hành vi":
các event độc hại trên cùng máy được nối với nhau nếu
  - cùng cây process: cùng ProcessGuid, cha -> con (Sysmon 1), process inject sang process khác (Sysmon 8);
  - cùng process theo PID: ProcessId (Sysmon / Security) hoặc ExecutionProcessId (PowerShell);
  - cùng phiên đăng nhập (LogonId), trừ các phiên dùng chung của SYSTEM / LOCAL / NETWORK SERVICE;
  - gần nhau về thời gian: cách nhau <= --window giây.
Process "trung tâm" của hệ thống (services, svchost, explorer, wininit...) không dùng làm điểm nối, để các hoạt động
không liên quan không bị gộp chung. Một nhóm bị cắt thành nhiều cảnh báo nếu có khoảng lặng > --max-gap giây.

Mỗi cảnh báo có: máy, thời gian, số event, tactic theo thứ tự xuất hiện, process, user, cờ hành vi (giải thích),
các event điểm cao nhất, mức độ (high / medium / low).
Nếu đầu vào có nhãn (labels/) thì tính thêm chỉ số theo cảnh báo.

Dùng:
  python src/alert.py <file/thư mục .evtx / .json>        # chạy predict.py rồi gộp cảnh báo
  python src/alert.py --predictions results/predict/<tên>/predictions.csv
Kết quả (cùng thư mục với predictions.csv): alerts.md, alerts.csv (1 dòng / cảnh báo), alert_events.csv (event của
từng cảnh báo).
"""
import os, sys, argparse, collections
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SHARED_LOGONS = {0x3e7, 0x3e4, 0x3e5, 0}  # SYSTEM / NETWORK SERVICE / LOCAL SERVICE
HUB_IMAGES = {'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'svchost.exe',
              'lsass.exe', 'explorer.exe', 'userinit.exe', 'taskhostw.exe', 'taskeng.exe', 'sihost.exe'}
SEVERITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}
# cờ hành vi có mức nguy hiểm cao: đủ để nâng cảnh báo lên high
CRITICAL_FLAGS = {'f_cred_tool', 'f_cred_dump_file', 'b_lsass_target', 'f_log_tamper', 'f_av_tamper',
                  'f_shadow_copy', 'f_amsi_bypass', 'f_proc_inject', 'f_wmi_sub', 'k_appinit_lsa'}

FLAG_TEXT = {
    'f_download': 'tải file / script từ mạng',
    'f_encoded': 'lệnh mã hoá base64',
    'f_hidden_ps': 'PowerShell chạy ẩn / bỏ qua execution policy',
    'f_iex': 'thực thi chuỗi lệnh động (iex)',
    'f_reflection': 'nạp code vào bộ nhớ (reflection, VirtualAlloc)',
    'f_amsi_bypass': 'vô hiệu AMSI',
    'f_script_proto': 'chạy script qua javascript:/vbscript:/scriptlet',
    'f_dotnet_inline': 'biên dịch / nạp C# tại chỗ',
    'f_service_cfg': 'tạo / sửa service',
    'f_schtask': 'tạo scheduled task',
    'f_reg_write': 'ghi registry bằng lệnh',
    'f_wmi_sub': 'WMI event subscription (persistence)',
    'f_user_mgmt': 'thêm / xoá tài khoản, nhóm',
    'f_cred_tool': 'công cụ đánh cắp thông tin xác thực (mimikatz, kerberoast...)',
    'f_cred_dump_file': 'dump lsass / SAM / NTDS',
    'f_cred_store': 'đọc kho mật khẩu, cookie, credential',
    'f_shadow_copy': 'thao tác shadow copy',
    'f_discovery_cmd': 'lệnh khám phá hệ thống / domain',
    'f_sam_enum': 'liệt kê SAM / LSA qua RPC',
    'f_remote_target': 'thực thi trên máy khác (WMI, WinRM, PsExec, DCOM)',
    'f_admin_share': 'truy cập share quản trị (ADMIN$, C$, IPC$)',
    'f_rpc_pipe': 'named pipe RPC nhạy cảm (svcctl, samr, lsarpc...)',
    'f_log_tamper': 'xoá / sửa log, audit policy',
    'f_av_tamper': 'can thiệp Defender / firewall',
    'f_hide_file': 'ẩn file / ADS',
    'f_proc_inject': 'inject vào process khác',
    'k_run': 'khoá Run / RunOnce',
    'k_services': 'khoá cấu hình service',
    'k_winlogon': 'khoá Winlogon',
    'k_ifeo': 'khoá IFEO / SilentProcessExit',
    'k_com_hijack': 'chiếm COM object',
    'k_uac_bypass': 'khoá dùng để vượt UAC',
    'k_appinit_lsa': 'khoá AppInit / LSA / print monitor',
    'k_startup_dir': 'thư mục Startup',
    'k_task_dir': 'file / khoá scheduled task',
    'f_drop_exec': 'ghi file thực thi / script',
    'f_lnk_or_doc': 'file Office có macro / lnk',
    'b_user_writable': 'chạy từ thư mục người dùng ghi được (temp, profile, programdata)',
    'b_renamed': 'binary bị đổi tên',
    'b_unsigned_module': 'nạp module không ký',
    'b_public_dst': 'kết nối ra IP public',
    'b_lsass_target': 'truy cập process lsass',
    'b_full_access': 'mở process với toàn quyền',
    'b_vm_read': 'đọc bộ nhớ process khác',
    'b_child_of_office': 'process con của Office',
    'b_child_of_remote': 'process con của dịch vụ thực thi từ xa (wsmprovhost, wmiprvse, DCOM)',
    'b_shell_child_of_script': 'shell / LOLBin do script host / Office / trình duyệt sinh ra',
}


def base(p):
    return str(p or '').replace('\\', '/').rsplit('/', 1)[-1].lower()


def short_provider(p):
    p = str(p)
    for k in ('Sysmon', 'Security', 'PowerShell'):
        if k.lower() in p.lower():
            return k
    return p.split('-')[-1]


def to_int(v):
    s = val(v)
    if s is None:
        return None
    try:
        return int(s, 16) if s.lower().startswith('0x') else int(float(s))
    except ValueError:
        return None


def val(v):
    """Giá trị rỗng / NaN / '-' -> None (CSV đọc ô trống thành NaN)."""
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    s = str(v).strip()
    return None if s in ('', '-', 'nan', 'None') else s


def link_keys(r, guid_image):
    """Các khoá nối của 1 event (chỉ cùng máy)."""
    h = str(r.host or '').split('.')[0].lower()
    keys = []
    hub = base(r.process) in HUB_IMAGES
    guid, parent_guid, target_guid = val(r.process_guid), val(r.parent_guid), val(r.target_guid)
    if guid and not hub:
        keys.append(('proc', h, guid))
    if r.event_id == 1 and parent_guid and base(guid_image.get(parent_guid, r.parent)) not in HUB_IMAGES:
        keys.append(('proc', h, parent_guid))
    if r.event_id == 8 and str(r.provider).endswith('Sysmon') and target_guid:
        keys.append(('proc', h, target_guid))
    pid = to_int(r.exec_pid) if 'powershell' in str(r.provider).lower() else to_int(r.pid)
    if pid not in (None, 0, 4) and not hub:
        keys.append(('pid', h, pid))
    lid = to_int(r.logon_id)
    if lid is not None and lid not in SHARED_LOGONS:
        keys.append(('logon', h, lid))
    return h, keys


class DSU:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        self.p[self.find(a)] = self.find(b)


def group_events(m, guid_image, window, max_gap):
    """m: event độc hại (đã sắp theo thời gian) -> mảng mã cảnh báo."""
    n = len(m)
    dsu = DSU(n)
    hosts, first = [], {}
    for i, r in enumerate(m.itertuples(index=False)):
        h, keys = link_keys(r, guid_image)
        hosts.append(h)
        for k in keys:
            if k in first:
                dsu.union(i, first[k])
            else:
                first[k] = i
    # khung thời gian: event liên tiếp trên cùng máy cách nhau <= window giây
    t = m['t'].values
    last = {}
    for i, h in enumerate(hosts):
        j = last.get(h)
        if j is not None and (t[i] - t[j]) / np.timedelta64(1, 's') <= window:
            dsu.union(i, j)
        last[h] = i
    comp = np.array([dsu.find(i) for i in range(n)])
    # cắt nhóm khi có khoảng lặng > max_gap
    alert = np.empty(n, dtype=int)
    nid = 0
    for c in pd.unique(comp):
        idx = np.where(comp == c)[0]  # đã theo thời gian
        alert[idx[0]] = nid
        for a, b in zip(idx[:-1], idx[1:]):
            if (t[b] - t[a]) / np.timedelta64(1, 's') > max_gap:
                nid += 1
            alert[b] = nid
        nid += 1
    return alert, hosts


def describe(g):
    """Bảng event của 1 cảnh báo -> 1 dòng tóm tắt."""
    tac = g.drop_duplicates('tactic')['tactic'].tolist()  # theo thứ tự xuất hiện
    cnt = g['tactic'].value_counts()
    flags = collections.Counter(f for s in g['flags'].fillna('') for f in s.split())
    procs = collections.Counter(base(p) for p in g['process'] if base(p))
    users = sorted({str(u).split('\\')[-1] for u in g['user'].fillna('') if u and str(u) not in ('-', 'nan')})
    max_p = float(g['p_malicious'].max())
    crit = sorted(set(flags) & CRITICAL_FLAGS)
    if max_p >= 0.9 and (len(tac) >= 2 or crit):
        sev = 'high'
    elif max_p >= 0.8 or len(g) >= 3:
        sev = 'medium'
    else:
        sev = 'low'
    return dict(host=g['host'].iloc[0], start=g['t'].min(), end=g['t'].max(), n_events=len(g),
                n_processes=g['process_guid'].fillna(g['host'] + ':' + g['pid'].astype(str)).nunique(), max_p=round(max_p, 4),
                mean_p=round(float(g['p_malicious'].mean()), 4), severity=sev,
                tactic_chain=' → '.join(tac), tactics='; '.join(f'{k} ({v})' for k, v in cnt.items()),
                processes=', '.join(f'{k} ({v})' for k, v in procs.most_common(6)),
                users=', '.join(users[:5]), critical_flags=' '.join(crit),
                flags='; '.join(f'{k} ({v})' for k, v in flags.most_common(8)),
                files=', '.join(sorted(g['file'].astype(str).unique())[:5]))


def build_alerts(out, window=60, max_gap=1800):
    """out: bảng của predict.py -> (alerts, events của các cảnh báo)."""
    out = out.copy()
    out['t'] = pd.to_datetime(out['time'], utc=True, errors='coerce', format='ISO8601')
    out['t'] = out['t'].fillna(pd.Timestamp(0, tz='UTC'))
    guid_image = {val(g): p for g, p in zip(out['process_guid'], out['process']) if val(g) and val(p)}
    m = out[out['malicious'] == 1].sort_values('t', kind='stable').reset_index(drop=True)
    if m.empty:
        return pd.DataFrame(), m
    m['alert'], _ = group_events(m, guid_image, window, max_gap)
    rows = []
    for a, g in m.groupby('alert', sort=False):
        d = describe(g)
        if 'true_malicious' in g:
            tm = g['true_malicious']
            d.update(true_malicious_events=int((tm == 1).sum()), true_benign_events=int((tm == 0).sum()),
                     true_uncertain_events=int((tm == -1).sum()))
        rows.append(dict(alert=a, **d))
    al = pd.DataFrame(rows)
    al['_s'] = al['severity'].map(SEVERITY_ORDER)
    al = al.sort_values(['_s', 'max_p', 'n_events'], ascending=[True, False, False]).drop(columns='_s')
    newid = {a: f'A{i + 1:04d}' for i, a in enumerate(al['alert'])}
    al['alert'] = al['alert'].map(newid)
    m['alert'] = m['alert'].map(newid)
    return al.reset_index(drop=True), m


def alert_metrics(out, al, ev):
    """Chỉ số theo cảnh báo khi có nhãn (bỏ uncertain + ngoài phạm vi)."""
    lab = out[out['true_malicious'].isin([0, 1]) & (out['out_of_scope'] == 0)]
    n_true = int((lab['true_malicious'] == 1).sum())
    covered = int((ev['true_malicious'] == 1).sum())
    fp_alerts = al[(al['true_malicious_events'] == 0) & (al['true_benign_events'] > 0)]
    unk = al[(al['true_malicious_events'] == 0) & (al['true_benign_events'] == 0)]  # chỉ gồm event uncertain
    files_mal = set(lab.loc[lab['true_malicious'] == 1, 'file'])
    files_hit = set(ev.loc[ev['true_malicious'] == 1, 'file'])
    return dict(n_alerts=len(al), n_alert_events=len(ev), n_true_mal_events=n_true,
                event_recall=covered / max(n_true, 1),
                alert_precision=1 - len(fp_alerts) / max(len(al) - len(unk), 1), n_fp_alerts=len(fp_alerts),
                n_uncertain_alerts=len(unk),
                fp_by_severity=fp_alerts['severity'].value_counts().to_dict(),
                files_with_attack=len(files_mal), files_detected=len(files_mal & files_hit))


def fmt(al, ev, out, metrics, window, max_gap):
    L = ['# Cảnh báo\n',
         f'- {len(out):,} event đầu vào, {int(out.malicious.sum()):,} event bị báo độc hại → **{len(al)} cảnh báo**',
         f'- nối event: cùng cây process / PID / phiên đăng nhập trên cùng máy, hoặc cách nhau ≤ {window}s; '
         f'cắt khi lặng > {max_gap}s']
    if len(al):
        L.append('- mức độ: ' + ', '.join(f'{k} {v}' for k, v in al['severity'].value_counts()
                                           .reindex(list(SEVERITY_ORDER)).dropna().astype(int).items()))
    if metrics:
        mm = metrics
        L += ['\n## So với nhãn\n',
              f'- cảnh báo đúng (có ít nhất 1 event độc hại thật): '
              f'{mm["n_alerts"] - mm["n_fp_alerts"] - mm["n_uncertain_alerts"]}/{mm["n_alerts"] - mm["n_uncertain_alerts"]}'
              f' (precision theo cảnh báo {mm["alert_precision"]:.3f}); cảnh báo sai theo mức độ: {mm["fp_by_severity"]}'
              + (f'; {mm["n_uncertain_alerts"]} cảnh báo chỉ gồm event uncertain, không tính' if mm['n_uncertain_alerts']
                 else ''),
              f'- event độc hại thật nằm trong cảnh báo: {mm["event_recall"]:.3f} '
              f'({int(round(mm["event_recall"] * mm["n_true_mal_events"]))}/{mm["n_true_mal_events"]})',
              f'- file có tấn công được cảnh báo: {mm["files_detected"]}/{mm["files_with_attack"]}']
    L += ['\n## Danh sách\n', '| ID | Mức | Máy | Bắt đầu | Thời lượng | Event | Chuỗi tactic | Process chính | p max |',
          '|---|---|---|---|---|---|---|---|---|']
    for r in al.itertuples():
        dur = (r.end - r.start).total_seconds()
        L.append(f'| {r.alert} | {r.severity} | {r.host} | {r.start:%Y-%m-%d %H:%M:%S} | {dur:.0f}s | {r.n_events} | '
                 f'{r.tactic_chain} | {r.processes.split(",")[0]} | {r.max_p:.2f} |')
    L.append('\n## Chi tiết\n')
    for r in al.head(50).itertuples():
        g = ev[ev['alert'] == r.alert]
        L += [f'### {r.alert} · {r.severity} · {r.host}\n',
              f'- thời gian: {r.start:%Y-%m-%d %H:%M:%S} → {r.end:%H:%M:%S} UTC, {r.n_events} event, '
              f'{r.n_processes} process',
              f'- tactic: {r.tactics}',
              f'- process: {r.processes}' + (f'; user: {r.users}' if r.users else ''),
              f'- file log: {r.files}']
        if r.flags:
            L.append('- **vì sao báo:**')
            for item in r.flags.split('; '):
                k, n = item[:-1].rsplit(' (', 1)
                L.append(f'  - {FLAG_TEXT.get(k, k)} (`{k}`, {n} event)' + (' ⚠' if k in CRITICAL_FLAGS else ''))
        L += ['', '| Thời gian | Event | Process | p | Tactic | Command line |', '|---|---|---|---|---|---|']
        for e in g.sort_values('p_malicious', ascending=False).head(5).itertuples():
            cmd = str(e.command_line if isinstance(e.command_line, str) else '').replace('|', '\\|') \
                .replace('\n', ' ')[:100]
            L.append(f'| {e.t:%H:%M:%S} | {short_provider(e.provider)} {e.event_id} | {base(e.process)} | '
                     f'{e.p_malicious:.2f} | {e.tactic} | {cmd} |')
        L.append('')
    if len(al) > 50:
        L.append(f'_Còn {len(al) - 50} cảnh báo, xem alerts.csv._')
    return '\n'.join(L) + '\n'


def main():
    import predict
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    predict.add_args(ap, inputs_required=False)
    ap.add_argument('--predictions', help='dùng predictions.csv có sẵn thay vì chạy predict.py')
    ap.add_argument('--window', type=int, default=60, help='nối event cùng máy cách nhau <= N giây')
    ap.add_argument('--max-gap', type=int, default=1800, help='cắt cảnh báo khi lặng > N giây')
    a = ap.parse_args()
    if a.predictions:
        out, od = pd.read_csv(a.predictions, low_memory=False), os.path.dirname(os.path.abspath(a.predictions))
    elif a.inputs:
        out, od = predict.run(a)
    else:
        ap.error('cần đầu vào hoặc --predictions')
    if 'process_guid' not in out:
        sys.exit('predictions.csv thiếu cột khoá nối (process_guid, pid, logon_id...): chạy lại predict.py bản mới')

    al, ev = build_alerts(out, a.window, a.max_gap)
    has_labels = 'true_malicious' in out and out['true_malicious'].notna().any()
    metrics = alert_metrics(out, al, ev) if has_labels and len(al) else None
    rep = fmt(al, ev, out, metrics, a.window, a.max_gap)
    open(os.path.join(od, 'alerts.md'), 'w').write(rep)
    al.to_csv(os.path.join(od, 'alerts.csv'), index=False)
    cols = ['alert', 'time', 'host', 'file', 'provider', 'event_id', 'process', 'parent', 'target', 'user',
            'command_line', 'p_malicious', 'tactic', 'p_tactic', 'flags'] + \
           [c for c in ('true_label', 'true_malicious') if c in ev]
    ev[cols].to_csv(os.path.join(od, 'alert_events.csv'), index=False)
    print('\n' + rep.split('\n## Danh sách')[0])
    print(f'-> {od}/alerts.md, alerts.csv, alert_events.csv')


if __name__ == '__main__':
    main()
