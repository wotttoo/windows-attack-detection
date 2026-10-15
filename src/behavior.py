"""Feature hành vi cho events.parquet (dùng bởi train.py và predict.py).

Ý tưởng: thay danh tính (tên process, cổng cụ thể, đường dẫn của lab) bằng thuộc tính
mà công cụ chưa từng thấy cũng có: loại binary, vị trí chạy, quan hệ cha→con,
nhóm hành động trong command line / PowerShell, loại đối tượng bị tác động.

    import behavior
    df = behavior.add(df)          # thêm cột BEH_CAT (phân loại) + BEH_FLAGS (0/1)
    behavior.mask_text(df, cols)   # che tên .exe, volume, syswow64 trong văn bản
"""

import re
import warnings

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- loại binary
_CLASSES = {
    'shell': 'cmd powershell pwsh powershell_ise',
    'script_host': 'wscript cscript mshta',
    'lolbin': 'rundll32 regsvr32 msbuild installutil cmstp certutil bitsadmin wmic hh control mavinject esentutl '
              'msiexec regasm regsvcs odbcconf forfiles sdbinst appcmd register-cimprovider ieinstal ielowutil '
              'msdt pcalua infdefaultinstall msxsl xwizard wuauclt makecab expand extrac32 diskshadow ntdsutil '
              'appvdllsurrogate64 mmc dnscmd wusa',
    'admin_tool': 'sc reg schtasks at net net1 netsh whoami tasklist taskkill nltest ipconfig systeminfo wevtutil '
                  'vssadmin shutdown ping quser query qwinsta arp netstat route nslookup dsquery hostname '
                  'auditpol bcdedit fltmc attrib icacls takeown wbadmin cipher findstr',
    'remote_host': 'wmiprvse wsmprovhost scrcons psexesvc winrshost',
    'com_host': 'dllhost',
    'office': 'excel winword powerpnt outlook msaccess mspub onenote',
    'browser': 'iexplore chrome firefox msedge opera',
    'uac_autoelevate': 'consent fodhelper eventvwr sdclt computerdefaults slui changepk wsreset',
    'sensitive': 'lsass winlogon csrss smss wininit services spoolsv',
    'svc_host': 'svchost taskhostw taskhost runtimebroker sihost backgroundtaskhost wmiadap searchindexer '
                'searchprotocolhost',
    'compiler': 'csc cvtres vbc jsc ilasm',
    'interpreter': 'python pythonw java javaw node perl ruby',
    'shell_ui': 'explorer userinit logonui',
}
_IMG2CLASS = {f'{n}.exe': c for c, names in _CLASSES.items() for n in names.split()}


def _loc(path):
    p = str(path).replace('\\', '/')
    if not p:
        return 'none'
    if '/syswow64' in p or '/system32' in p:
        return 'system_dir'
    if re.search(r'/users/[^/]+/(appdata/local/temp|downloads)|/windows/temp|/temp(/|$)', p):
        return 'temp'
    if '/users/' in p:
        return 'user_profile'
    if '/programdata' in p:
        return 'programdata'
    if '/program files' in p or '/windowsapps' in p:
        return 'program_files'
    if p.startswith('//') or p.startswith('\\\\'):
        return 'network_share'
    if '/windows' in p:
        return 'windows_dir'
    return 'other'


def img_class(image, path=''):
    image = str(image)
    if image in ('', '-', '?', 'nan'):
        return 'none'
    image = re.sub(r'^\[\d+\]', '', image)
    if image in _IMG2CLASS:
        return _IMG2CLASS[image]
    if image == 'system':
        return 'kernel'
    loc = _loc(path)
    return 'unknown_' + ('system' if loc in ('system_dir', 'windows_dir') else 'program' if loc == 'program_files'
                         else 'userland' if loc in ('temp', 'user_profile', 'programdata', 'network_share')
                         else 'nopath')


def port_class(p):
    p = int(p)
    if p < 0:
        return 'none'
    for name, ports in (('web', {80, 443, 8080, 8443, 8000, 8888}), ('smb', {445, 139}), ('rpc', {135}),
                        ('winrm', {5985, 5986}), ('rdp', {3389}), ('ldap', {389, 636, 3268, 3269}),
                        ('kerberos', {88, 464}), ('dns', {53, 5353, 5355}), ('netbios', {137, 138}),
                        ('adws', {9389}), ('mssql', {1433}), ('smtp', {25, 587})):
        if p in ports:
            return name
    return 'ephemeral' if p >= 49152 else 'other_low' if p < 1024 else 'other_high'


def _hexnorm(v):
    v = str(v).strip()
    m = re.fullmatch(r'0x0*([0-9a-f]+)', v)
    return '0x' + m.group(1) if m else ('%%' if v.startswith('%%') else v)


# ---------------------------------------------------------------- cờ hành vi (regex trên văn bản)
_FLAGS = {
    # thực thi / tải về / làm rối
    'f_download': ('cmd ps', r'https?://|downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|'
                             r'net\.webclient|start-bitstransfer|/transfer|urlcache|msxml2\.xmlhttp|winhttp'),
    'f_encoded': ('cmd ps', r'\s-e(nc|ncodedcommand)?\s|frombase64string|\[convert\]::'),
    'f_hidden_ps': ('cmd', r'-w(indowstyle)?\s+h|-nop\b|-noprofile|-noni|-exec(utionpolicy)?\s+bypass|-ep\s+bypass'),
    'f_iex': ('cmd ps', r'\biex\b|invoke-expression'),
    'f_reflection': ('ps', r'reflection\.assembly|::load\(|virtualalloc|getdelegateforfunctionpointer|'
                           r'createthread|writeprocessmemory|marshal\]::'),
    'f_amsi_bypass': ('ps cmd', r'amsiutils|amsiinitfailed|amsiscanbuffer'),
    'f_script_proto': ('cmd', r'javascript:|vbscript:|scrobj|\.sct\b|getobject\('),
    'f_dotnet_inline': ('cmd ps', r'add-type|csc\b.*\.cs\b|/target:|codedom'),
    # persistence / cấu hình hệ thống
    'f_service_cfg': ('cmd ps', r'\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config|start)|new-service|binpath'),
    'f_schtask': ('cmd ps', r'schtasks(\.exe)?\s+/create|register-scheduledtask|new-scheduledtask|\bat\s+\\\\'),
    'f_reg_write': ('cmd ps', r'\breg(\.exe)?\s+(add|import|load)|set-itemproperty|new-itemproperty|'
                              r'regwrite|setstringvalue|setdwordvalue'),
    'f_wmi_sub': ('cmd ps obj', r'__eventfilter|commandlineeventconsumer|activescripteventconsumer|'
                                r'__filtertoconsumerbinding|wmibindingevent|wmiconsumerevent'),
    'f_user_mgmt': ('cmd ps', r'net1?\s+(user|localgroup|group)\s+\S+.*\s/(add|del)|new-localuser|add-localgroupmember'),
    # truy cập thông tin xác thực
    'f_cred_tool': ('cmd ps', r'sekurlsa|lsadump|kerberos::|mimikatz|invoke-mimikatz|dcsync|krbtgt|'
                              r'logonpasswords|asktgt|kerberoast|getuserspns|\bpth\b'),
    'f_cred_dump_file': ('cmd ps obj', r'ntds\.dit|\\sam\b|\\security\b|\\system\b.*save|comsvcs.*minidump|'
                                       r'procdump|\.dmp\b|lsass'),
    'f_cred_store': ('cmd ps obj', r'promptforcredential|credentialmanager|vaultcmd|\.kdbx|login data|'
                                   r'cookies|\\credentials\\|\\protect\\'),
    'f_shadow_copy': ('cmd ps obj', r'vssadmin|shadowcopy|harddiskvolumeshadowcopy|win32_shadowcopy|/vss'),
    # khám phá
    'f_discovery_cmd': ('cmd ps', r'\bwhoami\b|\bnet1?(\.exe)?\s+(user|group|localgroup|view|share|session|accounts|'
                                  r'config|use)\b|nltest|systeminfo|ipconfig|tasklist|\bquser\b|query\s+user|'
                                  r'qwinsta|\barp\s+-a|netstat|route\s+print|dsquery|\bget-(ad|net|domain)\w*|'
                                  r'get-wmiobject|\bgwmi\b|get-ciminstance|reg(\.exe)?\s+query|'
                                  r'get-process|get-service|nslookup|sharpview|seatbelt|bloodhound|sharphound'),
    'f_sam_enum': ('obj', r'sam_domain|sam_group|sam_user|\\samr\b|lsarpc'),
    # thực thi từ xa / di chuyển ngang
    'f_remote_target': ('cmd ps', r'/node:|\\\\<host>|\\\\<ip>|-computername|invoke-command|enter-pssession|'
                                  r'new-pssession|\bwinrs\b|psexec|invoke-wmimethod|\[activator\]::'
                                  r'createinstance|gettypefromprogid|mmc20\.application|shellwindows|'
                                  r'shellbrowserwindow|excel\.application'),
    'f_admin_share': ('obj cmd', r'\\admin\$|\\c\$|\\ipc\$'),
    'f_rpc_pipe': ('obj', r'svcctl|atsvc|winreg|lsarpc|samr|psexesvc|remcom|\\srvsvc|epmapper|efsrpc|lsass'),
    # che giấu dấu vết / vô hiệu bảo vệ
    'f_log_tamper': ('cmd ps', r'wevtutil\s+cl|clear-eventlog|remove-eventlog|auditpol\s+/(set|clear)|'
                               r'limit-eventlog'),
    'f_av_tamper': ('cmd ps obj', r'set-mppreference|add-mppreference|disablerealtime|exclusionpath|'
                                  r'windows defender\\|tamperprotection|advfirewall|netsh\s+firewall|fltmc'),
    'f_hide_file': ('cmd ps', r'attrib\s+\+h|attrib\s+\+s|-attributes\s+hidden|:\w+:\$data|\bmklink\b'),
    'f_proc_inject': ('ps cmd', r'mavinject|/injectrunning|createremotethread|ntqueueapcthread|setthreadcontext'),
    # đối tượng registry
    'k_run': ('obj', r'\\currentversion\\(run|runonce|runservices|policies\\explorer\\run)\b'),
    'k_services': ('obj', r'\\currentcontrolset\\services\\'),
    'k_winlogon': ('obj', r'\\winlogon\\(userinit|shell|notify)|\\winlogon\b'),
    'k_ifeo': ('obj', r'image file execution options|silentprocessexit'),
    'k_com_hijack': ('obj', r'\\clsid\\|inprocserver32|localserver32|treatas|scriptlet'),
    'k_uac_bypass': ('obj', r'ms-settings\\shell|mscfile\\shell|exefile\\shell|folder\\shell|'
                            r'\\shell\\open\\command|delegateexecute|app paths\\control\.exe'),
    'k_appinit_lsa': ('obj', r'appinit_dlls|\\control\\lsa\\|security packages|authentication packages|'
                             r'notification packages|\\print\\monitors|netsh\\'),
    'k_startup_dir': ('obj', r'\\start menu\\programs\\startup|/start menu/programs/startup'),
    'k_task_dir': ('obj', r'\\windows\\system32\\tasks\\|\\taskcache\\'),
    # file
    'f_drop_exec': ('file', r'\.(exe|dll|ps1|bat|cmd|vbs|js|hta|sct|xll|lnk|scr|msi|cpl|sys|inf)\b'),
    'f_lnk_or_doc': ('file', r'\.(docm|xlsm|xls|doc|iqy|slk|one)\b'),
}
_COMPILED = {k: (src.split(), re.compile(rx)) for k, (src, rx) in _FLAGS.items()}

BEH_CAT = ['img_class', 'parent_class', 'target_class', 'pc_pair', 'img_loc', 'port_class',
           'granted_access_n', 'access_mask_n']
BEH_FLAGS = list(_FLAGS) + ['b_user_writable', 'b_renamed', 'b_unsigned_module', 'b_public_dst',
                            'b_lsass_target', 'b_full_access', 'b_vm_read', 'b_child_of_office',
                            'b_child_of_remote', 'b_shell_child_of_script']

_TXT = {
    'cmd': ['cmdline', 'parent_cmdline', 'ps_host_app'],
    'ps': ['ps_text'],
    'file': ['file_path'],
    'obj': ['registry', 'file_path', 'module_path', 'pipe', 'share', 'object_name', 'service', 'other_text'],
}


def add(df):
    """Thêm cột BEH_CAT + BEH_FLAGS. Phải gọi trước mask_text (cần tên .exe gốc)."""
    df = df.copy()
    df['img_class'] = [img_class(i, p) for i, p in zip(df['image'], df['image_path'])]
    df['parent_class'] = [img_class(i) for i in df['parent_image']]
    df['target_class'] = [img_class(i) for i in df['target_image']]
    df['pc_pair'] = np.where(df['parent_class'] == 'none', 'none', df['parent_class'] + '>' + df['img_class'])
    df['img_loc'] = df['image_path'].map(_loc)
    df['port_class'] = df['dst_port'].map(port_class)
    df['granted_access_n'] = df['granted_access'].map(_hexnorm)
    df['access_mask_n'] = df['access_mask'].map(_hexnorm)

    text = {k: df[cols].astype(str).agg(' '.join, axis=1).str.lower() for k, cols in _TXT.items()}
    for name, (srcs, rx) in _COMPILED.items():
        s = text[srcs[0]]
        for extra in srcs[1:]:
            s = s + ' ' + text[extra]
        with warnings.catch_warnings():  # regex có nhóm (...) -> pandas cảnh báo, vô hại
            warnings.simplefilter('ignore', UserWarning)
            df[name] = s.str.contains(rx).astype(np.int8)

    # FileNameOriginal (PE header) khác tên file trên đĩa -> binary bị đổi tên
    stem = lambda s: s.str.lower().str.replace(r'\.(exe|c|mui)$', '', regex=True)
    orig = stem(df['other_text'].astype(str).str.extract(r'filenameoriginal=(\S+)', flags=re.I)[0])
    df['b_renamed'] = ((df['event_id'] == 1) & orig.notna() & (df['image'] != '') & (orig != stem(df['image']))
                       & ~orig.isin(['-', '?', ''])).astype(np.int8)
    df['b_user_writable'] = df['img_loc'].isin(['temp', 'user_profile', 'programdata', 'network_share']).astype(np.int8)
    df['b_unsigned_module'] = (df['module_signed'] == 'false').astype(np.int8)
    df['b_public_dst'] = (df['dst_ip_type'] == 'public').astype(np.int8)
    df['b_lsass_target'] = (df['target_image'] == 'lsass.exe').astype(np.int8)
    ga = df['granted_access_n'].map(lambda v: int(v, 16) if re.fullmatch(r'0x[0-9a-f]+', v) else 0)
    df['b_full_access'] = (ga & 0x1f0fff == 0x1f0fff).astype(np.int8)
    df['b_vm_read'] = ((ga & 0x10) > 0).astype(np.int8)
    df['b_child_of_office'] = (df['parent_class'] == 'office').astype(np.int8)
    df['b_child_of_remote'] = df['parent_class'].isin(['remote_host', 'com_host']).astype(np.int8)
    df['b_shell_child_of_script'] = (df['parent_class'].isin(['script_host', 'office', 'browser'])
                                     & df['img_class'].isin(['shell', 'script_host', 'lolbin'])).astype(np.int8)
    return df


_MASKS = [
    (r'[^\s\\/"\'|=,;:()<>]+\.exe\b', '<exe>'),          # tên file .exe
    (r'harddiskvolume\d+', 'harddiskvolume'),             # số volume của từng máy lab
    (r'syswow64', 'system32'),                            # 32/64 bit
]  # số >= 4 chữ số (gồm cổng động) đã thành <num> ở build_dataset


def mask_text(df, cols):
    for c in cols:
        s = df[c].astype(str)
        for rx, rep in _MASKS:
            s = s.str.replace(rx, rep, regex=True)
        df[c] = s
    return df
