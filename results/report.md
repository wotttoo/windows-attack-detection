# Kết quả train và đánh giá model

## 1. Tóm tắt

Trên các kịch bản model chưa thấy lúc train (đánh giá `cv`, gồm cả Mordor và EVTX):

- Model bắt được **94%** event tấn công (recall 0.942).
- Trong số event bị báo độc hại, **84%** là độc hại thật (precision 0.844); F1 **0.890**.
- **3.5%** event benign bị báo nhầm là độc hại.
- Đoán đúng tactic còn yếu: macro-F1 **0.353**. Tốt nhất ở command-and-control (0.85), lateral-movement (0.70), credential-access (0.63).
- Trên file EVTX chưa thấy (đánh giá `mix`): recall 0.826, precision 0.669, F1 0.739, báo nhầm 4.0%.

## 2. Dữ liệu

`data/processed/events.parquet`, tạo bởi `src/build_dataset.py`. Một **dòng** là một event sau khử trùng; cột `n_dup` ghi số **event** gốc giống hệt nhau mà dòng đó đại diện. **Group** là một kịch bản Mordor hoặc một file EVTX.

| Bộ | Group | Dòng | Event | Event độc hại | Event benign |
|---|---|---|---|---|---|
| Mordor | 99 | 103,797 | 521,550 | 89,771 | 431,779 |
| EVTX | 274 | 3,645 | 35,325 | 3,123 | 32,202 |
| **Tổng** | 373 | 107,442 | 556,875 | 92,894 | 463,981 |

Event độc hại theo tactic:

| Tactic | Group có tactic | Dòng | Event |
|---|---|---|---|
| command-and-control | 61 | 3,774 | 25,020 |
| credential-access | 59 | 4,403 | 42,890 |
| defense-evasion | 65 | 2,105 | 11,544 |
| discovery | 22 | 995 | 1,474 |
| execution | 45 | 309 | 475 |
| lateral-movement | 74 | 4,883 | 9,423 |
| persistence | 32 | 372 | 620 |
| privilege-escalation | 69 | 941 | 1,448 |

## 3. Model

- Feature: nhóm hành vi và cờ hành vi (`behavior.py`), one-hot các cột phân loại, TF-IDF đoạn ký tự (3–5 ký tự) cho command line / PowerShell / đường dẫn, các cột số.
- Logistic Regression 2 bước:
  1. **binary**: event độc hại hay benign (báo độc hại khi xác suất ≥ 0.5);
  2. **tactic**: với event độc hại, đoán 1 trong 8 tactic.
- Trọng số mẫu `min(n_dup, 10)`, rồi cân bằng để tổng trọng số mỗi lớp bằng nhau.
- Tham số cố định (`C=4.0`, ngưỡng 0.5), không dò trên tập test.

## 4. Cách đánh giá

Không có tập test cố định. Dữ liệu được chia xoay vòng 5 lần; mỗi lần train trên một phần, test trên phần còn lại. Một group luôn nằm trọn ở train hoặc test, nên lúc test model chưa thấy kịch bản / file đó. Kết quả test của 5 lần được gộp lại thành các bảng dưới.

| Đánh giá | Train mỗi lần | Test mỗi lần | Sau 5 lần đã test | Trả lời câu hỏi |
|---|---|---|---|---|
| `cv` | 4/5 số group (cả hai bộ) | 1/5 group còn lại | mọi group của cả hai bộ | phát hiện tấn công trong kịch bản mới, cùng môi trường |
| `mix` | toàn bộ Mordor + 4/5 file EVTX | 1/5 file EVTX còn lại | mọi file EVTX | phát hiện trên file EVTX chưa thấy khi train gồm cả hai bộ |

**Model cuối** (`models/binary.joblib`, `models/tactic.joblib`) được train trên toàn bộ dữ liệu; độ chính xác của nó được ước lượng bằng các số `cv` / `mix` ở đây.

Đánh giá **cảnh báo** (gộp event thành cảnh báo bằng `alert.py`) trên 75 group của lần 1 trong `cv`: xem `results/predict/holdout_cv_fold1/`.

## 5. Cách đọc chỉ số

| Chỉ số | Ý nghĩa |
|---|---|
| Precision | trong các event bị báo độc hại, bao nhiêu phần là độc hại thật |
| Recall | trong các event độc hại thật, bao nhiêu phần bị báo |
| F1 | trung bình điều hoà của precision và recall |
| PR-AUC | chất lượng xếp hạng theo xác suất độc hại, không phụ thuộc ngưỡng 0.5 (1 là tốt nhất) |
| Báo nhầm | tỉ lệ event benign bị báo độc hại |
| Macro-F1 tactic | trung bình F1 của các tactic, mỗi tactic nặng như nhau; tính trên mọi event độc hại thật, không phụ thuộc bước binary có báo event đó hay không |

Các bảng chính tính **theo event** (mỗi dòng nhân với `n_dup`). Bảng theo dòng nằm ở phụ lục.

## 6. Phát hiện độc hại / benign

| Phần dữ liệu test | Event độc hại | Precision | Recall | F1 | PR-AUC | Báo nhầm |
|---|---|---|---|---|---|---|
| **cv: kịch bản chưa thấy (cả hai bộ)** | 92,894 | 0.844 | 0.942 | 0.890 | 0.945 | 3.50% |
| &nbsp;&nbsp;↳ phần Mordor (99 group) | 89,771 | 0.851 | 0.946 | 0.896 | 0.949 | 3.44% |
| &nbsp;&nbsp;↳ phần EVTX (274 group) | 3,123 | 0.650 | 0.812 | 0.722 | 0.822 | 4.24% |
| **mix: file EVTX chưa thấy** | 3,123 | 0.669 | 0.826 | 0.739 | 0.832 | 3.97% |

`cv` gồm phần lớn là event Mordor, nên số tổng của `cv` gần với số của phần Mordor.

## 7. Đoán tactic

F1 của từng tactic (theo event). Cột "Event" là số event độc hại thật của tactic đó trong phần test.

| Tactic | F1 cv | Event cv | F1 mix | Event mix |
|---|---|---|---|---|
| command-and-control | 0.854 | 25,020 | 0.076 | 216 |
| credential-access | 0.629 | 42,890 | 0.230 | 256 |
| defense-evasion | 0.088 | 11,544 | 0.181 | 332 |
| discovery | 0.061 | 1,474 | 0.056 | 137 |
| execution | 0.085 | 475 | 0.293 | 166 |
| lateral-movement | 0.696 | 9,423 | 0.569 | 1,250 |
| persistence | 0.213 | 620 | 0.302 | 262 |
| privilege-escalation | 0.201 | 1,448 | 0.565 | 504 |
| **macro-F1** | **0.353** |  | **0.284** |  |

## 8. Group có nhiều event báo nhầm nhất

Số trong ngoặc là số event benign của group đó bị báo độc hại.

- **cv:** `mordor:purplesharp_ad_playbook_I` (4,304), `mordor:proxylogon_ssrf_rce_poc` (3,533), `mordor:empire_persistence_registry_modification_run_keys_standard_user` (1,956), `evtx:bits_openvpn` (1,172), `mordor:empire_scm_dll_hijack_ikeext` (1,130)
- **mix:** `evtx:bits_openvpn` (1,119), `evtx:persistence_sysmon_11_13_1_shime_appfix` (93), `evtx:execution_evasion_visual_studio_prebuild_event` (13), `evtx:sysmon_13_1_persistence_via_winlogon_shell` (9), `evtx:privesc_unquoted_svc_sysmon_1_11` (7)

## 9. Feature quan trọng nhất của model cuối

Các feature có hệ số dương lớn nhất trong Logistic Regression, tức là đẩy dự đoán về phía độc hại (binary) hoặc về phía tactic đó. Cách đọc tên feature:

| Dạng tên | Ý nghĩa |
|---|---|
| `cat__<cột>_<giá trị>` | cột phân loại mang giá trị đó, ví dụ `cat__event_id_4688` = event Security 4688, `cat__img_class_office` = process thuộc nhóm Office (nhóm do behavior.py đặt) |
| `num__<tên>` | feature số / cờ hành vi, ví dụ `num__f_encoded` = có lệnh mã hoá base64 |
| `t_proc__<chuỗi>` | đoạn ký tự 3–5 ký tự trong command line (của process và process cha) |
| `t_ps__<chuỗi>` | đoạn ký tự trong nội dung PowerShell |
| `t_obj__<chuỗi>` | đoạn ký tự trong đường dẫn file / registry / DLL / pipe / share / service / DNS |

**binary:** `cat__img_class_office`, `cat__provider_RemoteDesktopServices-RdpCoreTS`, `t_obj__\run`, `cat__event_id_4688`, `t_obj__\ru`, `cat__img_class_browser`, `cat__event_id_4826`, `cat__provider_PowerShell`, `cat__granted_access_n_0x101400`, `cat__img_loc_temp`, `cat__granted_access_n_0x1014c0`, `cat__event_id_2011`, `t_obj__\star`, `t_obj__.png `, `t_obj__png `

**tactic:command-and-control:** `cat__event_id_12`, `cat__protocol_udp`, `cat__provider_TerminalServices-RemoteConnectionManager`, `cat__port_class_web`, `cat__registry_event_`, `num__f_download`, `cat__event_id_6`, `cat__img_loc_user_profile`, `cat__img_class_sensitive`, `cat__port_class_rdp`, `t_ps__e="by`, `t_ps__"by`, `t_ps__"byte`, `t_ps__="byt`, `t_ps__="by`

**tactic:credential-access:** `num__k_appinit_lsa`, `t_ps__m.obj`, `t_ps__m.ob`, `t_ps__m.o`, `t_ps__em.ob`, `t_ps__em.o`, `t_ps__tem.o`, `cat__img_class_compiler`, `t_ps__.obje`, `t_ps__.obj`, `t_ps__.ob`, `num__f_cred_dump_file`, `cat__port_class_kerberos`, `cat__granted_access_n_0x1400`, `cat__event_id_18456`

**tactic:defense-evasion:** `cat__event_id_4826`, `cat__user_type_admin`, `cat__event_id_4985`, `cat__event_id_4720`, `t_ps__comob`, `t_ps__como`, `t_ps__omobj`, `t_ps__omob`, `t_ps__mobj`, `t_ps__mob`, `t_ps__mobje`, `t_ps__omo`, `t_ps__.__co`, `t_ps__em.__`, `t_ps__em._`

**tactic:discovery:** `cat__img_class_kernel`, `cat__event_id_4799`, `cat__img_loc_other`, `t_obj__ d:`, `cat__access_mask_n_0x12019f`, `cat__img_loc_user_profile`, `t_ps__---`, `t_ps__----`, `t_ps__-----`, `cat__img_class_admin_tool`, `cat__port_class_ldap`, `t_obj__d: `, `cat__target_class_admin_tool`, `t_proc__user `, `t_proc__ser `

**tactic:execution:** `cat__img_loc_programdata`, `cat__port_class_other_high`, `t_obj__r>/ap`, `t_obj__er>/a`, `t_obj__r>/a`, `cat__img_class_script_host`, `t_obj__m.m`, `num__f_shadow_copy`, `num__k_services`, `cat__event_id_2`, `cat__event_id_4690`, `cat__target_class_lolbin`, `t_proc__exec`, `cat__parent_class_shell_ui`, `t_proc__xec`

**tactic:lateral-movement:** `cat__img_class_remote_host`, `cat__img_class_office`, `cat__img_loc_temp`, `cat__access_mask_n_0x100081`, `cat__img_class_browser`, `t_obj__run`, `cat__registry_event_createkey`, `cat__pc_pair_shell_ui>shell`, `cat__port_class_winrm`, `cat__event_id_5145`, `cat__event_id_4648`, `num__f_hidden_ps`, `cat__granted_access_n_0x40`, `cat__event_id_4658`, `cat__img_loc_program_files`

**tactic:persistence:** `num__f_wmi_sub`, `t_obj__tmp`, `num__cmd_entropy`, `cat__granted_access_n_0x1014c0`, `t_proc__ /r`, `t_obj__>.<d`, `t_obj__>.<do`, `t_obj__mp1`, `cat__port_class_web`, `num__f_iex`, `t_obj__1.p`, `t_obj__.<dom`, `t_obj__.<d`, `t_obj__.<do`, `t_proc__aus`

**tactic:privilege-escalation:** `cat__img_class_uac_autoelevate`, `cat__port_class_other_low`, `cat__target_class_uac_autoelevate`, `cat__pc_pair_svc_host>admin_tool`, `cat__user_type_machine`, `num__f_service_cfg`, `t_obj__t\s`, `cat__port_class_smb`, `cat__event_id_4105`, `t_obj__dhc`, `t_obj__ives`, `t_obj__ves`, `cat__parent_class_uac_autoelevate`, `t_proc__.ms`, `t_obj__/te`

## Phụ lục: chỉ số theo dòng (sau khử trùng, không nhân `n_dup`)

| Đánh giá | PR-AUC | ROC-AUC | Precision | Recall | F1 | Tactic macro-F1 |
|---|---|---|---|---|---|---|
| cv | 0.936 | 0.981 | 0.836 | 0.902 | 0.868 | 0.396 |
| mix | 0.944 | 0.908 | 0.878 | 0.857 | 0.867 | 0.287 |
