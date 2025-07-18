# 상단 공통 import
import streamlit as st
import olefile
import zlib
import re
import os
from io import BytesIO
from datetime import datetime

# --------- 내부 함수 정의 ---------
def extract_streams_ole(file_obj):
    if not olefile.isOleFile(file_obj):
        st.error("유효한 HWP(OLE) 파일이 아닙니다.")
        return []
    ole = olefile.OleFileIO(file_obj)
    stream_data = []
    for stream_name in ole.listdir():
        try:
            data = ole.openstream(stream_name).read()
            stream_data.append( ("/".join(stream_name), data) )
        except:
            continue
    return stream_data

def try_decompress(data):
    offsets = [i for i in range(len(data)-2) if data[i:i+2] in [b'\x78\x9c', b'\x78\x01', b'\x78\xda']]
    for offset in offsets:
        try:
            return zlib.decompress(data[offset:])
        except:
            continue
    return None

def extract_strings(data, min_length=6):
    pattern = rb"[ -~]{%d,}" % min_length
    found = re.findall(pattern, data)
    return [s.decode('utf-8', errors='ignore') for s in found if len(s.strip()) >= min_length]

def normalize(s):
    return s.strip().replace(" ", "").replace("\t", "").replace("\n", "").lower()

def is_noise(s):
    return not re.search(r'[a-zA-Z]{3,}', s) or re.search(r'[^a-zA-Z0-9 _\-.:/\\]', s)

def filter_malicious_strings(strings, safe_strings):
    filtered = []
    for s in strings:
        norm = normalize(s)
        if norm not in safe_strings and len(norm) >= 6 and not is_noise(s):
            filtered.append(s)
    return filtered

def generate_yara_rule(strings, rule_name="AutoRule_HWP", author="auto", max_strings=10):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rule = f"rule {rule_name}_{timestamp} {{\n"
    rule += "    meta:\n"
    rule += f'        author = "{author}"\n'
    rule += f'        date = "{timestamp}"\n'
    rule += "    strings:\n"
    for idx, s in enumerate(strings[:max_strings]):
        safe = s.replace("\\", "\\\\").replace('"', '\\"')
        rule += f'        $s{idx} = "{safe}"\n'
    rule += "    condition:\n        any of them\n}"
    return rule

def load_safe_strings():
    path = "safe_strings.txt"
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(normalize(line) for line in f if line.strip())

def save_safe_strings_to_file(strings):
    path = "safe_strings.txt"
    existing = load_safe_strings()
    combined = existing.union(normalize(s) for s in strings)
    with open(path, "w", encoding="utf-8") as f:
        for s in sorted(combined):
            f.write(s + "\n")
    return len(combined)

# --------- UI 초기화 ---------
st.title("📄 HWP 악성코드 분석 및 YARA 룰 생성기")
st.warning("⚠️ 이 프로그램은 HWP(OLE 방식)만 지원합니다. HWP 파일을 업로드해 주세요.")

# --------- 세션 상태 초기화 ---------
for key, default in {
    'normal_files': [],
    'normal_string_counts': {},
    'malicious_file': None,
    'malicious_file_list': [],
    'malicious_results': {}
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# --------- 모드 선택 ---------
mode = st.radio("모드를 선택하세요:", ["정상 샘플 등록", "악성 샘플 분석"])

# --------- 정상 샘플 등록 ---------
if mode == "정상 샘플 등록":
    uploaded_files = st.file_uploader(
        "정상 HWP 파일 업로드 (드래그 앤 드롭 지원)",
        type=['hwp'],
        accept_multiple_files=True
    )

    if uploaded_files:
        if not isinstance(uploaded_files, list):
            uploaded_files = [uploaded_files]

        duplicated = []
        new_file_processed = False
        all_strings = set()

        for file in uploaded_files:
            if file.name in st.session_state['normal_files']:
                duplicated.append(file.name)
                continue

            streams = extract_streams_ole(file)
            file_strings = set()
            for name, raw in streams:
                decompressed = try_decompress(raw)
                data = decompressed or raw
                strings = extract_strings(data)
                file_strings.update(strings)

            if file_strings:
                st.session_state['normal_files'].append(file.name)
                st.session_state['normal_string_counts'][file.name] = len(file_strings)
                all_strings.update(file_strings)
                new_file_processed = True
                st.success(f"✅ 분석 완료: {file.name} (정상 문자열 {len(file_strings)}개)")
            else:
                st.warning(f"❌ 문자열을 추출하지 못함: {file.name}")

        if not new_file_processed and duplicated:
            st.warning("⚠️ 중복된 파일이 포함되어 있습니다. 업로드 목록을 확인해 주세요.")

        if all_strings:
            total = save_safe_strings_to_file(all_strings)
            st.info(f"🔒 누적 정상 문자열 총 {total}개 (이번 등록: {len(all_strings)}개)")

    if st.session_state['normal_files']:
        st.markdown("### ✅ 등록된 정상 샘플 목록")
        for name in st.session_state['normal_files']:
            count = st.session_state['normal_string_counts'].get(name, '?')
            st.write(f"- {name} (정상 문자열 {count}개)")

        if st.button("🗑️ 전체 초기화 (업로드 목록 + 문자열 파일 삭제)"):
            st.session_state['normal_files'] = []
            st.session_state['normal_string_counts'] = {}
            if os.path.exists("safe_strings.txt"):
                os.remove("safe_strings.txt")
            st.success("✅ 전체 초기화 완료: 문자열 파일과 업로드 목록이 모두 삭제되었습니다. 새로고침 해주세요.")

# --------- 악성 샘플 분석 ---------
elif mode == "악성 샘플 분석":
    uploaded_file = st.file_uploader(
        "분석할 HWP 악성 샘플 업로드 (드래그 앤 드롭 지원)",
        type=['hwp'],
        accept_multiple_files=False
    )

    safe_strings = load_safe_strings()
    if not safe_strings:
        st.warning("⚠️ 현재 등록된 정상 문자열 필터가 없습니다. 모든 문자열이 탐지될 수 있으며, 분석 정확도가 낮아질 수 있습니다.")

    if uploaded_file:
        name = uploaded_file.name
        st.session_state['malicious_file'] = name
        if name not in st.session_state['malicious_file_list']:
            st.session_state['malicious_file_list'].append(name)

        streams = extract_streams_ole(uploaded_file)
        found = False
        results = []

        for idx, (stream_name, raw) in enumerate(streams):
            decompressed = try_decompress(raw)
            data = decompressed or raw
            strings = extract_strings(data)
            filtered = filter_malicious_strings(strings, safe_strings)

            if filtered:
                found = True
                yara_rule = generate_yara_rule(filtered)
                results.append({
                    'stream': stream_name,
                    'strings': filtered,
                    'yara': yara_rule
                })

        st.success(f"✅ 분석 완료: {name}")
        st.session_state['malicious_results'][name] = results if found else []

    if st.session_state['malicious_file_list']:
        selected = st.selectbox("📁 이전 분석한 악성 파일 선택", st.session_state['malicious_file_list'])

        if selected in st.session_state['malicious_results']:
            result = st.session_state['malicious_results'][selected]
            if not result:
                st.info("⚪ 탐지된 의심 문자열이 없습니다.")
            else:
                st.markdown(f"### 🚨 탐지 결과: {selected}")
                for idx, entry in enumerate(result):
                    st.subheader(f"스트림 {idx+1}: {entry['stream']}")
                    st.code("\n".join(entry['strings']), language='text')
                    st.code(entry['yara'], language="text")
                    st.download_button(
                        f"YARA 룰 다운로드: {entry['stream'].replace('/', '_')}.yar",
                        entry['yara'],
                        file_name=f"{selected}_{entry['stream'].replace('/', '_')}.yar",
                        mime="text/plain"
                    )
