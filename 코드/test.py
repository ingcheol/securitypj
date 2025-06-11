import olefile
import zlib
import re
import os
import sys
from datetime import datetime

def extract_streams_ole(file_path):
    if not olefile.isOleFile(file_path):
        print(f"[!] 유효한 HWP(OLE) 파일이 아님: {file_path}")
        return []
    ole = olefile.OleFileIO(file_path)
    stream_data = []
    for stream_name in ole.listdir():
        try:
            data = ole.openstream(stream_name).read()
            stream_data.append(("/".join(stream_name), data))
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
    rule += "    condition:\n"
    rule += "        any of them\n"
    rule += "}\n"
    return rule

def is_noise(s):
    return not re.search(r'[a-zA-Z]{3,}', s) or re.search(r'[^a-zA-Z0-9 _\-.:/\\]', s)

def filter_malicious_strings(strings, safe_strings):
    filtered = []
    for s in strings:
        norm = normalize(s)
        if norm not in safe_strings and len(norm) >= 6 and not is_noise(s):
            print(f"[DEBUG] 탐지된 의심 문자열: '{s}'")
            filtered.append(s)
    return filtered


def collect_safe_strings(hwp_paths, min_length=6):
    safe_set = set()
    for hwp_path in hwp_paths:
        print(f"[*] 정상 샘플 분석 중: {hwp_path}")
        streams = extract_streams_ole(hwp_path)
        for name, raw in streams:
            decompressed = try_decompress(raw)
            data = decompressed if decompressed else raw
            strings = extract_strings(data, min_length)
            safe_set.update(normalize(s) for s in strings)
    return safe_set

def save_safe_strings(hwp_paths, output_path="safe_strings.txt"):
    # 기존 safe 문자열 불러오기
    existing_strings = load_safe_strings(output_path)

    # 새로운 safe 문자열 수집
    new_strings = collect_safe_strings(hwp_paths)

    # 병합
    merged_strings = existing_strings.union(new_strings)

    # 저장
    with open(output_path, "w", encoding="utf-8") as f:
        for s in sorted(merged_strings):
            f.write(s + "\n")

    print(f"[✓] 기존 + 새로운 정상 문자열 총 {len(merged_strings)}개 저장됨: {output_path}")


def load_safe_strings(path="safe_strings.txt"):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set(normalize(line) for line in f if line.strip())

def analyze_malicious_hwp(hwp_path, output_dir="output", safe_strings_path="safe_strings.txt"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    safe_strings = load_safe_strings(safe_strings_path)
    streams = extract_streams_ole(hwp_path)
    rule_count = 0

    for idx, (name, raw) in enumerate(streams):
        decompressed = try_decompress(raw)
        data = decompressed if decompressed else raw
        strings = extract_strings(data)
        filtered = filter_malicious_strings(strings, safe_strings)

        if filtered:
            # 의심 stream 저장
            bin_path = os.path.join(output_dir, f"{idx}_{name.replace('/', '_')}.unzlib.bin")
            with open(bin_path, "wb") as f:
                f.write(data)
            print(f"[+] 의심 stream 저장됨: {bin_path}")

            # YARA 룰 저장
            yara_rule = generate_yara_rule(filtered)
            output_path = os.path.join(output_dir, f"{idx}_{name.replace('/', '_')}.yar")
            if os.path.exists(output_path):
                print(f"[=] YARA 룰 이미 존재함, 건너뜀: {output_path}")
            else:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(yara_rule)
                print(f"[+] YARA 룰 생성됨: {output_path}")
                rule_count += 1
    if rule_count == 0:
        print("[-] 악성 특징 문자열을 찾지 못했습니다.")
    else:
        print(f"[✓] 총 {rule_count}개의 YARA 룰이 생성되었습니다.")

def main():
    if len(sys.argv) < 3:
        print("사용법:")
        print("  python test.py normal <file1.hwp> <file2.hwp> ...")
        print("  python test.py malicious <target.hwp>")
        return

    mode = sys.argv[1].lower()
    if mode == "normal":
        hwp_files = sys.argv[2:]
        save_safe_strings(hwp_files)
    elif mode == "malicious":
        hwp_file = sys.argv[2]
        analyze_malicious_hwp(hwp_file)
    else:
        print("[!] 모드를 'normal' 또는 'malicious'로 지정하세요.")

if __name__ == "__main__":
    main()
