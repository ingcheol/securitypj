import zlib

# Step 1: 압축 해제
flist = ["BIN0001.bmp.zlib"]

for item in flist:
    with open(item, "rb") as f:
        buf = f.read()

    try:
        unzlibed = zlib.decompress(buf, -15)
        with open(item + ".unzlib", "wb") as out_f:
            out_f.write(unzlibed)
        print(f"[+] 압축 해제 완료 → 저장됨: {item}.unzlib")
    except zlib.error as e:
        print(f"[!] 압축 해제 중 오류 발생: {e}")


# Step 2: XOR 복호화 (해당 zlib 파일은 XOR 복호화 대상이 아님)
# 아래 코드는 XOR 키가 필요한 경우만 사용합니다.
# BIN0001.bmp.zlib 파일은 XOR 처리를 하지 않아도 되므로 이 블록은 생략하거나 주석 처리하세요.

# import zlib

# flist = ["BIN0001.bmp.zlib"]

# for item in flist:
#     with open(item, "rb") as f:
#         buf = f.read()

#     try:
#         unzlibed = zlib.decompress(buf, -15)
#         unzlib_path = item + ".unzlib"
#         with open(unzlib_path, "wb") as out_f:
#             out_f.write(unzlibed)
#         print(f"[+] 압축 해제 완료 → 저장됨: {unzlib_path}")

#         key = bytes.fromhex("296bd6eb2ca90321bbef5f5ff4cf1c0e")
#         decoded = bytes([b ^ key[i % len(key)] for i, b in enumerate(unzlibed)])

#         print("\n[+] XOR 복호화 결과 (일부 미리보기):\n")
#         print(decoded[:500].decode("utf-8", errors="replace"))

#     except zlib.error as e:
#         print(f"[!] 압축 해제 중 오류 발생: {e}")






