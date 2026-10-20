#!/usr/bin/env python3
"""
patch_apk.py — вшивает мод «игроки рядом» в Hassle_Online APK.

  python patch_apk.py Hassle_Online_1_8_5_rec_focus_apk.001 out_unsigned.apk --arm64 libHassleExtended_arm64.so [--arm32 libHassleExtended_arm32.so]
                      [--opus-arm64 libopus_proxy_arm64.so] [--opus-arm32 libopus_proxy_arm32.so]

Что делает
  • если на входе .001 — склеивает части (.001, .002, ...) в память/временный файл;
  • для каждой ABI: lib/<abi>/libHassleExtended.so переименовывает в libHassleExtend2.so
    (наш мод при загрузке сам подгрузит его и передаст JNI_OnLoad), а на его место кладёт новый .so;
    если оригинала для этой ABI нет — просто добавляет новый;
  • убирает старую подпись META-INF (MANIFEST.MF, *.SF, *.RSA/DSA/EC);
  • .so пишет без сжатия и с выравниванием 4096, остальное выравнивает по 4 (как zipalign);
  • --opus-*: (голос в Telegram) настоящий lib/<abi>/libopus.so кладёт под именем libopuz.so (в нём правится SONAME
    libopus.so → libopuz.so), а на место libopus.so ставит прокси hassle_opus.c, который копит входящие Opus-пакеты;
  • остальные записи копирует байт-в-байт, без перепаковки.
После этого APK надо подписать (apksigner / uber-apk-signer) — см. README.
"""
import argparse, glob, os, re, struct, sys, tempfile, zlib, zipfile

def join_parts(first):
    m = re.match(r'^(.*)\.(\d{3})$', first)
    if not m:
        return first, False
    base = m.group(1)
    parts = sorted(glob.glob(base + '.[0-9][0-9][0-9]'))
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.apk')
    for p in parts:
        with open(p, 'rb') as f:
            while True:
                b = f.read(1 << 22)
                if not b: break
                tmp.write(b)
    tmp.close()
    print('склеено частей: %d -> %s' % (len(parts), tmp.name))
    return tmp.name, True

ABIS = {'arm64': 'arm64-v8a', 'arm32': 'armeabi-v7a'}
SIG_RE = re.compile(r'^META-INF/[^/]+\.(SF|RSA|DSA|EC)$|^META-INF/MANIFEST\.MF$', re.I)

def patch_soname(blob, old, new):
    """Меняет DT_SONAME в ELF (32/64 бит, little-endian) на строку той же длины. Возвращает новые байты."""
    assert len(old) == len(new)
    b = bytearray(blob)
    if b[:4] != b'\x7fELF': sys.exit('не ELF')
    is64 = b[4] == 2
    if is64:
        phoff = struct.unpack_from('<Q', b, 0x20)[0]; phentsize, phnum = struct.unpack_from('<HH', b, 0x36); ptr = 8
    else:
        phoff = struct.unpack_from('<I', b, 0x1C)[0]; phentsize, phnum = struct.unpack_from('<HH', b, 0x2A); ptr = 4
    loads, dyn = [], None
    for i in range(phnum):
        o = phoff + i * phentsize
        if is64:
            t_, fl, po, pv, pp, pfs, pms, al = struct.unpack_from('<IIQQQQQQ', b, o)
        else:
            t_, po, pv, pp, pfs, pms, fl, al = struct.unpack_from('<IIIIIIII', b, o)
        if t_ == 1: loads.append((pv, po, pfs))
        if t_ == 2: dyn = (po, pfs)
    if not dyn: sys.exit('нет PT_DYNAMIC')
    def v2o(v):
        for pv, po, pfs in loads:
            if pv <= v < pv + pfs: return v - pv + po
        sys.exit('адрес вне сегментов')
    strtab = soname = None
    esz = 16 if is64 else 8
    for o in range(dyn[0], dyn[0] + dyn[1], esz):
        tag, val = struct.unpack_from('<qQ' if is64 else '<iI', b, o)
        if tag == 5: strtab = val
        if tag == 14: soname = val
        if tag == 0: break
    if strtab is None or soname is None: sys.exit('нет DT_STRTAB/DT_SONAME')
    so = v2o(strtab) + soname
    cur = bytes(b[so:so + len(old) + 1])
    if cur != old.encode() + b'\0': sys.exit('SONAME не %s: %r' % (old, cur))
    b[so:so + len(new)] = new.encode()
    return bytes(b)

def entry_bytes(e, fin):
    fin.seek(e.src[0]); raw = fin.read(e.src[1])
    if e.method == 0: return raw
    if e.method == 8: return zlib.decompress(raw, -15)
    sys.exit('метод сжатия %d не поддержан: %s' % (e.method, e.name))

class Ent:
    __slots__ = ('name', 'method', 'crc', 'csize', 'usize', 'flags', 'dt', 'dd', 'src', 'data', 'ext_attr')

def read_entries(path):
    ents = []
    with zipfile.ZipFile(path) as z, open(path, 'rb') as f:
        for zi in z.infolist():
            f.seek(zi.header_offset)
            h = f.read(30)
            if h[:4] != b'PK\x03\x04':
                sys.exit('битый локальный заголовок: ' + zi.filename)
            nlen, elen = struct.unpack('<HH', h[26:30])
            e = Ent()
            e.name = zi.filename
            e.method = zi.compress_type
            e.crc = zi.CRC
            e.csize = zi.compress_size
            e.usize = zi.file_size
            e.flags = zi.flag_bits & ~0x08 | 0x800 if any(ord(c) > 127 for c in zi.filename) else zi.flag_bits & ~0x08
            e.dt = (zi.date_time)
            e.src = (zi.header_offset + 30 + nlen + elen, zi.compress_size)
            e.data = None
            e.ext_attr = zi.external_attr
            ents.append(e)
    return ents

def new_entry(name, blob):
    e = Ent()
    e.name = name; e.method = 0
    e.crc = zlib.crc32(blob) & 0xffffffff
    e.csize = e.usize = len(blob)
    e.flags = 0
    e.dt = (2026, 1, 1, 0, 0, 0)
    e.src = None; e.data = blob; e.ext_attr = 0o100644 << 16
    return e

def dos(dt):
    y, mo, d, h, mi, s = dt
    return ((max(y, 1980) - 1980) << 9 | mo << 5 | d) & 0xffff, (h << 11 | mi << 5 | s // 2) & 0xffff

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('inp'); ap.add_argument('out')
    ap.add_argument('--arm64'); ap.add_argument('--arm32')
    ap.add_argument('--opus-arm64', dest='opus64'); ap.add_argument('--opus-arm32', dest='opus32')
    a = ap.parse_args()
    if not a.arm64 and not a.arm32:
        sys.exit('нужен хотя бы один из --arm64 / --arm32')
    src_path, tmp = join_parts(a.inp)
    ents = read_entries(src_path)
    libs = {}
    if a.arm64: libs['arm64-v8a'] = open(a.arm64, 'rb').read()
    if a.arm32: libs['armeabi-v7a'] = open(a.arm32, 'rb').read()

    out_ents = []
    for e in ents:
        if SIG_RE.match(e.name):
            print('убрана подпись:', e.name); continue
        out_ents.append(e)
    for abi, blob in libs.items():
        orig = 'lib/%s/libHassleExtended.so' % abi
        moved = False
        for e in out_ents:
            if e.name == orig:
                e.name = 'lib/%s/libHassleExtend2.so' % abi
                moved = True; break
        print('%s: оригинал %s' % (abi, 'переименован в libHassleExtend2.so' if moved else 'не найден — добавляю только наш'))
        out_ents.append(new_entry(orig, blob))

    opus = {}
    if a.opus64: opus['arm64-v8a'] = open(a.opus64, 'rb').read()
    if a.opus32: opus['armeabi-v7a'] = open(a.opus32, 'rb').read()
    with open(src_path, 'rb') as fin:
        for abi, proxy in opus.items():
            orig = 'lib/%s/libopus.so' % abi
            real = next((e for e in out_ents if e.name == orig), None)
            if real is None:
                print('%s: в APK нет %s — прокси голоса пропущен' % (abi, orig)); continue
            blob = patch_soname(entry_bytes(real, fin), 'libopus.so', 'libopuz.so')
            out_ents.remove(real)
            out_ents.append(new_entry('lib/%s/libopuz.so' % abi, blob))
            out_ents.append(new_entry(orig, proxy))
            print('%s: настоящий libopus.so -> libopuz.so (SONAME исправлен), на его месте прокси голоса (%d байт)' % (abi, len(proxy)))

    with open(src_path, 'rb') as fin, open(a.out, 'wb') as fo:
        cd = []
        for e in out_ents:
            nm = e.name.encode('utf-8')
            fl = e.flags | (0x800 if any(b > 127 for b in nm) else 0)
            off = fo.tell()
            align = 0
            if e.method == 0:
                align = 4096 if e.name.endswith('.so') else 4
            pad = 0
            if align:
                pad = (-(off + 30 + len(nm))) % align
                if 0 < pad < 4: pad += align
            extra = b''
            if pad:
                extra = struct.pack('<HH', 0xD935, pad - 4) + b'\0' * (pad - 4)
            d, t = dos(e.dt)[0], dos(e.dt)[1]
            ver = 20
            fo.write(struct.pack('<4sHHHHHIIIHH', b'PK\x03\x04', ver, fl, e.method, t, d, e.crc, e.csize, e.usize, len(nm), len(extra)))
            fo.write(nm); fo.write(extra)
            if e.data is not None:
                fo.write(e.data)
            else:
                fin.seek(e.src[0]); left = e.src[1]
                while left:
                    b = fin.read(min(left, 1 << 22))
                    if not b: sys.exit('обрыв данных: ' + e.name)
                    fo.write(b); left -= len(b)
            cd.append((e, nm, fl, off, d, t, ver))
        cd_off = fo.tell()
        for e, nm, fl, off, d, t, ver in cd:
            fo.write(struct.pack('<4sHHHHHHIIIHHHHHII', b'PK\x01\x02', 0x031E, ver, fl, e.method, t, d, e.crc, e.csize, e.usize,
                                 len(nm), 0, 0, 0, 0, e.ext_attr & 0xffffffff, off))
            fo.write(nm)
        cd_size = fo.tell() - cd_off
        fo.write(struct.pack('<4sHHHHIIH', b'PK\x05\x06', 0, 0, len(cd), len(cd), cd_size, cd_off, 0))
    if tmp: os.unlink(src_path)
    # самопроверка
    with zipfile.ZipFile(a.out) as z:
        bad = z.testzip()
        if bad: sys.exit('ОШИБКА целостности: ' + bad)
    print('готово:', a.out, '(%.1f МБ) — теперь подпишите APK' % (os.path.getsize(a.out) / 1e6))

if __name__ == '__main__':
    main()
