#!/usr/bin/env python3
"""
build_near.py — собирает hassle_near.c в libHassleExtended_arm64.so и libHassleExtended_arm32.so через Android NDK.

  python build_near.py [путь_к_NDK]

NDK ищется: аргумент -> ANDROID_NDK_HOME / ANDROID_NDK_ROOT / ANDROID_NDK -> <Android SDK>/ndk/<последняя версия>.
Нужен только clang из NDK (Android Studio -> SDK Manager -> SDK Tools -> NDK (Side by side)).
"""
import glob, os, platform, subprocess, sys

here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, 'hassle_near.c')

def find_ndk():
    if len(sys.argv) > 1: return sys.argv[1]
    for k in ('ANDROID_NDK_HOME', 'ANDROID_NDK_ROOT', 'ANDROID_NDK'):
        if os.environ.get(k): return os.environ[k]
    sdks = [os.environ.get('ANDROID_HOME'), os.environ.get('ANDROID_SDK_ROOT'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Android', 'Sdk'),
            os.path.expanduser('~/Android/Sdk'), os.path.expanduser('~/Library/Android/sdk')]
    for s in sdks:
        if s:
            c = sorted(glob.glob(os.path.join(s, 'ndk', '*')))
            if c: return c[-1]
    sys.exit('NDK не найден. Передайте путь аргументом: python build_near.py D:\\Android\\Sdk\\ndk\\27.0.12077973')

ndk = find_ndk()
host = {'Windows': 'windows-x86_64', 'Linux': 'linux-x86_64', 'Darwin': 'darwin-x86_64'}[platform.system()]
clang = os.path.join(ndk, 'toolchains', 'llvm', 'prebuilt', host, 'bin', 'clang' + ('.exe' if os.name == 'nt' else ''))
if not os.path.exists(clang):
    sys.exit('не найден clang: ' + clang)

targets = [
    ('arm64', 'aarch64-linux-android21', ['-Wl,-z,max-page-size=16384']),
    ('arm32', 'armv7a-linux-androideabi21', []),
]
for name, tgt, extra in targets:
    out = os.path.join(here, 'libHassleExtended_%s.so' % name)
    cmd = [clang, '--target=' + tgt, '-O2', '-shared', '-fPIC', '-fvisibility=hidden', '-fno-stack-protector',
           '-Wall', '-Wno-unused-function', '-Wl,-soname,libHassleExtended.so', '-Wl,--build-id=none', '-s',
           src, '-o', out] + extra
    print('>', name)
    r = subprocess.run(cmd)
    if r.returncode: sys.exit('сборка %s упала' % name)
    print('   ', out, os.path.getsize(out), 'байт')
print('готово. Дальше: python patch_apk.py <apk.001> out_unsigned.apk --arm64 libHassleExtended_arm64.so --arm32 libHassleExtended_arm32.so')
