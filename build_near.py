name: build-near

on:
  workflow_dispatch:
  push:
    branches: [main, master]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Собрать libHassleExtended (arm64 + arm32) через NDK раннера
        run: |
          echo "NDK: $ANDROID_NDK_LATEST_HOME"
          python3 build_near.py "$ANDROID_NDK_LATEST_HOME"
          mkdir -p out
          cp libHassleExtended_arm64.so libHassleExtended_arm32.so out/

      - name: Выложить .so
        uses: actions/upload-artifact@v4
        with:
          name: near-so
          path: out/*.so

      # --- дальше только если в папку apk/ закинуты части Hassle_Online_..._apk.001, .002, ... ---
      - name: Есть ли APK
        id: hasapk
        run: |
          if ls apk/*.001 >/dev/null 2>&1; then echo "yes=1" >> "$GITHUB_OUTPUT"; fi

      - name: Вшить мод в APK
        if: steps.hasapk.outputs.yes == '1'
        run: |
          python3 patch_apk.py "$(ls apk/*.001 | head -1)" out/unsigned.apk \
            --arm64 libHassleExtended_arm64.so --arm32 libHassleExtended_arm32.so

      - name: Подписать APK
        if: steps.hasapk.outputs.yes == '1'
        env:
          KEYSTORE_B64: ${{ secrets.KEYSTORE_B64 }}
          KEYSTORE_PASS: ${{ secrets.KEYSTORE_PASS }}
        run: |
          BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
          PASS="${KEYSTORE_PASS:-hassle123}"
          if [ -n "$KEYSTORE_B64" ]; then
            echo "$KEYSTORE_B64" | base64 -d > ks.jks
          else
            keytool -genkeypair -keystore ks.jks -alias hassle -keyalg RSA -keysize 2048 -validity 36500 \
              -storepass "$PASS" -keypass "$PASS" -dname "CN=Hassle Near"
            cp ks.jks out/keystore-SAVE-ME.jks
          fi
          "$BT/apksigner" sign --ks ks.jks --ks-pass "pass:$PASS" --key-pass "pass:$PASS" \
            --out out/Hassle_Online_near_signed.apk out/unsigned.apk
          "$BT/apksigner" verify -v out/Hassle_Online_near_signed.apk | head -5

      - name: Выложить APK
        if: steps.hasapk.outputs.yes == '1'
        uses: actions/upload-artifact@v4
        with:
          name: apk-signed
          path: |
            out/Hassle_Online_near_signed.apk
            out/keystore-SAVE-ME.jks
