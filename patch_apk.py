# Сборка через GitHub Actions

1. Создайте **приватный** репозиторий на github.com и загрузите в него содержимое этой папки (включая `.github/workflows/build.yml`).
2. Вкладка **Actions** -> `build-near` -> **Run workflow**. Через 1–2 минуты в Artifacts появится `near-so` (два `.so`).
3. Скачайте `near-so`, положите `.so` рядом с `patch_apk.py` и локально выполните (NDK не нужен, только Python):
   `python patch_apk.py Hassle_Online_1_8_5_rec_focus_apk.001 out_unsigned.apk --arm64 libHassleExtended_arm64.so --arm32 libHassleExtended_arm32.so`
   затем подпишите (`uber-apk-signer -a out_unsigned.apk`).

## Если хотите, чтобы APK собрал и подписал GitHub
Закиньте части `.001`–`.005` в папку `apk/` через `git push` (веб-загрузка принимает файлы до 25 МБ, а части по 28 МБ; лимит git — 100 МБ на файл). Репозиторий обязательно приватный. Тогда в Artifacts появится `apk-signed`.
Ключ подписи: без секретов на каждый запуск создаётся новый ключ (кладётся в артефакт `keystore-SAVE-ME.jks`), и обновить APK поверх прошлой сборки не получится. Чтобы ключ был постоянным, сохраните его в Settings -> Secrets: `KEYSTORE_B64` (`base64 -w0 ks.jks`) и `KEYSTORE_PASS`.
