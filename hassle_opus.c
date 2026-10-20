/*
 * hassle_opus.c — прокси для libopus.so (Hassle Online, Unity IL2CPP): копит входящие голосовые Opus-пакеты.
 *
 * Как это работает
 *   • Игра декодирует голос через Hassle.Audio.Opus → libopus.so (DllImport "opus": opus_decoder_create / opus_decode /
 *     opus_decoder_destroy и три функции кодера). patch_apk.py кладёт в APK ЭТОТ файл как lib/<abi>/libopus.so, а настоящий
 *     libopus.so переименовывает в libopuz.so (в нём заодно правится SONAME).
 *   • Прокси экспортирует ровно те 7 функций, которые импортирует игра, и пробрасывает их в настоящий libopuz.so.
 *     Звук не меняется: пакет сначала декодирует оригинал, и только потом (если декод удался) копия пакета кладётся в кольцо.
 *   • hassle_near.c (libHassleExtended.so) находит эти функции через dlsym и отдаёт пакеты по HTTP: GET /voice?since=N.
 *     Code3.js собирает из пакетов OGG/Opus и шлёт в Telegram голосовым сообщением.
 *
 * События в кольце (тип): 0 — декодер создан (fs, ch), 1 — пакет, 2 — декодер уничтожен.
 * Формат hassle_voice_pull:
 *   {"v":1,"ok":1,"p":[[тип,№,t_мс,декодер,fs,ch,длина,"base64"],...],"next":N,"lost":K,"now":t_мс}
 *   t_мс — монотонные миллисекунды на момент события, now — на момент ответа (Code3 по ним сопоставляет время с Date.now()).
 *
 * Код не использует libc-заголовки (как и hassle_near.c): прототипы объявлены вручную.
 * Для кодера ничего не копится — свой микрофон не записывается, только проброс.
 */

typedef unsigned long uptr;
typedef unsigned char u8;
typedef unsigned long long u64;

#define NULL ((void*)0)
#define EXPORT __attribute__((visibility("default")))

extern void* dlopen(const char*, int);
extern void* dlsym(void*, const char*);
extern const char* dlerror(void);
extern int clock_gettime(int, void*);
extern int sched_yield(void);

#define RTLD_NOW_ 2
#define CLOCK_MONOTONIC_ 1

#define RING_N 2048          /* событий в кольце (степень двойки не нужна) */
#define MAX_PAY 640          /* пакет длиннее — не копим (голос игры — десятки-сотни байт) */
#define MAX_DEC 64           /* одновременно живых декодеров */
#define PULL_MAX_EVENTS 200  /* за один ответ */

typedef struct { u64 seq; unsigned t; unsigned dec; int fs, ch, type, len; u8 d[MAX_PAY]; } Slot;
static Slot g_ring[RING_N];
static u64 g_seq;                         /* последний выданный номер (первый = 1) */

typedef struct { void* ptr; unsigned id; int fs, ch; } Dec;
static Dec g_dec[MAX_DEC];
static unsigned g_nextDecId = 1;

static unsigned long g_cCreate, g_cDestroy, g_cPkt, g_cBytes, g_cPlc, g_cFec, g_cBig, g_cErr, g_cUnknownDec;
static int g_fsSeen[4];                   /* какие fs встречались: 8000/12000/16000/24000/48000 — по первым четырём разным */
static unsigned g_maxLen, g_lastPktT;

/* ───────────── спинлок (потоки: главный Unity, аудио, наш HTTP) ───────────── */
static volatile int g_lk;
static void lock(void) {
    unsigned spin = 0;
    while (__atomic_exchange_n(&g_lk, 1, __ATOMIC_ACQUIRE)) { if (++spin > 200) { sched_yield(); spin = 0; } }
}
static void unlock(void) { __atomic_store_n(&g_lk, 0, __ATOMIC_RELEASE); }

static unsigned now_ms(void) {
    struct { long s; long ns; } ts;
    clock_gettime(CLOCK_MONOTONIC_, &ts);
    return (unsigned)((unsigned long)ts.s * 1000UL + (unsigned long)ts.ns / 1000000UL);
}

/* ───────────── настоящий libopus ───────────── */
typedef void* (*f_dcreate)(int, int, int*);
typedef void  (*f_dfree)(void*);
typedef int   (*f_decode)(void*, const u8*, int, short*, int, int);
typedef void* (*f_ecreate)(int, int, int, int*);
typedef void  (*f_efree)(void*);
typedef int   (*f_encode)(void*, const short*, int, u8*, int);
typedef int   (*f_ectl)(void*, int, long);
static f_dcreate r_dcreate; static f_dfree r_dfree; static f_decode r_decode;
static f_ecreate r_ecreate; static f_efree r_efree; static f_encode r_encode; static f_ectl r_ectl;
static volatile int g_state;              /* 0 — ещё не грузили, 1 — готово, -1 — не удалось */
static char g_realName[24];
static char g_realErr[160];

static void copy_str(char* d, const char* s, int cap) { int i = 0; while (s && s[i] && i < cap - 1) { d[i] = s[i]; i++; } d[i] = 0; }

static int real_ok(void) {
    void* h; const char* nm = "libopuz.so";
    if (g_state) return g_state > 0;
    lock();
    if (!g_state) {
        h = dlopen(nm, RTLD_NOW_);
        if (!h) { copy_str(g_realErr, dlerror(), sizeof g_realErr); }
        if (h) {
            *(void**)&r_dcreate = dlsym(h, "opus_decoder_create");
            *(void**)&r_dfree   = dlsym(h, "opus_decoder_destroy");
            *(void**)&r_decode  = dlsym(h, "opus_decode");
            *(void**)&r_ecreate = dlsym(h, "opus_encoder_create");
            *(void**)&r_efree   = dlsym(h, "opus_encoder_destroy");
            *(void**)&r_encode  = dlsym(h, "opus_encode");
            *(void**)&r_ectl    = dlsym(h, "opus_encoder_ctl");
            if (r_dcreate && r_dfree && r_decode && r_ecreate && r_efree && r_encode && r_ectl) { copy_str(g_realName, nm, sizeof g_realName); g_state = 1; }
            else { copy_str(g_realErr, "в libopuz.so нет нужных opus_* функций", sizeof g_realErr); g_state = -1; }
        } else g_state = -1;
    }
    unlock();
    return g_state > 0;
}

/* ───────────── кольцо ───────────── */
static Slot* push_locked(int type, unsigned dec, int fs, int ch) {
    Slot* s = &g_ring[g_seq % RING_N];
    g_seq++;
    s->seq = g_seq; s->t = now_ms(); s->dec = dec; s->fs = fs; s->ch = ch; s->type = type; s->len = 0;
    return s;
}
static Dec* find_dec_locked(void* p) {
    int i;
    for (i = 0; i < MAX_DEC; i++) if (g_dec[i].ptr == p) return &g_dec[i];
    return NULL;
}
static Dec* add_dec_locked(void* p, int fs, int ch) {
    int i;
    for (i = 0; i < MAX_DEC; i++) if (!g_dec[i].ptr) {
        g_dec[i].ptr = p; g_dec[i].id = g_nextDecId++; g_dec[i].fs = fs; g_dec[i].ch = ch;
        return &g_dec[i];
    }
    return NULL;                                              /* таблица переполнена — этот декодер не отслеживаем */
}

/* ───────────── экспорт: 7 функций, которые импортирует игра ───────────── */
EXPORT void* opus_decoder_create(int fs, int ch, int* err) {
    void* p; Dec* d;
    if (!real_ok()) { if (err) *err = -1; return NULL; }
    p = r_dcreate(fs, ch, err);
    if (p) {
        lock();
        g_cCreate++;
        d = add_dec_locked(p, fs, ch);
        if (d) push_locked(0, d->id, fs, ch);
        {
            int i, seen = 0;
            for (i = 0; i < 4; i++) if (g_fsSeen[i] == fs) seen = 1;
            for (i = 0; i < 4 && !seen; i++) if (!g_fsSeen[i]) { g_fsSeen[i] = fs; seen = 1; }
        }
        unlock();
    }
    return p;
}
EXPORT void opus_decoder_destroy(void* p) {
    Dec* d;
    if (!real_ok()) return;
    lock();
    d = find_dec_locked(p);
    if (d) { push_locked(2, d->id, d->fs, d->ch); d->ptr = NULL; }
    g_cDestroy++;
    unlock();
    r_dfree(p);
}
EXPORT int opus_decode(void* p, const u8* data, int len, short* pcm, int frame, int fec) {
    int r;
    if (!real_ok()) return -1;
    r = r_decode(p, data, len, pcm, frame, fec);
    if (!data || len <= 0) { g_cPlc++; return r; }             /* потеря пакета (PLC) — копить нечего */
    if (fec) { g_cFec++; return r; }                           /* FEC-проход повторно разбирает предыдущий пакет — дубль */
    if (r < 0) { g_cErr++; return r; }
    if (len > MAX_PAY) { g_cBig++; return r; }
    lock();
    {
        Dec* d = find_dec_locked(p);
        Slot* s;
        if (!d) { g_cUnknownDec++; d = add_dec_locked(p, 0, 0); }
        if (d) {
            s = push_locked(1, d->id, d->fs, d->ch);
            s->len = len;
            { int i; for (i = 0; i < len; i++) s->d[i] = data[i]; }
            g_cPkt++; g_cBytes += (unsigned long)len; g_lastPktT = s->t;
            if ((unsigned)len > g_maxLen) g_maxLen = (unsigned)len;
        }
    }
    unlock();
    return r;
}
/* кодер — чистый проброс (свой микрофон не копим) */
EXPORT void* opus_encoder_create(int fs, int ch, int app, int* err) {
    if (!real_ok()) { if (err) *err = -1; return NULL; }
    return r_ecreate(fs, ch, app, err);
}
EXPORT void opus_encoder_destroy(void* p) { if (real_ok()) r_efree(p); }
EXPORT int opus_encode(void* p, const short* pcm, int frame, u8* out, int max) {
    if (!real_ok()) return -1;
    return r_encode(p, pcm, frame, out, max);
}
/* opus_encoder_ctl(st, request, ...) — у всех запросов кодера один аргумент (int или указатель): передаём его как long */
EXPORT int opus_encoder_ctl(void* p, int req, long a) {
    if (!real_ok()) return -1;
    return r_ectl(p, req, a);
}

/* ───────────── вывод для hassle_near.c ───────────── */
typedef struct { char* p; int n, cap; } W;
static void w_ch(W* w, char c) { if (w->n + 1 < w->cap) w->p[w->n++] = c; }
static void w_s(W* w, const char* s) { while (*s) w_ch(w, *s++); }
static void w_u(W* w, u64 v) {
    char t[24]; int n = 0;
    if (!v) { w_ch(w, '0'); return; }
    while (v) { t[n++] = (char)('0' + (int)(v % 10)); v /= 10; }
    while (n) w_ch(w, t[--n]);
}
static void w_b64(W* w, const u8* d, int n) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i;
    for (i = 0; i + 2 < n; i += 3) {
        unsigned v = ((unsigned)d[i] << 16) | ((unsigned)d[i + 1] << 8) | d[i + 2];
        w_ch(w, T[v >> 18]); w_ch(w, T[(v >> 12) & 63]); w_ch(w, T[(v >> 6) & 63]); w_ch(w, T[v & 63]);
    }
    if (n - i == 1) { unsigned v = (unsigned)d[i] << 16; w_ch(w, T[v >> 18]); w_ch(w, T[(v >> 12) & 63]); w_ch(w, '='); w_ch(w, '='); }
    else if (n - i == 2) { unsigned v = ((unsigned)d[i] << 16) | ((unsigned)d[i + 1] << 8); w_ch(w, T[v >> 18]); w_ch(w, T[(v >> 12) & 63]); w_ch(w, T[(v >> 6) & 63]); w_ch(w, '='); }
}

/* since = ~0 — «только узнать номер»: пакеты не отдаём (так Code3 стартует после перезагрузки страницы, не получая старый хвост) */
EXPORT int hassle_voice_pull(u64 since, char* out, int cap) {
    W w; u64 first, last, s; int cnt = 0; u64 lost = 0, head;
    w.p = out; w.n = 0; w.cap = cap - 8;
    lock();
    head = g_seq;
    if (since == ~(u64)0) {
        w_s(&w, "{\"v\":1,\"ok\":1,\"p\":[],\"next\":"); w_u(&w, head); w_s(&w, ",\"lost\":0,\"now\":"); w_u(&w, now_ms()); w_s(&w, "}");
        unlock(); out[w.n] = 0; return w.n;
    }
    if (since > head) since = head;                            /* клиент помнит больший номер (перезапуск процесса) — начинаем с текущего */
    first = head > RING_N ? head - RING_N + 1 : 1;
    if (since + 1 > first) first = since + 1; else if (since + 1 < first) lost = first - (since + 1);
    last = since;
    w_s(&w, "{\"v\":1,\"ok\":1,\"p\":[");
    for (s = first; s <= head && cnt < PULL_MAX_EVENTS; s++) {
        Slot* e = &g_ring[(s - 1) % RING_N];
        int need = 80 + ((e->len + 2) / 3) * 4;
        if (e->seq != s) { lost++; last = s; continue; }       /* затёрто (на всякий случай) */
        if (w.n + need + 160 > w.cap) break;
        if (cnt) w_ch(&w, ',');
        w_ch(&w, '['); w_u(&w, (u64)e->type); w_ch(&w, ','); w_u(&w, e->seq); w_ch(&w, ','); w_u(&w, e->t); w_ch(&w, ',');
        w_u(&w, e->dec); w_ch(&w, ','); w_u(&w, (u64)e->fs); w_ch(&w, ','); w_u(&w, (u64)e->ch); w_ch(&w, ','); w_u(&w, (u64)e->len);
        w_s(&w, ",\"");
        if (e->len) w_b64(&w, e->d, e->len);
        w_s(&w, "\"]");
        cnt++; last = s;
    }
    w_s(&w, "],\"next\":"); w_u(&w, last); w_s(&w, ",\"lost\":"); w_u(&w, lost);
    w_s(&w, ",\"now\":"); w_u(&w, now_ms()); w_s(&w, "}");
    unlock();
    out[w.n] = 0;
    return w.n;
}

EXPORT int hassle_voice_info(char* out, int cap) {
    W w; int i, live = 0;
    w.p = out; w.n = 0; w.cap = cap;
    w_s(&w, "прокси libopus: ");
    if (g_state > 0) { w_s(&w, "OK, настоящий = "); w_s(&w, g_realName); }
    else if (g_state < 0) { w_s(&w, "НЕ РАБОТАЕТ: "); w_s(&w, g_realErr); }
    else w_s(&w, "ещё не вызывался игрой");
    w_s(&w, "\nдекодеров создано/уничтожено: "); w_u(&w, g_cCreate); w_s(&w, "/"); w_u(&w, g_cDestroy);
    lock();
    for (i = 0; i < MAX_DEC; i++) if (g_dec[i].ptr) live++;
    w_s(&w, "\nживых декодеров: "); w_u(&w, (u64)live);
    w_s(&w, "\nпакетов: "); w_u(&w, g_cPkt); w_s(&w, " ("); w_u(&w, g_cBytes); w_s(&w, " байт, макс. "); w_u(&w, g_maxLen); w_s(&w, ")");
    w_s(&w, "\nPLC: "); w_u(&w, g_cPlc); w_s(&w, ", FEC: "); w_u(&w, g_cFec); w_s(&w, ", ошибок декода: "); w_u(&w, g_cErr);
    w_s(&w, ", слишком длинных: "); w_u(&w, g_cBig); w_s(&w, ", от неизвестного декодера: "); w_u(&w, g_cUnknownDec);
    w_s(&w, "\nчастоты: ");
    for (i = 0; i < 4; i++) if (g_fsSeen[i]) { w_u(&w, (u64)g_fsSeen[i]); w_ch(&w, ' '); }
    w_s(&w, "\nномер последнего события: "); w_u(&w, g_seq);
    w_s(&w, "\nпоследний пакет, мс назад: ");
    if (g_cPkt) w_u(&w, (u64)(now_ms() - g_lastPktT)); else w_s(&w, "—");
    w_ch(&w, '\n');
    unlock();
    if (w.n < cap) out[w.n] = 0; else out[cap - 1] = 0;
    return w.n;
}
