/* near_client.js — клиент для нативного мода «игроки рядом» (вставить в Code3.js).
 * Мод отдаёт JSON на http://127.0.0.1:17771/near (порты 17771..17780): {ok, stage, me:{id,x,y,z}, n:[{id,nick,label,x,y,z,d,d2,hp,ar,ping,score,veh}]}
 *   d — дистанция 3D, d2 — по горизонтали (метры).
 * Использование:
 *   NearPlayers.list()            -> массив игроков рядом, ближайшие первыми
 *   NearPlayers.within(20)        -> те, кто ближе 20 м
 *   NearPlayers.byNick('Ivan')    -> игрок по части ника (без учёта регистра)
 *   NearPlayers.byId(123)
 *   NearPlayers.status()          -> {alive, ok, stage, age}  (alive=false — мода в APK нет / не отвечает)
 *   NearPlayers.diag(cb)          -> cb(текст журнала мода) — для отладки
 */
(function () {
    if (window.NearPlayers) return;
    var PORTS = [];
    for (var i = 0; i < 10; i++) PORTS.push(17771 + i);
    var base = null, snap = null, stamp = 0, busy = false, portIdx = 0;

    function xhr(url, ok, fail, timeout) {
        try {
            var r = new XMLHttpRequest();
            r.open('GET', url, true);
            r.timeout = timeout || 800;
            r.onload = function () { r.status === 200 ? ok(r.responseText) : fail(); };
            r.onerror = r.ontimeout = fail;
            r.send();
        } catch (e) { fail(); }
    }
    function tick() {
        if (busy) return;
        busy = true;
        var done = function () { busy = false; };
        if (!base) {
            var p = PORTS[portIdx++ % PORTS.length];
            xhr('http://127.0.0.1:' + p + '/ping', function (t) {
                if (t === 'hassle-near') base = 'http://127.0.0.1:' + p;
                done();
            }, done, 400);
            return;
        }
        xhr(base + '/near', function (t) {
            try { snap = JSON.parse(t); stamp = Date.now(); } catch (e) {}
            done();
        }, function () { base = null; done(); });
    }
    setInterval(tick, 500);
    tick();

    function fresh() { return snap && Date.now() - stamp < 3000; }
    window.NearPlayers = {
        list: function () {
            if (!fresh() || !snap.ok) return [];
            return snap.n.slice().sort(function (a, b) { return (a.d2 == null ? 1e9 : a.d2) - (b.d2 == null ? 1e9 : b.d2); });
        },
        within: function (m) { return this.list().filter(function (p) { return p.d2 != null && p.d2 <= m; }); },
        byNick: function (s) {
            s = String(s).toLowerCase();
            return this.list().filter(function (p) { return (p.nick || '').toLowerCase().indexOf(s) >= 0; });
        },
        byId: function (id) { return this.list().filter(function (p) { return p.id === id; })[0] || null; },
        me: function () { return fresh() ? snap.me : null; },
        status: function () {
            return { alive: !!fresh(), ok: !!(snap && snap.ok), stage: snap ? snap.stage : 'нет связи с модом', age: stamp ? Date.now() - stamp : null };
        },
        diag: function (cb) { if (!base) return cb('нет связи'); xhr(base + '/diag', cb, function () { cb('ошибка'); }, 1500); }
    };
})();
