#!/usr/bin/env python3
"""
gui — отдельное окно-приложение: функциональный ТЕРМИНАЛ в стиле кибер-CMD (этап 3).

Это не «картинка с кнопками», а полноценный терминал: пользователь вводит команды
(scan/help/key/monitor/clear/exit…), как в нашем CLI, но в красивом тёмном окне.
Дизайн-мокап — лишь референс стиля. Никаких фейковых кнопок окна: рамку и кнопки
свернуть/закрыть даёт сама Windows.

`scan` без пути открывает системное окно выбора файла.

Запуск (разработка):  python gui.py
Сборка:               pyinstaller --noconsole --onefile --name VTScan gui.py
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import webview

import vtscan
from engines import data_dir


def _serialize(r: "vtscan.ScanResult") -> dict:
    primary = r.threat_categories[0] if r.threat_categories else ""
    return {
        "name": r.path.name,
        "path": str(r.path),
        "status": r.status,
        "verdict": r.verdict_label,
        "sha256": r.sha256,
        "threat_type": (vtscan.describe_threat(primary) or primary) if primary else "",
        "threat_others": r.threat_categories[1:],
        "family": ", ".join(r.threat_names[:3]) if r.threat_names else "",
        "engines": [
            {"engine": e.engine, "status": e.status, "detail": e.detail}
            for e in r.engine_results
        ],
        "message": r.message,
    }


class Api:
    """Методы для JS (pywebview.api.<метод>). Команды интерпретирует фронтенд."""

    def __init__(self) -> None:
        self._client = None
        self._monitor = None
        self._scanning = False
        self._scan_stop = False
        self._window = None

    # --- ключ ---
    def has_key(self) -> bool:
        return vtscan.resolve_api_key(None) is not None

    def save_key(self, key: str) -> bool:
        key = (key or "").strip()
        if not key:
            return False
        vtscan.save_api_key(key)
        self._client = vtscan.VirusTotalClient(key)
        return True

    def _ensure_client(self):
        if self._client is None:
            key = vtscan.resolve_api_key(None)
            if key:
                self._client = vtscan.VirusTotalClient(key)
        return self._client

    # --- инфо / окружение ---
    def app_info(self) -> dict:
        sources = ["VirusTotal"]
        if vtscan.clamav_engine().is_available():
            sources.append("ClamAV")
        return {"version": vtscan.VERSION, "sources": sources, "cwd": os.getcwd(),
                "data_dir": str(data_dir())}

    def get_cwd(self) -> str:
        return os.getcwd()

    def set_cwd(self, path: str) -> dict:
        try:
            os.chdir(os.path.expanduser(path))
            return {"ok": True, "cwd": os.getcwd()}
        except OSError as e:
            return {"ok": False, "error": str(e)}

    # --- открыть ссылку в системном браузере (клик по ссылке в консоли) ---
    def open_url(self, url: str) -> dict:
        url = (url or "").strip()
        if not (url.startswith("http://") or url.startswith("https://")):
            return {"ok": False, "message": "недопустимая ссылка"}
        import webbrowser
        try:
            webbrowser.open(url)
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": str(e)}

    # --- выбор файла системным диалогом ---
    def pick_file(self):
        win = webview.windows[0]
        result = win.create_file_dialog(webview.OPEN_DIALOG, allow_multiple=False)
        if not result:
            return None
        return result[0]

    # --- сканирование ---
    def scan(self, path: str, upload: bool = False) -> dict:
        client = self._ensure_client()
        if client is None:
            return {"error": "no_key"}
        p = Path(os.path.expanduser(path))
        if not p.is_absolute():
            p = Path(os.getcwd()) / p
        if not p.exists():
            return {"error": "not_found", "name": p.name}
        try:
            result = vtscan.scan_one(client, p, upload)
        except Exception as e:  # noqa: BLE001
            return {"error": "scan_failed", "message": str(e), "name": p.name}
        return _serialize(result)

    # --- проверка обновлений ---
    def check_update(self) -> dict:
        try:
            latest = vtscan.fetch_latest_release()
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"не удалось проверить: {e}"}
        if not latest:
            return {"ok": False, "message": "не удалось получить релизы"}
        ver, _ = latest
        if vtscan._version_tuple(ver) > vtscan._version_tuple(vtscan.VERSION):
            return {"ok": True, "newer": ver, "message": f"доступна версия {ver} (у вас {vtscan.VERSION})"}
        return {"ok": True, "newer": None, "message": f"у вас последняя версия ({vtscan.VERSION})"}

    def do_update(self) -> dict:
        """Реально скачивает и устанавливает свежий релиз (прогресс — в окно)."""
        try:
            latest = vtscan.fetch_latest_release()
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": str(e)}
        if not latest:
            return {"ok": False, "message": "нет релизов"}
        ver, assets = latest
        if vtscan._version_tuple(ver) <= vtscan._version_tuple(vtscan.VERSION):
            return {"ok": False, "message": f"уже последняя версия ({vtscan.VERSION})"}
        url = vtscan._asset_url_for_current_exe(assets)

        def _log(m: str) -> None:
            try:
                payload = vtscan.json.dumps({"text": m}, ensure_ascii=False)
                webview.windows[0].evaluate_js(f"window.onLog && window.onLog({payload})")
            except Exception:
                pass

        threading.Thread(target=lambda: vtscan._apply_update(url, ver, log=_log),
                         daemon=True).start()
        return {"ok": True, "started": True, "ver": ver}

    # --- фоновая защита ---
    def monitor_start(self) -> dict:
        if self._monitor is not None:
            return {"ok": False, "message": "защита уже включена"}
        try:
            import monitor as monitor_mod
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"монитор недоступен: {e}"}
        client = self._ensure_client()
        cb = vtscan._monitor_scan_callback(client) if client else None

        def on_event(ev):
            try:
                win = webview.windows[0]
                payload = vtscan.json.dumps(
                    {"title": ev.title, "detail": ev.detail, "severity": ev.severity,
                     "kind": ev.kind, "pid": ev.pid, "path": ev.path},
                    ensure_ascii=False)
                win.evaluate_js(f"window.onMonitorEvent && window.onMonitorEvent({payload})")
            except Exception:
                pass

        self._monitor = monitor_mod.Monitor(on_event, scan_callback=cb,
                                            notifier=self._threat_notify)
        self._monitor.start()
        self._push_guard()
        return {"ok": True}

    def monitor_stop(self) -> dict:
        if self._monitor is None:
            return {"ok": False, "message": "защита не запущена"}
        try:
            self._monitor.stop()
        finally:
            self._monitor = None
        self._push_guard()
        return {"ok": True}

    def monitor_status(self) -> dict:
        return {"on": self._monitor is not None}

    def _push_guard(self) -> None:
        """Обновить индикатор «Защита» в шапке (в т.ч. при переключении из трея)."""
        try:
            on = vtscan.json.dumps({"on": self._monitor is not None})
            webview.windows[0].evaluate_js(f"window.onGuardState && window.onGuardState({on})")
        except Exception:
            pass

    def monitor_toggle(self) -> dict:
        """Одна команда: выключена → включить, включена → выключить."""
        if self._monitor is None:
            res = self.monitor_start()
            return {"on": bool(res.get("ok")), "message": res.get("message", "")}
        self.monitor_stop()
        return {"on": False, "message": ""}

    # --- скан компьютера (быстрый/полный, ClamAV офлайн) ---
    def scan_computer(self, mode: str = "quick") -> dict:
        eng = vtscan.clamav_engine()
        if not eng.is_available():
            return {"ok": False, "need_clamav": True}
        if self._scanning:
            return {"ok": False, "message": "скан уже идёт"}
        dirs = vtscan.quick_scan_dirs() if mode == "quick" else vtscan.full_scan_dirs()
        if not dirs:
            return {"ok": False, "message": "не найдено папок для проверки"}
        self._scan_stop = False
        self._scanning = True

        def push(js: str) -> None:
            try:
                webview.windows[0].evaluate_js(js)
            except Exception:
                pass

        state = {"last": 0.0, "total": 0}

        def on_file(n: int, path: str) -> None:
            now = time.time()
            if now - state["last"] >= 0.2:    # троттлинг, чтобы не заваливать UI
                state["last"] = now
                payload = vtscan.json.dumps(
                    {"scanned": n, "total": state["total"], "path": path},
                    ensure_ascii=False)
                push(f"window.onScanProgress && window.onScanProgress({payload})")

        def worker() -> None:
            try:
                # Сначала считаем общее число файлов — для прогресса «X из N».
                state["total"] = vtscan.count_files(dirs)
                push(f"window.onScanStart && window.onScanStart("
                     f"{vtscan.json.dumps({'total': state['total']})})")
                res = eng.scan_tree(dirs, on_file=on_file,
                                    should_stop=lambda: self._scan_stop)
            except Exception as e:  # noqa: BLE001
                res = {"scanned": 0, "infected": [], "error": str(e)}
            finally:
                self._scanning = False
            res["stopped"] = self._scan_stop
            payload = vtscan.json.dumps(res, ensure_ascii=False)
            push(f"window.onScanDone && window.onScanDone({payload})")

        threading.Thread(target=worker, daemon=True).start()
        return {"ok": True, "started": True, "mode": mode,
                "dirs": [str(d) for d in dirs]}

    def scan_stop(self) -> dict:
        self._scan_stop = True
        return {"ok": True}

    # --- скан памяти (запущенные процессы) ---
    def scan_memory(self) -> dict:
        if self._scanning:
            return {"ok": False, "message": "скан уже идёт"}
        import monitor as monitor_mod
        st = vtscan._clamav_scan_tree()
        self._scan_stop = False
        self._scanning = True

        def push(js: str) -> None:
            try:
                webview.windows[0].evaluate_js(js)
            except Exception:
                pass

        state = {"last": 0.0}

        def on_progress(n: int, total: int, name: str) -> None:
            now = time.time()
            if now - state["last"] >= 0.2:
                state["last"] = now
                payload = vtscan.json.dumps({"checked": n, "total": total, "name": name},
                                            ensure_ascii=False)
                push(f"window.onMemProgress && window.onMemProgress({payload})")

        def worker() -> None:
            try:
                res = monitor_mod.scan_processes(scan_tree=st, on_progress=on_progress,
                                                 should_stop=lambda: self._scan_stop)
            except Exception as e:  # noqa: BLE001
                res = {"checked": 0, "findings": [], "error": str(e)}
            finally:
                self._scanning = False
            res["stopped"] = self._scan_stop
            res["clamav"] = st is not None
            push(f"window.onMemDone && window.onMemDone("
                 f"{vtscan.json.dumps(res, ensure_ascii=False)})")

        threading.Thread(target=worker, daemon=True).start()
        return {"ok": True, "started": True, "clamav": st is not None}

    # --- автозапуск с Windows ---
    def autostart_status(self) -> dict:
        return {"enabled": vtscan.autostart_enabled()}

    def autostart_set(self, on: bool) -> dict:
        ok = vtscan.enable_autostart() if on else vtscan.disable_autostart()
        return {"ok": ok, "enabled": vtscan.autostart_enabled()}

    # --- действия по угрозе (кнопки в окне) ---
    def act_quarantine(self, path: str) -> dict:
        import monitor as monitor_mod
        dest = monitor_mod.quarantine_file(Path(path))
        return {"ok": bool(dest), "message": (f"В карантине: {dest}" if dest else "Не удалось поместить в карантин")}

    def act_delete(self, path: str) -> dict:
        try:
            Path(path).unlink()
            return {"ok": True, "message": "Файл устранён."}
        except OSError as e:
            return {"ok": False, "message": f"Не удалось удалить: {e}"}

    def act_suspend(self, pid: int) -> dict:
        import monitor as monitor_mod
        ok = monitor_mod.suspend_process(int(pid))
        return {"ok": ok, "message": ("Процесс приостановлен (обратимо)." if ok else "Не удалось (нужны права?).")}

    def act_kill(self, pid: int) -> dict:
        import monitor as monitor_mod
        ok = monitor_mod.kill_process(int(pid))
        return {"ok": ok, "message": ("Процесс завершён." if ok else "Не удалось завершить (нужны права администратора?).")}

    # --- загрузчик ClamAV в папку приложения ---
    def setup_clamav(self) -> dict:
        if os.name != "nt":
            return {"ok": False, "message": "Загрузчик ClamAV работает только на Windows."}

        def _log(m: str) -> None:
            try:
                payload = vtscan.json.dumps({"text": m}, ensure_ascii=False)
                webview.windows[0].evaluate_js(f"window.onLog && window.onLog({payload})")
            except Exception:
                pass

        def worker() -> None:
            from engines import provision_clamav
            ok = provision_clamav(log=_log)
            _log("ГОТОВО — перезапустите приложение." if ok else "Не удалось установить ClamAV.")

        threading.Thread(target=worker, daemon=True).start()
        return {"ok": True}

    # --- самопроверка уведомлений ---
    def selftest(self) -> dict:
        import monitor as monitor_mod

        def open_app():
            try:
                webview.windows[0].restore()
            except Exception:
                pass

        monitor_mod.toast("Подозрительный процесс (тест)",
                          r"C:\Users\you\Downloads\suspicious.exe", on_click=open_app)
        demo = data_dir() / "selftest-sample.txt"
        dest = None
        try:
            demo.write_text("Тестовый файл VTScan для проверки карантина.", encoding="utf-8")
            dest = monitor_mod.quarantine_file(demo)
        except OSError:
            pass
        monitor_mod.toast("Файл помещён в карантин (тест)",
                          str(dest) if dest else "selftest-sample.txt", on_click=open_app)
        return {"ok": True, "quarantine": str(dest) if dest else ""}

    # --- создать тест-файлы EICAR ---
    def make_eicar(self) -> dict:
        folder = Path.home() / "Desktop" / "VTScan-test"
        files = vtscan.make_eicar_samples(folder)
        return {"ok": bool(files), "folder": str(folder), "files": [f.name for f in files]}

    # --- доп. источники проверки ---
    def keys_list(self) -> list:
        import sources
        return sources.source_catalog()

    def keys_set(self, sid: str, key: str) -> dict:
        import sources
        sources.save_key(sid.lower(), key)
        return {"ok": True, "message": f"Ключ для {sid} сохранён."}

    # --- карантин ---
    def quarantine_list(self) -> list:
        import monitor as monitor_mod
        return monitor_mod.list_quarantine()

    def quarantine_restore(self, item_id: str) -> dict:
        import monitor as monitor_mod
        return monitor_mod.restore_quarantine(item_id)

    def quarantine_delete(self, item_id: str) -> dict:
        import monitor as monitor_mod
        return monitor_mod.delete_quarantine(item_id)

    def quarantine_allow(self, item_id: str) -> dict:
        import monitor as monitor_mod
        return monitor_mod.allow_quarantine(item_id)

    # --- заморозка подозрительных (анти-шифровальщик) ---
    def act_freeze(self) -> dict:
        import monitor as monitor_mod
        frozen = monitor_mod.freeze_suspicious_processes()
        return {"ok": True, "message": (f"Заморожено: {', '.join(frozen[:3])}" if frozen
                                        else "Подозрительных процессов не найдено.")}

    # --- тестовые имитации (для проверки) ---
    def _open_window(self):
        """Показать и развернуть окно (в т.ч. если оно свёрнуто в трей)."""
        try:
            w = webview.windows[0]
            try:
                w.show()
            except Exception:
                pass
            w.restore()
        except Exception:
            pass

    def _restore_window(self):
        self._open_window()

    def _threat_notify(self, ev):
        """Показывает системное уведомление; клик по нему открывает окно И выводит
        блок решения (кнопки) по этой угрозе — чтобы можно было сразу реагировать."""
        import monitor as monitor_mod

        def open_app(_ev=ev):
            self._open_window()
            try:
                payload = vtscan.json.dumps(
                    {"title": _ev.title, "detail": _ev.detail, "severity": _ev.severity,
                     "kind": _ev.kind, "pid": _ev.pid, "path": _ev.path}, ensure_ascii=False)
                webview.windows[0].evaluate_js(
                    f"window.onThreatFocus && window.onThreatFocus({payload})")
            except Exception:
                pass

        monitor_mod.toast(ev.title, ev.detail, on_click=open_app)

    def _emit_to_ui(self, ev):
        try:
            payload = vtscan.json.dumps(
                {"title": ev.title, "detail": ev.detail, "severity": ev.severity,
                 "kind": ev.kind, "pid": ev.pid, "path": ev.path}, ensure_ascii=False)
            webview.windows[0].evaluate_js(f"window.onMonitorEvent && window.onMonitorEvent({payload})")
        except Exception:
            pass

    def test_ransomware(self) -> dict:
        import monitor as monitor_mod
        ev = monitor_mod.Event("ransomware", "ТЕСТ: ВОЗМОЖЕН ШИФРОВАЛЬЩИК (имитация)",
                               "реальной угрозы нет — это проверка приманок", severity="danger")
        self._emit_to_ui(ev)
        self._threat_notify(ev)   # клик по уведомлению покажет блок решения
        return {"ok": True}

    def test_autostart(self) -> dict:
        import monitor as monitor_mod
        ev = monitor_mod.Event("autostart", "ТЕСТ: Новое в автозагрузке (имитация)",
                               r"C:\Users\you\AppData\evil.exe", severity="warn")
        self._emit_to_ui(ev)
        monitor_mod.toast(ev.title, ev.detail, on_click=self._restore_window)
        return {"ok": True}

    # --- выход ---
    def quit(self) -> None:
        try:
            webview.windows[0].destroy()
        except Exception:
            pass


HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<style>
  :root {
    --bg:#0a0f1e; --txt:#aebbd6; --bright:#d7e3fb; --dim:#56678a;
    --cyan:#36d3ff; --green:#43e08a; --red:#ff5d6c; --amber:#ffb454;
  }
  * { box-sizing:border-box; }
  html,body { margin:0; height:100%; background:var(--bg); }
  body { font-family:"Cascadia Mono","Consolas","Menlo",monospace; color:var(--txt);
         font-size:15px; line-height:1.55; height:100vh; overflow:hidden;
         display:flex; flex-direction:column; }
  #topbar { display:flex; align-items:center; gap:10px; padding:6px 12px; background:#0d1428;
            border-bottom:1px solid #1d2c4a; flex:0 0 auto; }
  .brand { color:#7fb6ff; letter-spacing:2px; font-size:12px; }
  .spacer { flex:1; }
  .topbtn { background:#11203c; border:1px solid #1d2c4a; color:var(--cyan); cursor:pointer;
            padding:4px 14px; border-radius:6px; font-family:inherit; font-size:13px; }
  .topbtn:hover { background:#16294a; border-color:var(--cyan); color:#7fe6ff; }
  #screen { flex:1 1 auto; min-height:0; overflow-y:auto; padding:14px 16px;
            white-space:pre-wrap; word-break:break-word; cursor:text;
            user-select:text; -webkit-user-select:text; }
  #out { user-select:text; -webkit-user-select:text; }
  #qoverlay { display:none; position:fixed; inset:0; background:rgba(4,8,18,.72);
              align-items:center; justify-content:center; z-index:10; }
  #qpanel { width:84%; max-width:680px; max-height:80%; background:#0a0f1e;
            border:1px solid #1d2c4a; border-radius:10px; display:flex; flex-direction:column;
            overflow:hidden; }
  #qhead { display:flex; justify-content:space-between; align-items:center; padding:10px 14px;
           background:#0d1428; border-bottom:1px solid #1d2c4a; color:var(--bright); }
  #qclose { cursor:pointer; color:var(--dim); }
  #qclose:hover { color:var(--red); }
  #qlist { padding:8px 14px; overflow-y:auto; }
  .qrow { display:flex; justify-content:space-between; align-items:center; gap:12px;
          padding:9px 0; border-bottom:1px solid #11203c; }
  #screen::-webkit-scrollbar { width:12px; }
  #screen::-webkit-scrollbar-track { background:#070b16; }
  #screen::-webkit-scrollbar-thumb { background:#1d2c4a; border:3px solid #070b16; border-radius:8px; }
  #screen::-webkit-scrollbar-thumb:hover { background:#36d3ff; }
  #screen { scrollbar-width:thin; scrollbar-color:#1d2c4a #070b16; }
  .cmdline { display:flex; align-items:baseline; }
  .inputwrap { position:relative; flex:1; margin-left:6px; }
  #cmd { width:100%; background:transparent; border:none; outline:none; color:var(--bright);
         font-family:inherit; font-size:inherit; line-height:inherit; padding:0; }
  #ghost { position:absolute; left:0; top:0; pointer-events:none; white-space:pre;
           font-family:inherit; font-size:inherit; line-height:inherit; }
  .c-cyan{color:var(--cyan);} .c-green{color:var(--green);} .c-red{color:var(--red);}
  .c-amber{color:var(--amber);} .c-dim{color:var(--dim);} .c-bright{color:var(--bright);}
  .b{font-weight:bold;}
  .cmd-link{ color:var(--cyan); cursor:pointer; border-radius:3px; padding:0 3px; }
  .cmd-link:hover{ background:#11203c; color:#7fe6ff; }
  .act-btn{ display:inline-block; margin-right:8px; padding:2px 10px; border:1px solid #1d2c4a;
            border-radius:6px; color:var(--cyan); cursor:pointer; font-size:13px; }
  .act-btn:hover{ background:#11203c; border-color:var(--cyan); color:#7fe6ff; }
  .url{ color:var(--cyan); cursor:pointer; text-decoration:underline; }
  .url:hover{ color:#7fe6ff; }
  #ctxmenu{ display:none; position:fixed; z-index:20; background:#0d1428;
            border:1px solid #1d2c4a; border-radius:6px; padding:4px;
            box-shadow:0 4px 16px rgba(0,0,0,.5); user-select:none; -webkit-user-select:none; }
  #ctxmenu div{ padding:5px 16px; color:var(--txt); cursor:pointer; border-radius:4px; font-size:13px; }
  #ctxmenu div:hover{ background:#16294a; color:#7fe6ff; }
  #drophint{ display:none; position:fixed; inset:0; z-index:30; background:rgba(4,8,18,.82);
             align-items:center; justify-content:center; }
  #dropbox{ border:2px dashed var(--cyan); border-radius:14px; padding:42px 64px;
            color:var(--cyan); font-size:20px; text-align:center; line-height:1.8;
            background:rgba(17,32,60,.6); }
</style>
</head>
<body>
  <div id="topbar"><span class="brand">V T S C A N</span><div class="spacer"></div><button class="topbtn" id="guardbtn" onclick="toggleGuard()"><span class="c-dim">●</span> Защита: …</button><button class="topbtn" onclick="openQuarantine()">Карантин</button></div>
  <div id="screen" onclick="focusCmd()">
    <div id="out"></div>
    <div class="cmdline"><span id="prompt" class="c-green"></span><span class="inputwrap"><input id="cmd" autocomplete="off" spellcheck="false" autofocus><span id="ghost"></span></span></div>
  </div>
  <div id="qoverlay">
    <div id="qpanel">
      <div id="qhead"><span>Карантин</span><span id="qclose" onclick="closeQuarantine()">&#10005;</span></div>
      <div id="qlist"></div>
    </div>
  </div>
  <div id="ctxmenu"><div id="ctxcopy">Копировать</div></div>
  <div id="drophint"><div id="dropbox">⤓<br>Отпустите файл, чтобы проверить</div></div>

<script>
  const out = document.getElementById('out');
  const screen = document.getElementById('screen');
  const cmd = document.getElementById('cmd');
  const promptEl = document.getElementById('prompt');
  const ghost = document.getElementById('ghost');
  const COMMANDS = ['scan','quickscan','fullscan','memscan','monitor','autostart','quarantine','keys','key','clear','help','exit','setup-clamav','make-eicar','selftest','test-ransomware','test-autostart','check-update','cd','version','where'];
  // Подсказки второго слова для команд с под-аргументами.
  const SUBARGS = { help:['advanced','test'], autostart:['on','off'], scan:['memory'] };
  function updateGhost(){
    const v = cmd.value;
    if(keyMode || !v){ ghost.innerHTML=''; ghost.dataset.full=''; return; }
    const sp = v.indexOf(' ');
    let m = null;
    if(sp < 0){
      const low = v.toLowerCase();
      const c = COMMANDS.find(c => c.indexOf(low)===0 && c !== low);
      if(c) m = c;
    } else {
      // второе слово: подсказываем суб-аргумент известной команды
      const cmd0 = v.slice(0, sp).toLowerCase();
      const rest = v.slice(sp + 1);
      if(rest.indexOf(' ') < 0 && SUBARGS[cmd0]){
        const low = rest.toLowerCase();
        const sub = SUBARGS[cmd0].find(a => a.indexOf(low)===0 && a !== low);
        if(sub) m = v.slice(0, sp + 1) + sub;   // полная строка «команда суб-арг»
      }
    }
    if(m){ ghost.innerHTML='<span style="color:transparent">'+esc(v)+'</span><span class="c-dim">'+esc(m.slice(v.length))+'</span>'; ghost.dataset.full=m; }
    else { ghost.innerHTML=''; ghost.dataset.full=''; }
  }
  let cwd = 'C:\\';
  let keyMode = false;
  const history = []; let hi = -1;

  function esc(s){return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  // Превращает ссылки в кликабельные (открываются в системном браузере).
  function linkify(html){ return html.replace(/(https?:\/\/[^\s<>"']+)/g, '<span class="url" data-url="$1">$1</span>'); }
  function print(html){ const d=document.createElement('div'); d.innerHTML=linkify(html); out.appendChild(d); screen.scrollTop=screen.scrollHeight; }
  // Не воровать фокус в поле ввода, если пользователь выделяет текст для копирования.
  function focusCmd(){ const sel=window.getSelection&&window.getSelection().toString(); if(sel) return; cmd.focus(); }
  function setPrompt(){ promptEl.textContent = keyMode ? 'ключ> ' : ('vtscan '+cwd+'> '); }

  const MARK={malicious:'<span class="c-red">●</span>',suspicious:'<span class="c-amber">●</span>',clean:'<span class="c-green">●</span>',unknown:'<span class="c-dim">○</span>',skipped:'<span class="c-dim">○</span>',error:'<span class="c-dim">x</span>',unavailable:'<span class="c-dim">·</span>'};
  const VCLS={malicious:'c-red',suspicious:'c-amber',clean:'c-green',unknown:'c-dim',skipped:'c-dim',error:'c-red'};
  const ICON={malicious:'[!]',suspicious:'[?]',clean:'[+]',unknown:'[ ]',skipped:'[-]',error:'[x]'};

  function renderResult(r){
    if(r.error==='no_key'){ print('<span class="c-amber">Нет ключа. Введите команду </span><span class="b">key</span><span class="c-amber"> и вставьте ключ VirusTotal.</span>'); return; }
    if(r.error==='not_found'){ print('<span class="c-red">Файл не найден: '+esc(r.name)+'</span>'); return; }
    if(r.error){ print('<span class="c-red">Ошибка: '+esc(r.message||r.error)+'</span>'); return; }
    const cls=VCLS[r.status]||'c-dim';
    let s='<span class="'+cls+' b">'+(ICON[r.status]||'[ ]')+' '+esc(r.verdict)+'</span>   <span class="c-bright">'+esc(r.name)+'</span>\n';
    if(r.threat_type) s+='      <span class="c-dim">тип угрозы:</span> <span class="c-amber">'+esc(r.threat_type)+'</span>\n';
    if(r.threat_others&&r.threat_others.length) s+='        <span class="c-dim">также: '+esc(r.threat_others.join(', '))+'</span>\n';
    if(r.family) s+='      <span class="c-dim">семейство:</span> <span class="c-amber">'+esc(r.family)+'</span>\n';
    (r.engines||[]).forEach((e,i,a)=>{ const br=(i===a.length-1)?'└':'├'; s+='      <span class="c-dim">'+br+'</span> '+esc((e.engine+'             ').slice(0,13))+(MARK[e.status]||'○')+' <span class="c-dim">'+esc(e.detail)+'</span>\n'; });
    if(r.message&&['unknown','skipped','error'].includes(r.status)) s+='      <span class="c-dim">'+esc(r.message)+'</span>\n';
    s+='      <span class="c-dim">sha256: '+esc(r.sha256)+'</span>';
    print(s);
    // Опасный/подозрительный файл → сразу предлагаем действия.
    if((r.status==='malicious'||r.status==='suspicious') && r.path){
      print('      '+actBtn('В карантин','quarantine',r.path)+actBtn('Устранить','delete',r.path)+actBtn('Пропустить','ignore',''));
    }
  }

  const HELP_BASIC=[['scan [путь]','проверить файл; без пути — выбор файла','scan '],['quickscan','быстрый скан опасных папок (ClamAV)','quickscan'],['fullscan','полный скан профиля (ClamAV)','fullscan'],['memscan','скан памяти (запущенные процессы)','memscan'],['monitor','вкл/выкл фоновую защиту','monitor'],['quarantine','список карантина (или кнопка вверху)','quarantine'],['key','ввести/обновить ключ VirusTotal','key'],['clear','очистить экран','clear'],['help','команды','help'],['exit','закрыть','exit']];
  const HELP_ADV=[['keys','доп. источники и их ключи','keys'],['autostart','запуск защиты с Windows (on/off)','autostart'],['where','показать папку приложения','where'],['setup-clamav','скачать офлайн-движок ClamAV','setup-clamav'],['make-eicar','создать безвредные тест-файлы','make-eicar'],['selftest','проверка уведомлений (имитация)','selftest'],['check-update','проверить обновления','check-update'],['cd <путь>','сменить текущую папку','cd '],['version','версия','version']];
  const HELP_TEST=[['selftest','имитация уведомления + тестовый карантин','selftest'],['make-eicar','создать безвредные тест-файлы (детект)','make-eicar'],['test-ransomware','имитация приманки-шифровальщика','test-ransomware'],['test-autostart','имитация алерта автозагрузки','test-autostart']];
  function printHelp(tier){
    const rows = tier==='advanced'?HELP_ADV : tier==='test'?HELP_TEST : HELP_BASIC;
    const title = tier==='advanced'?'Продвинутые команды:' : tier==='test'?'Тестовые команды:' : 'Команды:';
    let s='<span class="b">'+title+'</span>\n';
    rows.forEach(([c,d,ins])=>{ s+='  <span class="cmd-link" data-cmd="'+esc(ins)+'">'+esc((c+'                ').slice(0,16))+'</span><span class="c-dim">'+esc(d)+'</span>\n'; });
    if(tier!=='advanced' && tier!=='test') s+='  <span class="c-dim">ещё: </span><span class="cmd-link" data-cmd="help advanced">help advanced</span><span class="c-dim"> · </span><span class="cmd-link" data-cmd="help test">help test</span>\n';
    print(s);
  }

  function actBtn(label,act,arg){ return '<span class="act-btn" data-act="'+act+'" data-arg="'+esc(arg)+'">'+esc(label)+'</span>'; }
  window.onMonitorEvent = function(ev){
    const cls={info:'c-dim',warn:'c-amber',danger:'c-red'}[ev.severity]||'c-dim';
    let html='<span class="'+cls+'">[защита] '+esc(ev.title)+(ev.detail?': '+esc(ev.detail):'')+'</span>';
    if(ev.kind==='threat-file' && ev.path){ html+='<br>      '+actBtn('В карантин','quarantine',ev.path)+actBtn('Устранить','delete',ev.path)+actBtn('Пропустить','ignore',''); }
    else if(ev.kind==='process' && ev.pid){ html+='<br>      '+actBtn('Остановить','suspend',''+ev.pid)+actBtn('Завершить','kill',''+ev.pid)+actBtn('Пропустить','ignore',''); }
    else if(ev.kind==='ransomware'){ html+='<br>      '+actBtn('Заморозить подозрительные','freeze','')+actBtn('Пропустить','ignore',''); }
    print(html);
  };
  // Клик по системному уведомлению → просто открыть окно и промотать к сообщению об
  // угрозе (оно уже есть в ленте с кнопками). Копию НЕ создаём.
  window.onThreatFocus = function(ev){
    screen.scrollTop=screen.scrollHeight;
    // Подсветим последнее сообщение, чтобы его было видно.
    const last=out.lastElementChild;
    if(last){ last.style.transition='background .2s'; last.style.background='#16294a';
              setTimeout(()=>{ last.style.background=''; }, 1200); }
    focusCmd();
  };
  window.onLog = function(o){ print('<span class="c-dim">'+esc(o.text)+'</span>'); };

  // --- индикатор «Защита» в шапке ---
  function updateGuardUI(on){
    const b=document.getElementById('guardbtn'); if(!b) return;
    b.innerHTML = on ? '<span class="c-green">●</span> Защита: ВКЛ' : '<span class="c-dim">●</span> Защита: ВЫКЛ';
    b.style.borderColor = on ? 'var(--green)' : '#1d2c4a';
  }
  window.onGuardState = function(o){ updateGuardUI(!!o.on); };
  async function toggleGuard(){
    const r=await window.pywebview.api.monitor_toggle();
    updateGuardUI(!!r.on);
    if(r.on) print('<span class="c-green">Фоновая защита ВКЛЮЧЕНА.</span>');
    else print(r.message?'<span class="c-amber">'+esc(r.message)+'</span>':'<span class="c-dim">Фоновая защита выключена.</span>');
    focusCmd();
  }

  // --- прогресс/итог скана компьютера ---
  let scanStatusEl=null;
  window.onScanStart = function(o){
    if(!scanStatusEl){ scanStatusEl=document.createElement('div'); out.appendChild(scanStatusEl); }
    scanStatusEl.innerHTML='<span class="c-cyan">› скан…</span> <span class="c-dim">всего файлов: ~'+(o.total||0)+'</span>';
    screen.scrollTop=screen.scrollHeight;
  };
  window.onScanProgress = function(o){
    if(!scanStatusEl){ scanStatusEl=document.createElement('div'); out.appendChild(scanStatusEl); }
    const p=o.path||''; const short=p.length>56?'…'+p.slice(-55):p;
    const total=o.total||0, n=o.scanned||0;
    let s='<span class="c-cyan">› скан…</span> ';
    if(total>0){
      const pct=Math.min(100, Math.round(n*100/total)), left=Math.max(0,total-n);
      const fill=Math.round(pct/5); const bar='█'.repeat(fill)+'░'.repeat(20-fill);
      s+='<span class="c-green">['+bar+'] '+pct+'%</span> <span class="c-dim">проверено '+n+' из ~'+total+' (осталось ~'+left+')</span>';
    } else {
      s+='<span class="c-dim">проверено '+n+'</span>';
    }
    s+='<br>      <span class="c-dim">'+esc(short)+'</span>';
    scanStatusEl.innerHTML=s;
    screen.scrollTop=screen.scrollHeight;
  };
  window.onScanDone = function(res){
    scanStatusEl=null;
    if(res.error){ print('<span class="c-red">Ошибка скана: '+esc(res.error)+'</span>'); return; }
    const inf=res.infected||[];
    const head=res.stopped?'Скан прерван.':'Скан завершён.';
    print('<span class="'+(inf.length?'c-red b':'c-green')+'">'+head+' Проверено: '+res.scanned+', заражённых: '+inf.length+'</span>');
    inf.forEach(it=>{
      let html='<span class="c-red">[!] '+esc(it.name)+'</span> <span class="c-dim">'+esc(it.path)+'</span>';
      html+='<br>      '+actBtn('В карантин','quarantine',it.path)+actBtn('Устранить','delete',it.path)+actBtn('Пропустить','ignore','');
      print(html);
    });
    if(inf.length) print('<span class="c-dim">Совет: помести заражённые в карантин (обратимо) или удали.</span>');
  };

  // --- скан памяти (процессы) ---
  let memStatusEl=null;
  window.onMemProgress = function(o){
    if(!memStatusEl){ memStatusEl=document.createElement('div'); out.appendChild(memStatusEl); }
    const total=o.total||0, n=o.checked||0;
    let s='<span class="c-cyan">› скан памяти…</span> ';
    if(total>0){ const pct=Math.min(100,Math.round(n*100/total)); s+='<span class="c-dim">процессов '+n+' из '+total+' ('+pct+'%)  '+esc(o.name||'')+'</span>'; }
    else s+='<span class="c-dim">процессов '+n+'</span>';
    memStatusEl.innerHTML=s; screen.scrollTop=screen.scrollHeight;
  };
  window.onMemDone = function(res){
    memStatusEl=null;
    if(res.error){ print('<span class="c-red">Ошибка скана памяти: '+esc(res.error)+'</span>'); return; }
    const f=res.findings||[];
    const head=res.stopped?'Скан памяти прерван.':'Скан памяти завершён.';
    print('<span class="'+(f.length?'c-red b':'c-green')+'">'+head+' Проверено процессов: '+res.checked+', подозрительных: '+f.length+'</span>');
    if(!f.length){ print('<span class="c-dim">Подозрительных процессов не найдено.</span>'); return; }
    f.forEach(it=>{
      const cls=it.status==='malicious'?'c-red':'c-amber'; const mark=it.status==='malicious'?'[!]':'[?]';
      let html='<span class="'+cls+'">'+mark+' '+esc(it.name)+'</span> <span class="c-dim">(pid '+it.pid+') — '+esc(it.reason)+'</span>';
      if(it.exe) html+='<br>      <span class="c-dim">'+esc(it.exe)+'</span>';
      html+='<br>      '+actBtn('Остановить','suspend',''+it.pid)+actBtn('Завершить','kill',''+it.pid)+actBtn('Пропустить','ignore','');
      print(html);
    });
    print('<span class="c-dim">«Остановить» = заморозка (обратимо), «Завершить» = закрыть процесс. Скрытые руткитом процессы из user-mode не видны — это этап 4 (драйвер).</span>');
  };

  async function openQuarantine(){
    const items=await window.pywebview.api.quarantine_list();
    const el=document.getElementById('qlist');
    if(!items.length){ el.innerHTML='<div class="c-dim" style="padding:8px 0">Карантин пуст.</div>'; }
    else { el.innerHTML=items.map(qrow).join(''); }
    document.getElementById('qoverlay').style.display='flex';
  }
  function qrow(it){ return '<div class="qrow"><div style="overflow:hidden"><span class="c-amber">'+esc(it.name)+'</span><br><span class="c-dim" style="font-size:12px">'+esc(it.original||'')+'  ·  '+esc(it.ts||'')+'</span></div><div style="white-space:nowrap"><span class="act-btn" data-q="restore" data-id="'+esc(it.id)+'">Восстановить</span><span class="act-btn" data-q="allow" data-id="'+esc(it.id)+'">Разрешить</span><span class="act-btn" data-q="delete" data-id="'+esc(it.id)+'">Удалить</span></div></div>'; }
  function closeQuarantine(){ document.getElementById('qoverlay').style.display='none'; focusCmd(); }
  document.getElementById('qlist').addEventListener('click', async e=>{
    const b=e.target.closest('[data-q]'); if(!b) return;
    const id=b.dataset.id, q=b.dataset.q;
    const r = q==='restore' ? await window.pywebview.api.quarantine_restore(id)
            : q==='allow'   ? await window.pywebview.api.quarantine_allow(id)
                            : await window.pywebview.api.quarantine_delete(id);
    print('<span class="'+(r.ok?'c-green':'c-red')+'">[карантин] '+esc(r.message)+'</span>');
    openQuarantine();
  });
  document.addEventListener('keydown', e=>{ if(e.key==='Escape'){ closeQuarantine(); hideCtx(); } });

  // --- контекстное меню «Копировать» по правому клику (pywebview прячет системное) ---
  const ctxmenu=document.getElementById('ctxmenu');
  function hideCtx(){ ctxmenu.style.display='none'; }
  function selText(){ return window.getSelection ? window.getSelection().toString() : ''; }
  document.addEventListener('contextmenu', e=>{
    if(!selText()){ hideCtx(); return; }          // нет выделения — меню не показываем
    e.preventDefault();
    ctxmenu.style.display='block';
    const mw=ctxmenu.offsetWidth||130, mh=ctxmenu.offsetHeight||34;
    // Меню «вверх-вправо»: нижний-левый угол у кончика курсора (как в Windows).
    let x=e.clientX, y=e.clientY-mh;
    if(x+mw>window.innerWidth) x=window.innerWidth-mw-4;
    if(y<0) y=e.clientY;                       // если сверху не помещается — показать вниз
    ctxmenu.style.left=x+'px'; ctxmenu.style.top=y+'px';
  });
  ctxmenu.addEventListener('mousedown', e=>e.preventDefault());  // не сбрасывать выделение
  document.getElementById('ctxcopy').addEventListener('click', ()=>{
    const sel=selText();
    let ok=false;
    try{ ok=document.execCommand('copy'); }catch(_){}
    if(!ok && sel && navigator.clipboard){ navigator.clipboard.writeText(sel).catch(()=>{}); }
    hideCtx();
  });
  document.addEventListener('click', hideCtx);
  window.addEventListener('blur', hideCtx);

  // --- drag-and-drop файла в окно (путь подставляет pywebview на стороне Python) ---
  const drophint=document.getElementById('drophint');
  let dragDepth=0;
  window.addEventListener('dragenter', e=>{ e.preventDefault(); dragDepth++; drophint.style.display='flex'; });
  window.addEventListener('dragover', e=>{ e.preventDefault(); });
  window.addEventListener('dragleave', e=>{ dragDepth=Math.max(0,dragDepth-1); if(!dragDepth) drophint.style.display='none'; });
  window.addEventListener('drop', e=>{ e.preventDefault(); dragDepth=0; drophint.style.display='none'; });
  window.onDropStart = function(o){ print('<span class="c-dim">› перетянут файл: '+esc(o.name)+' — проверяю источники...</span>'); };
  window.onDropResult = function(r){ renderResult(r); };

  async function dispatch(raw){
    const line=raw.trim();
    print('<span class="c-green">'+esc(cwd)+'></span> '+esc(line));   // эхо команды
    if(keyMode){
      keyMode=false; setPrompt();
      const ok=await window.pywebview.api.save_key(line);
      print(ok?'<span class="c-green">Ключ сохранён.</span>':'<span class="c-red">Пустой ключ.</span>');
      return;
    }
    if(!line) return;
    const parts=line.split(/\s+/); const c=parts[0].toLowerCase(); const rest=parts.slice(1);
    if(c==='help'||c==='?'){ const a=rest[0]; printHelp((a==='advanced'||a==='adv'||a==='настройки')?'advanced':((a==='test'||a==='тест')?'test':'basic')); }
    else if(c==='test-ransomware'){ await window.pywebview.api.test_ransomware(); }
    else if(c==='test-autostart'){ await window.pywebview.api.test_autostart(); }
    else if(c==='clear'||c==='cls'){ out.innerHTML=''; }
    else if(c==='version'||c==='ver'){ const i=await window.pywebview.api.app_info(); print('vtscan '+esc(i.version)); }
    else if(c==='where'||c==='folder'){ const i=await window.pywebview.api.app_info(); print('<span class="c-dim">Папка данных (ключ, ClamAV, карантин):</span>\n  <span class="c-cyan">'+esc(i.data_dir)+'</span>'); }
    else if(c==='quarantine'||c==='карантин'){ openQuarantine(); }
    else if(c==='keys'){
      if(rest.length>=2){ const r=await window.pywebview.api.keys_set(rest[0], rest.slice(1).join(' ')); print('<span class="c-green">'+esc(r.message)+'</span>'); }
      else { const items=await window.pywebview.api.keys_list(); let s='<span class="b">Доп. источники проверки (ключ бесплатный):</span>\n'; items.forEach(it=>{ s+='  <span class="c-cyan">'+esc((it.id+'              ').slice(0,14))+'</span>'+esc(it.name)+'  '+(it.has_key?'<span class="c-green">есть ключ</span>':'<span class="c-dim">нет ключа</span>')+'\n    <span class="c-dim">'+esc(it.signup)+'</span>\n'; }); s+='  <span class="c-dim">Добавить:</span> keys &lt;id&gt; &lt;ключ&gt;'; print(s); }
    }
    else if(c==='exit'||c==='quit'){ window.pywebview.api.quit(); }
    else if(c==='key'){ keyMode=true; setPrompt(); print('<span class="c-amber">Вставьте ключ VirusTotal и нажмите Enter (получить бесплатно: </span>https://www.virustotal.com/gui/join-us<span class="c-amber">):</span>'); }
    else if(c==='cd'){ if(!rest.length){ print('<span class="c-dim">'+esc(cwd)+'</span>'); } else { const r=await window.pywebview.api.set_cwd(rest.join(' ')); if(r.ok){ cwd=r.cwd; setPrompt(); } else print('<span class="c-red">'+esc(r.error)+'</span>'); } }
    else if(c==='check-update'||c==='update'){ print('<span class="c-dim">Проверяю обновления...</span>'); const r=await window.pywebview.api.check_update(); if(r.newer){ print('<span class="c-amber">'+esc(r.message)+'</span><br>      <span class="c-bright">Скачать и установить новую версию?</span>  '+actBtn('Да','update','')+actBtn('Нет','ignore','')); } else print('<span class="c-green">'+esc(r.message)+'</span>'); }
    else if(c==='monitor'||c==='guard'){
      const r=await window.pywebview.api.monitor_toggle();
      updateGuardUI(!!r.on);
      if(r.on) print('<span class="c-green">Фоновая защита ВКЛЮЧЕНА.</span> <span class="c-dim">(monitor ещё раз — выключить)</span>');
      else print(r.message?'<span class="c-amber">'+esc(r.message)+'</span>':'<span class="c-dim">Фоновая защита выключена.</span>');
    }
    else if(c==='autostart'){
      const a=(rest[0]||'').toLowerCase();
      if(a==='on'||a==='off'){ const r=await window.pywebview.api.autostart_set(a==='on'); print('<span class="'+(r.enabled?'c-green':'c-dim')+'">Автозапуск с Windows '+(r.enabled?'включён':'выключен')+'.</span>'); }
      else { const r=await window.pywebview.api.autostart_status(); print('<span class="c-dim">Автозапуск с Windows: </span>'+(r.enabled?'<span class="c-green">включён</span>':'<span class="c-dim">выключен</span>')+'<br><span class="c-dim">Команды: </span><span class="cmd-link" data-cmd="autostart on">autostart on</span><span class="c-dim"> · </span><span class="cmd-link" data-cmd="autostart off">autostart off</span>'); }
    }
    else if(c==='setup-clamav'||c==='install-clamav'){
      print('<span class="c-dim">Запускаю загрузчик ClamAV (это надолго: ~300+ МБ)...</span>');
      const r=await window.pywebview.api.setup_clamav();
      if(!r.ok) print('<span class="c-amber">'+esc(r.message)+'</span>');
    }
    else if(c==='selftest'||c==='test'){
      print('<span class="c-dim">Самопроверка: сейчас всплывут 2 уведомления справа...</span>');
      const r=await window.pywebview.api.selftest();
      print('<span class="c-green">Готово.</span> <span class="c-dim">Если уведомления появились — всё работает.'+(r.quarantine?' Тестовый файл в карантине: '+esc(r.quarantine):'')+'</span>');
    }
    else if(c==='make-eicar'||c==='maketest'){
      const r=await window.pywebview.api.make_eicar();
      if(r.ok){ print('<span class="c-green">Создано '+r.files.length+' тест-файлов (EICAR):</span> <span class="c-dim">'+esc(r.folder)+'</span>'); print('<span class="c-amber">Безвредные, но детектятся всеми АВ. Проверь: scan '+esc(r.folder)+'</span>'); }
      else print('<span class="c-red">Не удалось создать тест-файлы.</span>');
    }
    else if(c==='quickscan'||c==='fullscan'||c==='scan-pc'){
      const mode=(c==='fullscan')?'full':'quick';
      const r=await window.pywebview.api.scan_computer(mode);
      if(r.need_clamav){ print('<span class="c-amber">Для скана компьютера нужен офлайн-движок ClamAV (VirusTotal не годится — лимит запросов).</span><br><span class="c-dim">Установить: </span><span class="cmd-link" data-cmd="setup-clamav">setup-clamav</span>'); }
      else if(!r.ok){ print('<span class="c-amber">'+esc(r.message||'не удалось запустить скан')+'</span>'); }
      else { print('<span class="c-cyan">'+(mode==='full'?'Полный':'Быстрый')+' скан запущен.</span> <span class="c-dim">Папки: '+esc((r.dirs||[]).join(', '))+'</span>  '+actBtn('Прервать скан','scanstop','')); }
    }
    else if(c==='scan-stop'||c==='stopscan'){ await window.pywebview.api.scan_stop(); print('<span class="c-dim">Останавливаю скан…</span>'); }
    else if(c==='memscan' || (c==='scan' && rest[0] && ['memory','mem','память','процессы'].includes(rest[0].toLowerCase()))){
      const r=await window.pywebview.api.scan_memory();
      if(!r.ok){ print('<span class="c-amber">'+esc(r.message||'не удалось запустить')+'</span>'); }
      else { print('<span class="c-cyan">Скан памяти запущен.</span> '+(r.clamav?'<span class="c-dim">(эвристика + ClamAV)</span>':'<span class="c-dim">(только эвристика — ClamAV не установлен)</span>')+'  '+actBtn('Прервать','scanstop','')); }
    }
    else if(c==='scan'){
      let path=rest.join(' ');
      if(!path){ path=await window.pywebview.api.pick_file(); if(!path){ print('<span class="c-dim">Отменено.</span>'); return; } print('<span class="c-dim">выбран: '+esc(path)+'</span>'); }
      print('<span class="c-dim">› проверяю источники ...</span>');
      const r=await window.pywebview.api.scan(path);
      renderResult(r);
    }
    else { print('<span class="c-dim">Неизвестная команда. Введите </span><span class="b">help</span><span class="c-dim">.</span>'); }
  }

  cmd.addEventListener('keydown', async e=>{
    if(e.key==='Tab'){ e.preventDefault(); if(ghost.dataset.full){ cmd.value=ghost.dataset.full+' '; updateGhost(); } return; }
    if(e.key==='Enter'){ const v=cmd.value; cmd.value=''; updateGhost(); if(v.trim()&&!keyMode){ history.push(v); hi=history.length; } await dispatch(v); }
    else if(e.key==='ArrowUp'){ if(history.length){ hi=Math.max(0,hi-1); cmd.value=history[hi]||''; updateGhost(); e.preventDefault(); } }
    else if(e.key==='ArrowDown'){ if(history.length){ hi=Math.min(history.length,hi+1); cmd.value=history[hi]||''; updateGhost(); e.preventDefault(); } }
    else if(e.key==='ArrowRight'){ if(ghost.dataset.full && cmd.selectionStart===cmd.value.length){ cmd.value=ghost.dataset.full; updateGhost(); } }
  });
  cmd.addEventListener('input', updateGhost);

  window.addEventListener('pywebviewready', async ()=>{
    const i=await window.pywebview.api.app_info();
    cwd=i.cwd||'C:\\'; setPrompt();
    print('<span class="c-cyan b">VTSCAN</span> <span class="c-dim">// кибер-сканер файлов  v'+esc(i.version)+'</span>');
    print('<span class="c-dim">источники: '+esc(i.sources.join(' + '))+'</span>\n');
    printHelp('basic');
    const hk=await window.pywebview.api.has_key();
    if(!hk) print('<span class="c-amber">\nКлюч не задан. Введите </span><span class="b">key</span><span class="c-amber"> для настройки.</span>');
    try{ const g=await window.pywebview.api.monitor_status(); updateGuardUI(g.on); }catch(_){ updateGuardUI(false); }
    focusCmd();
  });
  out.addEventListener('click', async e=>{
    const url=e.target.closest('.url');
    if(url){ e.stopPropagation(); window.pywebview.api.open_url(url.dataset.url); return; }
    const link=e.target.closest('.cmd-link');
    if(link){ e.stopPropagation(); cmd.value=link.dataset.cmd; focusCmd(); return; }
    const b=e.target.closest('.act-btn');
    if(b){ e.stopPropagation();
      const act=b.dataset.act, arg=b.dataset.arg;
      b.parentElement.querySelectorAll('.act-btn').forEach(x=>x.style.opacity=.4);
      b.parentElement.querySelectorAll('.act-btn').forEach(x=>x.remove());
      if(act==='update'){ const u=await window.pywebview.api.do_update(); if(!u.ok) print('<span class="c-amber">→ '+esc(u.message)+'</span>'); return; }
      if(act==='scanstop'){ await window.pywebview.api.scan_stop(); print('<span class="c-dim">→ останавливаю скан…</span>'); return; }
      let r={ok:true,message:'Пропущено.'};
      if(act==='quarantine') r=await window.pywebview.api.act_quarantine(arg);
      else if(act==='delete') r=await window.pywebview.api.act_delete(arg);
      else if(act==='suspend') r=await window.pywebview.api.act_suspend(parseInt(arg));
      else if(act==='kill') r=await window.pywebview.api.act_kill(parseInt(arg));
      else if(act==='freeze') r=await window.pywebview.api.act_freeze();
      print('<span class="'+(r.ok?'c-green':'c-red')+'">→ '+esc(r.message||'готово')+'</span>');
    }
  });
  document.addEventListener('click', focusCmd);
</script>
</body>
</html>
"""


def _scan_dropped(api: "Api", path: str) -> None:
    """Сканирует перетащенный в окно файл и выводит результат (в отдельном потоке)."""
    def push(js: str) -> None:
        try:
            webview.windows[0].evaluate_js(js)
        except Exception:
            pass
    name = os.path.basename(path)
    push(f"window.onDropStart && window.onDropStart("
         f"{vtscan.json.dumps({'name': name}, ensure_ascii=False)})")
    res = api.scan(path)
    push(f"window.onDropResult && window.onDropResult("
         f"{vtscan.json.dumps(res, ensure_ascii=False)})")


def _wire_dnd(api: "Api", window) -> None:
    """Вешает обработчик drop на body. pywebview сам подставляет реальный путь файла
    (pywebviewFullPath) — обычный браузер путь к локальному файлу не отдаёт."""
    def on_drop(e):
        try:
            files = (e.get("dataTransfer") or {}).get("files") or []
        except AttributeError:
            files = []
        for f in files:
            p = f.get("pywebviewFullPath")
            if p:
                threading.Thread(target=_scan_dropped, args=(api, p), daemon=True).start()
    try:
        window.dom.body.events.drop += on_drop
    except Exception:
        pass


def _tray_image():
    """Значок щита для трея — рисуем через Pillow, без внешнего файла-ресурса."""
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(32, 6), (56, 16), (56, 34), (32, 60), (8, 34), (8, 16)],
              fill=(13, 20, 40, 255), outline=(54, 211, 255, 255))
    d.line([(22, 32), (30, 42), (44, 22)], fill=(67, 224, 138, 255), width=5)
    return img


_tray_icon = None


def _start_tray(api: "Api", window, state: dict) -> None:
    """Иконка в системном трее + меню. Запускается в отдельном потоке после
    старта GUI (webview.start). Если pystray недоступен — тихо выходим, а при
    скрытом старте всё же показываем окно (иначе к нему не будет доступа)."""
    global _tray_icon
    try:
        import pystray
    except Exception:
        if state.get("hidden"):
            try:
                window.show()
            except Exception:
                pass
        return
    state["tray"] = True

    def do_open(icon=None, item=None):
        try:
            window.show()
            window.restore()
        except Exception:
            pass

    def do_toggle_protection(icon=None, item=None):
        api.monitor_toggle()
        if _tray_icon is not None:
            _tray_icon.update_menu()

    def do_toggle_autostart(icon=None, item=None):
        api.autostart_set(not vtscan.autostart_enabled())
        if _tray_icon is not None:
            _tray_icon.update_menu()

    def do_quit(icon=None, item=None):
        state["force"] = True
        try:
            if _tray_icon is not None:
                _tray_icon.stop()
        finally:
            try:
                window.destroy()
            except Exception:
                pass

    menu = pystray.Menu(
        pystray.MenuItem("Открыть VTScan", do_open, default=True),
        pystray.MenuItem("Защита включена", do_toggle_protection,
                         checked=lambda item: api._monitor is not None),
        pystray.MenuItem("Запуск с Windows", do_toggle_autostart,
                         checked=lambda item: vtscan.autostart_enabled()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Выход", do_quit),
    )
    _tray_icon = pystray.Icon("VTScan", _tray_image(), "VTScan — антивирус", menu)

    # Режим автозапуска (--tray): окно скрыто, сразу включаем фоновую защиту.
    if state.get("hidden"):
        try:
            api.monitor_start()
        except Exception:
            pass

    try:
        _tray_icon.run()
    except Exception:
        pass


def main() -> None:
    # Чистим остаток прошлого обновления (<exe>-old.exe), если он есть.
    try:
        vtscan.cleanup_old_update()
    except Exception:
        pass
    start_hidden = ("--tray" in sys.argv) or ("--minimized" in sys.argv)
    api = Api()
    state = {"force": False, "tray": False, "hidden": start_hidden}
    window = webview.create_window(
        f"VTScan v{vtscan.VERSION} — кибер-сканер",
        html=HTML,
        js_api=api,
        width=900, height=600, min_size=(560, 380),
        background_color="#0a0f1e",
        hidden=start_hidden,
    )
    api._window = window

    # Drag-and-drop: после загрузки DOM вешаем обработчик перетаскивания файла.
    try:
        window.events.loaded += lambda *_a: _wire_dnd(api, window)
    except Exception:
        pass

    # Крестик окна не закрывает программу, а прячет её в трей — фоновая защита
    # продолжает работать. Настоящий выход — пункт «Выход» в меню трея.
    def _on_closing():
        if state["force"] or not state["tray"]:
            return True               # форс-выход или трея нет — закрываемся по-настоящему
        try:
            window.hide()
        except Exception:
            return True
        return False                  # отменяем закрытие — свернулись в трей
    try:
        window.events.closing += _on_closing
    except Exception:
        pass

    webview.start(_start_tray, (api, window, state))


if __name__ == "__main__":
    main()
