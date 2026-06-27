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
import threading
from pathlib import Path

import webview

import vtscan
from engines import data_dir


def _serialize(r: "vtscan.ScanResult") -> dict:
    primary = r.threat_categories[0] if r.threat_categories else ""
    return {
        "name": r.path.name,
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

        def notifier(ev):
            def open_app():
                try:
                    webview.windows[0].restore()      # клик по уведомлению → открыть окно
                except Exception:
                    pass
            monitor_mod.toast(ev.title, ev.detail, on_click=open_app)

        self._monitor = monitor_mod.Monitor(on_event, scan_callback=cb, notifier=notifier)
        self._monitor.start()
        return {"ok": True}

    def monitor_stop(self) -> dict:
        if self._monitor is None:
            return {"ok": False, "message": "защита не запущена"}
        try:
            self._monitor.stop()
        finally:
            self._monitor = None
        return {"ok": True}

    def monitor_toggle(self) -> dict:
        """Одна команда: выключена → включить, включена → выключить."""
        if self._monitor is None:
            res = self.monitor_start()
            return {"on": bool(res.get("ok")), "message": res.get("message", "")}
        self.monitor_stop()
        return {"on": False, "message": ""}

    # --- действия по угрозе (кнопки в окне) ---
    def act_quarantine(self, path: str) -> dict:
        import monitor as monitor_mod
        dest = monitor_mod.quarantine_file(Path(path))
        return {"ok": bool(dest), "message": (f"В карантине: {dest}" if dest else "Не удалось поместить в карантин")}

    def act_delete(self, path: str) -> dict:
        try:
            Path(path).unlink()
            return {"ok": True, "message": "Файл удалён."}
        except OSError as e:
            return {"ok": False, "message": f"Не удалось удалить: {e}"}

    def act_suspend(self, pid: int) -> dict:
        import monitor as monitor_mod
        ok = monitor_mod.suspend_process(int(pid))
        return {"ok": ok, "message": ("Процесс приостановлен." if ok else "Не удалось (нужны права?).")}

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
            white-space:pre-wrap; word-break:break-word; cursor:text; }
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
  #cmd { flex:1; background:transparent; border:none; outline:none; color:var(--bright);
         font-family:inherit; font-size:inherit; line-height:inherit; padding:0; margin-left:6px; }
  .c-cyan{color:var(--cyan);} .c-green{color:var(--green);} .c-red{color:var(--red);}
  .c-amber{color:var(--amber);} .c-dim{color:var(--dim);} .c-bright{color:var(--bright);}
  .b{font-weight:bold;}
  .cmd-link{ color:var(--cyan); cursor:pointer; border-radius:3px; padding:0 3px; }
  .cmd-link:hover{ background:#11203c; color:#7fe6ff; }
  .act-btn{ display:inline-block; margin-right:8px; padding:2px 10px; border:1px solid #1d2c4a;
            border-radius:6px; color:var(--cyan); cursor:pointer; font-size:13px; }
  .act-btn:hover{ background:#11203c; border-color:var(--cyan); color:#7fe6ff; }
</style>
</head>
<body>
  <div id="topbar"><span class="brand">V T S C A N</span><div class="spacer"></div><button class="topbtn" onclick="openQuarantine()">Карантин</button></div>
  <div id="screen" onclick="focusCmd()">
    <div id="out"></div>
    <div class="cmdline"><span id="prompt" class="c-green"></span><input id="cmd" autocomplete="off" spellcheck="false" autofocus></div>
  </div>
  <div id="qoverlay">
    <div id="qpanel">
      <div id="qhead"><span>Карантин</span><span id="qclose" onclick="closeQuarantine()">&#10005;</span></div>
      <div id="qlist"></div>
    </div>
  </div>

<script>
  const out = document.getElementById('out');
  const screen = document.getElementById('screen');
  const cmd = document.getElementById('cmd');
  const promptEl = document.getElementById('prompt');
  let cwd = 'C:\\';
  let keyMode = false;
  const history = []; let hi = -1;

  function esc(s){return (s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function print(html){ const d=document.createElement('div'); d.innerHTML=html; out.appendChild(d); screen.scrollTop=screen.scrollHeight; }
  function focusCmd(){ cmd.focus(); }
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
  }

  const HELP_BASIC=[['scan [путь]','проверить файл; без пути — выбор файла','scan '],['monitor','вкл/выкл фоновую защиту','monitor'],['quarantine','список карантина (или кнопка вверху)','quarantine'],['key','ввести/обновить ключ VirusTotal','key'],['clear','очистить экран','clear'],['help','команды','help'],['exit','закрыть','exit']];
  const HELP_ADV=[['keys','доп. источники и их ключи','keys'],['where','показать папку приложения','where'],['setup-clamav','скачать офлайн-движок ClamAV','setup-clamav'],['make-eicar','создать безвредные тест-файлы','make-eicar'],['selftest','проверка уведомлений (имитация)','selftest'],['check-update','проверить обновления','check-update'],['cd <путь>','сменить текущую папку','cd '],['version','версия','version']];
  function printHelp(adv){
    const rows=adv?HELP_ADV:HELP_BASIC;
    let s='<span class="b">'+(adv?'Продвинутые команды:':'Команды:')+'</span>\n';
    rows.forEach(([c,d,ins])=>{ s+='  <span class="cmd-link" data-cmd="'+esc(ins)+'">'+esc((c+'                ').slice(0,16))+'</span><span class="c-dim">'+esc(d)+'</span>\n'; });
    if(!adv) s+='  <span class="c-dim">ещё: </span><span class="cmd-link" data-cmd="help advanced">help advanced</span>\n';
    print(s);
  }

  function actBtn(label,act,arg){ return '<span class="act-btn" data-act="'+act+'" data-arg="'+esc(arg)+'">'+esc(label)+'</span>'; }
  window.onMonitorEvent = function(ev){
    const cls={info:'c-dim',warn:'c-amber',danger:'c-red'}[ev.severity]||'c-dim';
    let html='<span class="'+cls+'">[защита] '+esc(ev.title)+(ev.detail?': '+esc(ev.detail):'')+'</span>';
    if(ev.kind==='threat-file' && ev.path){ html+='<br>      '+actBtn('В карантин','quarantine',ev.path)+actBtn('Удалить','delete',ev.path)+actBtn('Пропустить','ignore',''); }
    else if(ev.kind==='process' && ev.pid){ html+='<br>      '+actBtn('Остановить процесс','suspend',''+ev.pid)+actBtn('Пропустить','ignore',''); }
    print(html);
  };
  window.onLog = function(o){ print('<span class="c-dim">'+esc(o.text)+'</span>'); };

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
  document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeQuarantine(); });

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
    if(c==='help'||c==='?'){ printHelp(rest[0]==='advanced'||rest[0]==='adv'||rest[0]==='настройки'); }
    else if(c==='clear'||c==='cls'){ out.innerHTML=''; }
    else if(c==='version'||c==='ver'){ const i=await window.pywebview.api.app_info(); print('vtscan '+esc(i.version)); }
    else if(c==='where'||c==='folder'){ const i=await window.pywebview.api.app_info(); print('<span class="c-dim">Папка данных (ключ, ClamAV, карантин):</span>\n  <span class="c-cyan">'+esc(i.data_dir)+'</span>'); }
    else if(c==='quarantine'||c==='карантин'){ openQuarantine(); }
    else if(c==='keys'){
      if(rest.length>=2){ const r=await window.pywebview.api.keys_set(rest[0], rest.slice(1).join(' ')); print('<span class="c-green">'+esc(r.message)+'</span>'); }
      else { const items=await window.pywebview.api.keys_list(); let s='<span class="b">Доп. источники проверки (ключ бесплатный):</span>\n'; items.forEach(it=>{ s+='  <span class="c-cyan">'+esc((it.id+'              ').slice(0,14))+'</span>'+esc(it.name)+'  '+(it.has_key?'<span class="c-green">есть ключ</span>':'<span class="c-dim">нет ключа</span>')+'\n    <span class="c-dim">'+esc(it.signup)+'</span>\n'; }); s+='  <span class="c-dim">Добавить:</span> keys &lt;id&gt; &lt;ключ&gt;'; print(s); }
    }
    else if(c==='exit'||c==='quit'){ window.pywebview.api.quit(); }
    else if(c==='key'){ keyMode=true; setPrompt(); print('<span class="c-amber">Вставьте ключ VirusTotal и нажмите Enter (бесплатно: virustotal.com/gui/join-us):</span>'); }
    else if(c==='cd'){ if(!rest.length){ print('<span class="c-dim">'+esc(cwd)+'</span>'); } else { const r=await window.pywebview.api.set_cwd(rest.join(' ')); if(r.ok){ cwd=r.cwd; setPrompt(); } else print('<span class="c-red">'+esc(r.error)+'</span>'); } }
    else if(c==='check-update'||c==='update'){ print('<span class="c-dim">Проверяю обновления...</span>'); const r=await window.pywebview.api.check_update(); if(r.newer){ print('<span class="c-amber">'+esc(r.message)+'</span><br>      <span class="c-bright">Скачать и установить новую версию?</span>  '+actBtn('Да','update','')+actBtn('Нет','ignore','')); } else print('<span class="c-green">'+esc(r.message)+'</span>'); }
    else if(c==='monitor'||c==='guard'){
      const r=await window.pywebview.api.monitor_toggle();
      if(r.on) print('<span class="c-green">Фоновая защита ВКЛЮЧЕНА.</span> <span class="c-dim">(monitor ещё раз — выключить)</span>');
      else print(r.message?'<span class="c-amber">'+esc(r.message)+'</span>':'<span class="c-dim">Фоновая защита выключена.</span>');
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
    if(e.key==='Enter'){ const v=cmd.value; cmd.value=''; if(v.trim()&&!keyMode){ history.push(v); hi=history.length; } await dispatch(v); }
    else if(e.key==='ArrowUp'){ if(history.length){ hi=Math.max(0,hi-1); cmd.value=history[hi]||''; e.preventDefault(); } }
    else if(e.key==='ArrowDown'){ if(history.length){ hi=Math.min(history.length,hi+1); cmd.value=history[hi]||''; e.preventDefault(); } }
  });

  window.addEventListener('pywebviewready', async ()=>{
    const i=await window.pywebview.api.app_info();
    cwd=i.cwd||'C:\\'; setPrompt();
    print('<span class="c-cyan b">VTSCAN</span> <span class="c-dim">// кибер-сканер файлов  v'+esc(i.version)+'</span>');
    print('<span class="c-dim">источники: '+esc(i.sources.join(' + '))+'</span>\n');
    printHelp(false);
    const hk=await window.pywebview.api.has_key();
    if(!hk) print('<span class="c-amber">\nКлюч не задан. Введите </span><span class="b">key</span><span class="c-amber"> для настройки.</span>');
    focusCmd();
  });
  out.addEventListener('click', async e=>{
    const link=e.target.closest('.cmd-link');
    if(link){ e.stopPropagation(); cmd.value=link.dataset.cmd; focusCmd(); return; }
    const b=e.target.closest('.act-btn');
    if(b){ e.stopPropagation();
      const act=b.dataset.act, arg=b.dataset.arg;
      b.parentElement.querySelectorAll('.act-btn').forEach(x=>x.style.opacity=.4);
      b.parentElement.querySelectorAll('.act-btn').forEach(x=>x.remove());
      if(act==='update'){ const u=await window.pywebview.api.do_update(); if(!u.ok) print('<span class="c-amber">→ '+esc(u.message)+'</span>'); return; }
      let r={ok:true,message:'Пропущено.'};
      if(act==='quarantine') r=await window.pywebview.api.act_quarantine(arg);
      else if(act==='delete') r=await window.pywebview.api.act_delete(arg);
      else if(act==='suspend') r=await window.pywebview.api.act_suspend(parseInt(arg));
      print('<span class="'+(r.ok?'c-green':'c-red')+'">→ '+esc(r.message||'готово')+'</span>');
    }
  });
  document.addEventListener('click', focusCmd);
</script>
</body>
</html>
"""


def main() -> None:
    # Чистим остаток прошлого обновления (<exe>-old.exe), если он есть.
    try:
        vtscan.cleanup_old_update()
    except Exception:
        pass
    api = Api()
    webview.create_window(
        "VTScan — кибер-сканер",
        html=HTML,
        js_api=api,
        width=900, height=600, min_size=(560, 380),
        background_color="#0a0f1e",
    )
    webview.start()


if __name__ == "__main__":
    main()
