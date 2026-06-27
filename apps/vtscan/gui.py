#!/usr/bin/env python3
"""
gui — отдельное окно-приложение в стиле кибер-терминала (этап 3, замена cmd).

Используем pywebview: внутри настоящего окна рендерится HTML/CSS, поэтому можно
в точности повторить дизайн-мокап (тёмно-синий фон, моноширинный шрифт, цветные
вердикты, разбивка по источникам). Вся логика сканирования переиспользуется из
vtscan.py — GUI это только «лицо» поверх уже готового движка.

Запуск (разработка):  python gui.py
Сборка в .exe:        pyinstaller --noconsole --onefile --name VTScan gui.py
"""

from __future__ import annotations

import threading
from pathlib import Path

import webview

import vtscan
from engines import EngineResult  # noqa: F401  (тип для сериализации)


# --------------------------------------------------------------------------- #
#  Сериализация результата для передачи в JS
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
#  Мост Python <-> JavaScript
# --------------------------------------------------------------------------- #
class Api:
    """Методы, вызываемые из JS как pywebview.api.<метод>()."""

    def __init__(self) -> None:
        self._client = None

    # --- ключ VirusTotal ---
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

    # --- информация о приложении ---
    def app_info(self) -> dict:
        engine = vtscan.clamav_engine()
        sources = ["VirusTotal"]
        if engine.is_available():
            sources.append("ClamAV")
        return {"version": vtscan.VERSION, "sources": sources}

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
        p = Path(path)
        if not p.exists():
            return {"error": "not_found", "name": p.name}
        try:
            result = vtscan.scan_one(client, p, upload)
        except Exception as e:  # noqa: BLE001 — не роняем окно из-за одной проверки
            return {"error": "scan_failed", "message": str(e), "name": p.name}
        return _serialize(result)


# --------------------------------------------------------------------------- #
#  HTML-интерфейс (стиль кибер-терминала из мокапа)
# --------------------------------------------------------------------------- #
HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<style>
  :root {
    --bg: #0a0f1e; --bar: #0d1428; --line: #1d2c4a;
    --txt: #aebbd6; --bright: #d7e3fb; --dim: #56678a;
    --cyan: #36d3ff; --green: #43e08a; --red: #ff5d6c; --amber: #ffb454;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; background: var(--bg); }
  body {
    font-family: "Cascadia Mono", "Consolas", "Menlo", monospace;
    color: var(--txt); font-size: 15px; line-height: 1.6;
    display: flex; flex-direction: column; height: 100vh; overflow: hidden;
  }
  .bar {
    display: flex; align-items: center; gap: 10px; padding: 9px 14px;
    background: var(--bar); border-bottom: 1px solid var(--line); flex: 0 0 auto;
  }
  .dot { width: 9px; height: 9px; border-radius: 50%; }
  .title { flex: 1; text-align: center; letter-spacing: 3px; color: #7fb6ff; font-size: 13px; }
  .online { color: var(--green); font-size: 12px; }
  #log { flex: 1 1 auto; overflow-y: auto; padding: 14px 18px; white-space: pre-wrap; }
  .row { display: flex; gap: 8px; padding: 10px 14px; background: var(--bar);
         border-top: 1px solid var(--line); flex: 0 0 auto; }
  input[type=text] {
    flex: 1; background: #0a1124; border: 1px solid var(--line); color: var(--bright);
    font-family: inherit; font-size: 14px; padding: 8px 10px; border-radius: 6px; outline: none;
  }
  input[type=text]:focus { border-color: var(--cyan); }
  button {
    background: #11203c; border: 1px solid var(--line); color: var(--bright);
    font-family: inherit; font-size: 14px; padding: 8px 14px; border-radius: 6px; cursor: pointer;
  }
  button:hover { border-color: var(--cyan); color: var(--cyan); }
  .c-cyan { color: var(--cyan); } .c-green { color: var(--green); }
  .c-red { color: var(--red); } .c-amber { color: var(--amber); }
  .c-dim { color: var(--dim); } .c-bright { color: var(--bright); }
  .b { font-weight: bold; }
</style>
</head>
<body>
  <div class="bar">
    <span class="dot" style="background:#ff5d6c"></span>
    <span class="dot" style="background:#ffb454"></span>
    <span class="dot" style="background:#43e08a"></span>
    <span class="title">V T S C A N&nbsp;&nbsp;//&nbsp;&nbsp;кибер-сканер</span>
    <span class="online">● online</span>
  </div>
  <div id="log"></div>
  <div class="row">
    <input id="path" type="text" placeholder="путь к файлу или нажмите «Выбрать файл»" />
    <button onclick="browse()">Выбрать файл</button>
    <button onclick="doScan()">Сканировать</button>
  </div>

<script>
  const log = document.getElementById('log');
  const pathInput = document.getElementById('path');

  function line(html) { const d = document.createElement('div'); d.innerHTML = html; log.appendChild(d); log.scrollTop = log.scrollHeight; }
  function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  const MARK = { malicious:'<span class="c-red">●</span>', suspicious:'<span class="c-amber">●</span>',
                 clean:'<span class="c-green">●</span>', unknown:'<span class="c-dim">○</span>',
                 skipped:'<span class="c-dim">○</span>', error:'<span class="c-dim">x</span>',
                 unavailable:'<span class="c-dim">·</span>' };
  const VERDICT = { malicious:'c-red', suspicious:'c-amber', clean:'c-green',
                    unknown:'c-dim', skipped:'c-dim', error:'c-red' };
  const ICON = { malicious:'[!]', suspicious:'[?]', clean:'[+]', unknown:'[ ]', skipped:'[-]', error:'[x]' };

  function renderResult(r) {
    if (r.error === 'no_key') { askKey(); return; }
    if (r.error === 'not_found') { line('<span class="c-red">Файл не найден: '+esc(r.name)+'</span>'); return; }
    if (r.error) { line('<span class="c-red">Ошибка: '+esc(r.message||r.error)+'</span>'); return; }
    const cls = VERDICT[r.status] || 'c-dim';
    let out = '<span class="'+cls+' b">'+ (ICON[r.status]||'[ ]') +' '+esc(r.verdict)+'</span>   <span class="c-bright">'+esc(r.name)+'</span>\n';
    if (r.threat_type) out += '      <span class="c-dim">тип угрозы:</span> <span class="c-amber">'+esc(r.threat_type)+'</span>\n';
    if (r.threat_others && r.threat_others.length) out += '        <span class="c-dim">также отмечен как: '+esc(r.threat_others.join(', '))+'</span>\n';
    if (r.family) out += '      <span class="c-dim">семейство:</span> <span class="c-amber">'+esc(r.family)+'</span>\n';
    (r.engines||[]).forEach((e,i,a) => {
      const branch = (i===a.length-1) ? '└' : '├';
      out += '      <span class="c-dim">'+branch+'</span> '+esc((e.engine+'             ').slice(0,13))+(MARK[e.status]||'○')+' <span class="c-dim">'+esc(e.detail)+'</span>\n';
    });
    if (r.message && ['unknown','skipped','error'].includes(r.status)) out += '      <span class="c-dim">'+esc(r.message)+'</span>\n';
    out += '      <span class="c-dim">sha256: '+esc(r.sha256)+'</span>';
    line(out);
  }

  async function doScan() {
    const p = pathInput.value.trim();
    if (!p) return;
    line('<span class="c-green">scan</span> <span class="c-bright">'+esc(p)+'</span>');
    line('<span class="c-dim">› проверяю источники ...</span>');
    const r = await window.pywebview.api.scan(p);
    renderResult(r);
    line('');
  }

  async function browse() {
    const p = await window.pywebview.api.pick_file();
    if (p) { pathInput.value = p; doScan(); }
  }

  function askKey() {
    line('<span class="c-amber">Нужен ключ VirusTotal (бесплатно: virustotal.com/gui/join-us).</span>');
    line('<span class="c-dim">Вставьте ключ в поле ниже и нажмите «Сканировать» один раз — он сохранится.</span>');
    pathInput.placeholder = 'вставьте сюда API-ключ VirusTotal и нажмите Сканировать';
    pathInput.dataset.keymode = '1';
  }

  // Перехват: если ждём ключ — первый ввод трактуем как ключ.
  const realScan = doScan;
  doScan = async function() {
    if (pathInput.dataset.keymode === '1') {
      const ok = await window.pywebview.api.save_key(pathInput.value.trim());
      if (ok) { line('<span class="c-green">Ключ сохранён. Теперь можно сканировать файлы.</span>'); pathInput.value=''; pathInput.placeholder='путь к файлу или нажмите «Выбрать файл»'; delete pathInput.dataset.keymode; }
      else line('<span class="c-red">Пустой ключ.</span>');
      return;
    }
    return realScan();
  };

  pathInput.addEventListener('keydown', e => { if (e.key === 'Enter') doScan(); });

  window.addEventListener('pywebviewready', async () => {
    const info = await window.pywebview.api.app_info();
    line('<span class="c-cyan b">VTSCAN</span> <span class="c-dim">// кибер-сканер файлов  v'+esc(info.version)+'</span>');
    line('<span class="c-dim">источники: '+esc(info.sources.join(' + '))+'</span>');
    line('');
    const hasKey = await window.pywebview.api.has_key();
    if (!hasKey) askKey();
    else line('<span class="c-dim">Готов. Выберите файл или впишите путь и нажмите «Сканировать».</span>');
  });
</script>
</body>
</html>
"""


def main() -> None:
    api = Api()
    webview.create_window(
        "VTScan — кибер-сканер",
        html=HTML.replace("__VERSION__", vtscan.VERSION),
        js_api=api,
        width=900, height=620, min_size=(640, 460),
        background_color="#0a0f1e",
    )
    webview.start()


if __name__ == "__main__":
    main()
