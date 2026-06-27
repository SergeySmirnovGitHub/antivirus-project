#!/usr/bin/env python3
"""
monitor — ядро фонового наблюдения (этап 3).

Что умеет:
  1. Следить за АВТОЗАГРУЗКОЙ (где прячется ~90% малвари): снимок + диф → алерт на новое.
  2. Следить за ПРОЦЕССАМИ: снимок + диф → новые процессы (+ простые признаки подозрительности).
  3. Следить за НОВЫМИ ФАЙЛАМИ в папках (Downloads и др.) → отдать на проверку сканеру.

Реакция на угрозу (осознанное решение по безопасности):
  - по умолчанию — КАРАНТИН файла (перемещение в свою папку, ОБРАТИМО) и ПАУЗА процесса.
  - безвозвратное удаление/kill — только вручную/по явному подтверждению (ложные срабатывания
    бывают, нельзя автоматически крушить систему пользователя).

Модуль самодостаточный и тестируемый: проверка файлов делается через инъектируемый
колбэк scan_callback(path) -> str(status), поэтому monitor не завязан жёстко на vtscan.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

try:
    import psutil
except ImportError:  # psutil обязателен для процессов, но снимок автозагрузки работает и без него
    psutil = None

from engines import data_dir, add_to_whitelist


# --------------------------------------------------------------------------- #
#  Событие наблюдателя
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    kind: str        # autostart | process | threat-file | info
    title: str       # короткий заголовок для уведомления
    detail: str = ""
    path: str = ""
    pid: int = 0     # для процессов — чтобы можно было остановить
    severity: str = "info"   # info | warn | danger


# --------------------------------------------------------------------------- #
#  Снимки состояния системы
# --------------------------------------------------------------------------- #
def autostart_snapshot() -> dict[str, str]:
    """Снимок точек автозагрузки. {описание_ключа: значение}."""
    items: dict[str, str] = {}
    if os.name == "nt":
        import winreg
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for root, sub in run_keys:
            try:
                with winreg.OpenKey(root, sub) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        items[f"{sub}\\{name}"] = str(value)
                        i += 1
            except OSError:
                continue
        # Папка «Автозагрузка»
        startup = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
        if startup.is_dir():
            for f in startup.iterdir():
                items[f"Startup\\{f.name}"] = str(f)
    else:
        # macOS — для разработки/теста: LaunchAgents.
        for d in (Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents")):
            if d.is_dir():
                for f in d.glob("*.plist"):
                    items[f"LaunchAgents/{f.name}"] = str(f)
    return items


def process_snapshot() -> dict[int, dict]:
    """Снимок процессов: {pid: {name, exe, username, ppid}}."""
    snap: dict[int, dict] = {}
    if psutil is None:
        return snap
    for p in psutil.process_iter(["pid", "name", "exe", "username", "ppid"]):
        try:
            info = p.info
            snap[info["pid"]] = {
                "name": info.get("name") or "",
                "exe": info.get("exe") or "",
                "username": info.get("username") or "",
                "ppid": info.get("ppid") or 0,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snap


def looks_suspicious(proc: dict) -> str:
    """Простая поведенческая эвристика по процессу. Возвращает причину или ''."""
    exe = (proc.get("exe") or "").lower()
    suspicious_dirs = ("\\temp\\", "/tmp/", "\\downloads\\", "/downloads/",
                       "\\appdata\\local\\temp", "appdata\\roaming")
    if exe and any(s in exe for s in suspicious_dirs):
        return "запуск из временной папки/загрузок"
    return ""


# --------------------------------------------------------------------------- #
#  Реакция на угрозу (обратимая по умолчанию)
# --------------------------------------------------------------------------- #
def quarantine_dir() -> Path:
    d = data_dir() / "quarantine"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _index_path() -> Path:
    return quarantine_dir() / "index.json"


def _load_index() -> list[dict]:
    p = _index_path()
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
    return []


def _save_index(items: list[dict]) -> None:
    try:
        _index_path().write_text(json.dumps(items, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
    except OSError:
        pass


def _xor_stream(src: Path, dst: Path, key: bytes) -> str:
    """Копирует src→dst, XOR-скремблируя содержимое (обезвреживание). XOR симметричен —
    та же функция шифрует и расшифровывает. Возвращает SHA-256 ВХОДА."""
    h = hashlib.sha256()
    klen = len(key)
    i = 0
    with src.open("rb") as fi, dst.open("wb") as fo:
        while True:
            chunk = fi.read(262144)
            if not chunk:
                break
            h.update(chunk)
            if key:
                chunk = bytes(b ^ key[(i + j) % klen] for j, b in enumerate(chunk))
            fo.write(chunk)
            i += len(chunk)
    return h.hexdigest()


def quarantine_file(path: Path) -> Path | None:
    """В карантин: ШИФРУЕТ содержимое (файл становится инертным), удаляет оригинал,
    запоминает исходный путь, хэш и ключ для восстановления."""
    try:
        dest = quarantine_dir() / (path.name + ".quarantine")
        n = 1
        while dest.exists():
            dest = quarantine_dir() / f"{path.name}.{n}.quarantine"
            n += 1
        original = str(path.resolve())
        key = secrets.token_bytes(16)
        sha = _xor_stream(path, dest, key)   # зашифрованный блоб + хэш оригинала
        path.unlink()                        # оригинал убираем — угроза обезврежена
        items = _load_index()
        items.append({
            "id": dest.name, "name": path.name, "original": original,
            "qpath": str(dest), "sha256": sha,
            "key": base64.b64encode(key).decode(),
            "ts": time.strftime("%Y-%m-%d %H:%M"),
        })
        _save_index(items)
        return dest
    except OSError:
        return None


def list_quarantine() -> list[dict]:
    """Список файлов в карантине (только реально существующие)."""
    items = _load_index()
    alive = [it for it in items if Path(it.get("qpath", "")).is_file()]
    if len(alive) != len(items):
        _save_index(alive)
    return alive


def _restore_blob(it: dict) -> Path:
    """Расшифровывает блоб обратно в исходный файл, удаляет блоб. Возвращает путь."""
    qpath = Path(it.get("qpath", ""))
    original = Path(it.get("original", ""))
    key = base64.b64decode(it["key"]) if it.get("key") else b""
    original.parent.mkdir(parents=True, exist_ok=True)
    _xor_stream(qpath, original, key)        # XOR обратно (или просто копия, если ключа нет)
    qpath.unlink(missing_ok=True)
    return original


def restore_quarantine(item_id: str) -> dict:
    """Восстановить файл на исходное место (останется «подозрительным» для будущих сканов)."""
    items = _load_index()
    for it in items:
        if it.get("id") == item_id:
            try:
                original = _restore_blob(it)
            except OSError as e:
                return {"ok": False, "message": f"не удалось восстановить: {e}"}
            _save_index([x for x in items if x.get("id") != item_id])
            return {"ok": True, "message": f"восстановлен: {original}"}
    return {"ok": False, "message": "запись не найдена"}


def allow_quarantine(item_id: str) -> dict:
    """«Разрешить»: восстановить файл И добавить его в белый список (исключения),
    чтобы антивирус больше на него не реагировал (для ложных срабатываний)."""
    items = _load_index()
    for it in items:
        if it.get("id") == item_id:
            try:
                original = _restore_blob(it)
            except OSError as e:
                return {"ok": False, "message": f"не удалось восстановить: {e}"}
            if it.get("sha256"):
                add_to_whitelist(it["sha256"], it.get("name", ""))
            _save_index([x for x in items if x.get("id") != item_id])
            return {"ok": True, "message": f"разрешён и в белом списке: {original}"}
    return {"ok": False, "message": "запись не найдена"}


def delete_quarantine(item_id: str) -> dict:
    """Удаляет файл из карантина навсегда."""
    items = _load_index()
    for it in items:
        if it.get("id") == item_id:
            try:
                Path(it.get("qpath", "")).unlink(missing_ok=True)
            except OSError as e:
                return {"ok": False, "message": f"не удалось удалить: {e}"}
            _save_index([x for x in items if x.get("id") != item_id])
            return {"ok": True, "message": "удалён навсегда"}
    return {"ok": False, "message": "запись не найдена"}


def suspend_process(pid: int) -> bool:
    """Ставит процесс на паузу (обратимо через resume_process)."""
    if psutil is None:
        return False
    try:
        psutil.Process(pid).suspend()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def resume_process(pid: int) -> bool:
    if psutil is None:
        return False
    try:
        psutil.Process(pid).resume()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def toast(title: str, message: str = "", on_click: Callable[[], None] | None = None) -> None:
    """Системное уведомление Windows (всплывает справа). По клику — on_click().
    Best-effort: если уведомления недоступны, тихо ничего не делаем."""
    if os.name != "nt":
        return
    try:
        from windows_toasts import Toast, WindowsToaster
        toaster = WindowsToaster("VTScan")
        t = Toast()
        t.text_fields = [title, message] if message else [title]
        if on_click is not None:
            t.on_activated = lambda *_a: on_click()
        toaster.show_toast(t)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  Ловушки-приманки против шифровальщиков (canary / honeypot)
# --------------------------------------------------------------------------- #
# Имена с "!" в начале — чтобы при сортировке шифровальщик добрался до них первыми.
CANARY_NAMES = ("!!!-passwords-backup.txt", "!!!-wallet-seed.txt", "!!!-documents.docx")


def _set_hidden(path: Path) -> None:
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02)  # HIDDEN
        except Exception:
            pass


def canary_paths(dirs: list[Path]) -> list[Path]:
    out: list[Path] = []
    for d in dirs:
        if Path(d).is_dir():
            for n in CANARY_NAMES:
                out.append(Path(d) / n)
    return out


def plant_canaries(dirs: list[Path]) -> list[Path]:
    """Раскидывает скрытые файлы-приманки. Если их тронут — это сигнал шифровальщика."""
    planted: list[Path] = []
    content = (b"VTScan canary file. Do not modify or delete.\n"
               b"Used to detect ransomware (file-encrypting malware).\n") * 6
    for p in canary_paths(dirs):
        try:
            if not p.exists():
                p.write_bytes(content)
                _set_hidden(p)
            planted.append(p)
        except OSError:
            continue
    return planted


def remove_canaries(dirs: list[Path]) -> None:
    for p in canary_paths(dirs):
        try:
            if p.exists():
                p.unlink()
        except OSError:
            continue


def freeze_suspicious_processes() -> list[str]:
    """Замораживает (suspend) процессы из Temp/Downloads — вероятные шифровальщики.
    Обратимо (resume). Возвращает список того, что заморожено."""
    frozen: list[str] = []
    if psutil is None:
        return frozen
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = {"exe": p.info.get("exe") or "", "name": p.info.get("name") or ""}
            if looks_suspicious(info):
                p.suspend()
                frozen.append(info["exe"] or info["name"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return frozen


# --------------------------------------------------------------------------- #
#  Наблюдатель
# --------------------------------------------------------------------------- #
class Monitor:
    """Фоновый наблюдатель. on_event(Event) вызывается при каждом событии."""

    def __init__(self, on_event: Callable[[Event], None],
                 scan_callback: Callable[[str], str] | None = None,
                 watch_dirs: list[Path] | None = None,
                 notifier: Callable[[Event], None] | None = None,
                 use_canaries: bool = True,
                 poll_interval: float = 5.0) -> None:
        self.on_event = on_event
        self.scan_callback = scan_callback        # (path) -> status: clean/malicious/...
        self.watch_dirs = watch_dirs or _default_watch_dirs()
        self.notifier = notifier                  # (Event) -> показать системное уведомление
        self.use_canaries = use_canaries
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._observer = None
        self._autostart = autostart_snapshot()
        self._procs = process_snapshot()
        self._canary_set = set(CANARY_NAMES)
        self._last_canary_alert = 0.0

    def _emit(self, ev: "Event") -> None:
        """Шлёт событие в UI и — для важных (warn/danger) — системное уведомление."""
        cb = self.on_event
        cb(ev)
        if self.notifier is not None and ev.severity in ("warn", "danger"):
            try:
                self.notifier(ev)
            except Exception:
                pass

    # --- запуск/остановка ---
    def start(self) -> None:
        if self.use_canaries:
            plant_canaries(self.watch_dirs)
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        self._start_file_watch()
        extra = " + приманки-ловушки" if self.use_canaries else ""
        self._emit(Event("info", "Наблюдение запущено",
                            f"автозагрузка + процессы + файлы{extra}"))

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()
        if self.use_canaries:
            remove_canaries(self.watch_dirs)

    def _is_canary(self, path: Path) -> bool:
        return path.name in self._canary_set

    def _on_canary_event(self, path: Path) -> None:
        """Тронут файл-приманка → почти 100% шифровальщик. Замораживаем подозрительных."""
        if not self._is_canary(path):
            return
        now = time.time()
        if now - self._last_canary_alert < 8:   # дебаунс: один алерт на волну
            return
        self._last_canary_alert = now
        frozen = freeze_suspicious_processes()
        if frozen:
            detail = "заморожены процессы: " + ", ".join(frozen[:3])
        else:
            detail = "подозрительных процессов не найдено — проверьте систему вручную!"
        self._emit(Event("ransomware", "ВОЗМОЖЕН ШИФРОВАЛЬЩИК! Тронут файл-приманка",
                         detail, path=str(path), severity="danger"))

    # --- цикл опроса автозагрузки и процессов ---
    def _poll_loop(self) -> None:
        while not self._stop.wait(self.poll_interval):
            self._check_autostart()
            self._check_processes()

    def _check_autostart(self) -> None:
        cur = autostart_snapshot()
        for key, val in cur.items():
            if key not in self._autostart:
                self._emit(Event("autostart", "Новое в автозагрузке",
                                    f"{key} = {val}", path=val, severity="warn"))
        self._autostart = cur

    def _check_processes(self) -> None:
        cur = process_snapshot()
        for pid, info in cur.items():
            if pid in self._procs:
                continue
            reason = looks_suspicious(info)
            if not reason:
                continue   # обычные процессы НЕ показываем — иначе спам; только подозрительные
            detail = (info.get("exe") or info.get("name") or "") + f"  ({reason})"
            self._emit(Event("process", "Подозрительный процесс", detail,
                             path=info.get("exe", ""), pid=pid, severity="warn"))
        self._procs = cur

    # --- слежение за новыми файлами (watchdog) ---
    def _start_file_watch(self) -> None:
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            return

        monitor = self

        class _Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    monitor._on_new_file(Path(event.src_path))

            def on_modified(self, event):
                if not event.is_directory:
                    monitor._on_canary_event(Path(event.src_path))

            def on_deleted(self, event):
                if not event.is_directory:
                    monitor._on_canary_event(Path(event.src_path))

            def on_moved(self, event):
                if not event.is_directory:
                    monitor._on_canary_event(Path(event.src_path))

        self._observer = Observer()
        for d in self.watch_dirs:
            if Path(d).is_dir():
                self._observer.schedule(_Handler(), str(d), recursive=False)
        self._observer.daemon = True
        self._observer.start()

    def _on_new_file(self, path: Path) -> None:
        # Небольшая пауза — дать файлу дозаписаться.
        time.sleep(1.0)
        if not path.is_file() or not self.scan_callback:
            return
        status = self.scan_callback(str(path))
        if status == "malicious":
            # Только сигналим об угрозе — действие (карантин/удалить) выбирает пользователь.
            self._emit(Event("threat-file", "Обнаружен вредоносный файл",
                             str(path), path=str(path), severity="danger"))


def _default_watch_dirs() -> list[Path]:
    home = Path.home()
    dirs = [home / "Downloads", home / "Desktop"]
    return [d for d in dirs if d.is_dir()]


# --------------------------------------------------------------------------- #
#  Демонстрационный запуск из консоли
# --------------------------------------------------------------------------- #
def main() -> None:
    print("monitor: фоновое наблюдение (Ctrl+C — выход)")
    print("Папки под наблюдением:", ", ".join(str(d) for d in _default_watch_dirs()) or "—")

    def printer(ev: Event) -> None:
        mark = {"info": "[ ]", "warn": "[?]", "danger": "[!]"}.get(ev.severity, "[ ]")
        print(f"{mark} {ev.title}: {ev.detail}")

    mon = Monitor(on_event=printer)
    mon.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mon.stop()
        print("\nОстановлено.")


if __name__ == "__main__":
    main()
