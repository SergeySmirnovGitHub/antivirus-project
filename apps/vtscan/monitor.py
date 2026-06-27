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

import os
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

from engines import data_dir


# --------------------------------------------------------------------------- #
#  Событие наблюдателя
# --------------------------------------------------------------------------- #
@dataclass
class Event:
    kind: str        # autostart | process | newfile | action
    title: str       # короткий заголовок для уведомления
    detail: str = ""
    path: str = ""
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


def quarantine_file(path: Path) -> Path | None:
    """Перемещает файл в карантин (обратимо). Возвращает новый путь или None."""
    try:
        dest = quarantine_dir() / (path.name + ".quarantine")
        n = 1
        while dest.exists():
            dest = quarantine_dir() / f"{path.name}.{n}.quarantine"
            n += 1
        shutil.move(str(path), str(dest))
        return dest
    except OSError:
        return None


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
#  Наблюдатель
# --------------------------------------------------------------------------- #
class Monitor:
    """Фоновый наблюдатель. on_event(Event) вызывается при каждом событии."""

    def __init__(self, on_event: Callable[[Event], None],
                 scan_callback: Callable[[str], str] | None = None,
                 watch_dirs: list[Path] | None = None,
                 notifier: Callable[[Event], None] | None = None,
                 poll_interval: float = 5.0) -> None:
        self.on_event = on_event
        self.scan_callback = scan_callback        # (path) -> status: clean/malicious/...
        self.watch_dirs = watch_dirs or _default_watch_dirs()
        self.notifier = notifier                  # (Event) -> показать системное уведомление
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._observer = None
        self._autostart = autostart_snapshot()
        self._procs = process_snapshot()

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
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        self._start_file_watch()
        self._emit(Event("info", "Наблюдение запущено",
                            f"автозагрузка + процессы + папки: "
                            f"{', '.join(str(d) for d in self.watch_dirs)}"))

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            self._observer.stop()

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
            sev = "warn" if reason else "info"
            detail = info.get("exe") or info.get("name")
            if reason:
                detail += f"  ({reason})"
            self._emit(Event("process", "Новый процесс", detail,
                                path=info.get("exe", ""), severity=sev))
            # Если есть сканер и путь — проверим exe процесса.
            exe = info.get("exe")
            if self.scan_callback and exe and Path(exe).is_file():
                status = self.scan_callback(exe)
                if status == "malicious":
                    self._respond_process(pid, Path(exe))
        self._procs = cur

    def _respond_process(self, pid: int, exe: Path) -> None:
        suspended = suspend_process(pid)
        self._emit(Event("action",
                            "ВРЕДОНОСНЫЙ процесс " + ("приостановлен" if suspended else "обнаружен"),
                            str(exe), path=str(exe), severity="danger"))

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
                if event.is_directory:
                    return
                monitor._on_new_file(Path(event.src_path))

        self._observer = Observer()
        for d in self.watch_dirs:
            if Path(d).is_dir():
                self._observer.schedule(_Handler(), str(d), recursive=False)
        self._observer.daemon = True
        self._observer.start()

    def _on_new_file(self, path: Path) -> None:
        # Небольшая пауза — дать файлу дозаписаться.
        time.sleep(1.0)
        if not path.is_file():
            return
        self._emit(Event("newfile", "Новый файл", str(path), path=str(path)))
        if not self.scan_callback:
            return
        status = self.scan_callback(str(path))
        if status == "malicious":
            dest = quarantine_file(path)
            self._emit(Event("action",
                                "ВРЕДОНОСНЫЙ файл " + ("помещён в карантин" if dest else "обнаружен"),
                                str(path), path=str(dest or path), severity="danger"))


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
