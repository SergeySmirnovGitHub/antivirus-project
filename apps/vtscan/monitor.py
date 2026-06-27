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
    """Простая поведенческая эвристика по процессу. Возвращает причину или ''.

    Берём только реально подозрительные места запуска — Temp и Downloads (там стартует
    большинство дропперов). %AppData%\\Roaming НЕ берём: там живёт масса легальных
    программ (Telegram, Discord, Spotify…) — иначе сплошные ложные срабатывания."""
    exe = (proc.get("exe") or "").lower()
    suspicious_dirs = ("\\temp\\", "/tmp/", "\\downloads\\", "/downloads/",
                       "\\appdata\\local\\temp")
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


def kill_process(pid: int) -> bool:
    """Завершает процесс (terminate). НЕОБРАТИМО — только по явному выбору пользователя."""
    if psutil is None:
        return False
    try:
        psutil.Process(pid).terminate()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


# --------------------------------------------------------------------------- #
#  Умное обезвреживание (remediation): не просто удалить файл, а вычистить угрозу
# --------------------------------------------------------------------------- #
def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(262144), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def processes_using(path: Path) -> list[dict]:
    """Процессы, чей exe — этот файл (их надо завершить, иначе файл нельзя тронуть)."""
    out: list[dict] = []
    if psutil is None:
        return out
    target = os.path.normcase(os.path.abspath(str(path)))
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            exe = p.info.get("exe") or ""
            if exe and os.path.normcase(os.path.abspath(exe)) == target:
                out.append({"pid": p.info["pid"], "name": p.info.get("name") or ""})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def remove_autostart_for(path: Path) -> list[str]:
    """Снимает персистентность: убирает записи автозагрузки, ведущие на этот файл.
    Только HKCU Run/RunOnce + папка «Автозагрузка» (без админа). HKLM не трогаем —
    нужны права администратора (это уровень прав 2, отдельная задача)."""
    removed: list[str] = []
    if os.name != "nt":
        return removed
    import winreg
    target = os.path.normcase(os.path.abspath(str(path)))
    base = os.path.basename(str(path)).lower()
    for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0,
                                winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                values = []
                i = 0
                while True:
                    try:
                        nm, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    values.append((nm, str(val)))
                    i += 1
                for nm, val in values:
                    if target in os.path.normcase(val) or base in val.lower():
                        try:
                            winreg.DeleteValue(k, nm)
                            removed.append(f"HKCU\\{sub}\\{nm}")
                        except OSError:
                            pass
        except OSError:
            continue
    startup = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    if startup.is_dir():
        for f in startup.iterdir():
            try:
                if f.name.lower() == base or (
                        f.is_file() and target in os.path.normcase(str(f.resolve()))):
                    f.unlink()
                    removed.append(f"Startup\\{f.name}")
            except OSError:
                continue
    return removed


def find_copies(path: Path, sha256: str = "") -> list[Path]:
    """Ищет КОПИИ файла в типичных папках (поверхностно, быстро). Если задан sha256 —
    подтверждает по хэшу (точно тот же файл). Без хэша — по совпадению имени."""
    base = os.path.basename(str(path))
    orig = os.path.normcase(os.path.abspath(str(path)))
    env = os.environ
    dirs = [Path(path).parent, Path.home() / "Downloads", Path.home() / "Desktop"]
    if env.get("TEMP"):
        dirs.append(Path(env["TEMP"]))
    if env.get("APPDATA"):
        dirs.append(Path(env["APPDATA"]))
    if env.get("LOCALAPPDATA"):
        dirs.append(Path(env["LOCALAPPDATA"]) / "Temp")
    seen: set[str] = set()
    found: list[Path] = []
    for d in dirs:
        try:
            if not d.is_dir():
                continue
            for p in d.glob(base):           # поверхностно (без рекурсии) — быстро
                ap = os.path.normcase(os.path.abspath(str(p)))
                if ap == orig or ap in seen or not p.is_file():
                    continue
                if sha256 and _sha256_file(p) != sha256:
                    continue
                seen.add(ap)
                found.append(p)
        except OSError:
            continue
    return found


def remediate(path: str, sha256: str = "", kill: bool = True) -> dict:
    """Умное обезвреживание ВОКРУГ файла (сам файл карантинит/удаляет вызывающий код):
      1) завершает процессы, запущенные из этого файла (иначе его не тронуть);
      2) снимает его записи автозагрузки (персистентность);
      3) находит копии по хэшу в типичных папках.
    Возвращает отчёт {stopped, autostart_removed, copies}."""
    p = Path(path)
    report = {"stopped": [], "autostart_removed": [], "copies": []}
    for proc in processes_using(p):
        ok = kill_process(proc["pid"]) if kill else suspend_process(proc["pid"])
        if ok:
            report["stopped"].append(proc)
    report["autostart_removed"] = remove_autostart_for(p)
    if not sha256:
        sha256 = _sha256_file(p)
    report["copies"] = [str(c) for c in find_copies(p, sha256)]
    return report


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
    """Делает файл «суперскрытым»: HIDDEN | SYSTEM. Такой файл Explorer не показывает
    даже при включённом «показывать скрытые файлы» (нужно ещё снять «скрывать защищённые
    системные файлы» — она спрятана и по умолчанию включена). Приманку не должно быть видно."""
    if os.name == "nt":
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            ctypes.windll.kernel32.SetFileAttributesW(
                str(path), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
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
            _set_hidden(p)        # всегда (HIDDEN|SYSTEM), даже если приманка уже была
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


def scan_processes(scan_tree: Callable | None = None,
                   on_progress: Callable[[int, int, str], None] | None = None,
                   should_stop: Callable[[], bool] | None = None) -> dict:
    """СКАН ПАМЯТИ: проверяет все запущенные процессы. Для каждого — поведенческая
    эвристика (откуда запущен) + скан его exe движком ClamAV, что реально ловит
    вредонос, работающий в памяти.

    Все уникальные exe сканируются ОДНИМ вызовом clamscan (через scan_tree), иначе
    база сигнатур грузилась бы на каждый файл заново — это были бы минуты.

    Честно: процессы, скрытые руткитом на уровне ядра, из user-mode не видны — это
    задача драйвера (этап 4). Здесь проверяются все процессы, видимые системе.

    scan_tree(paths, on_file, should_stop) — метод движка (engines.ClamAVEngine.scan_tree).
    Возвращает {'checked': N, 'findings': [{pid,name,exe,status,reason}], 'error': str|None}.
    """
    if psutil is None:
        return {"checked": 0, "findings": [], "error": "psutil недоступен"}
    procs: list[tuple[int, str, str]] = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            procs.append((p.info["pid"], p.info.get("name") or "", p.info.get("exe") or ""))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 1) Пакетный скан уникальных exe движком — один вызов clamscan на всё.
    infected_exes: dict[str, str] = {}     # normcase(путь) → имя детекта
    if scan_tree is not None:
        unique = sorted({exe for _, _, exe in procs if exe and os.path.isfile(exe)})

        def on_file(n: int, path: str) -> None:
            if on_progress is not None:
                on_progress(n, len(unique), os.path.basename(path))

        try:
            res = scan_tree(unique, on_file=on_file, should_stop=should_stop)
            for it in res.get("infected", []):
                infected_exes[os.path.normcase(it["path"])] = it["name"]
        except Exception:  # noqa: BLE001
            pass

    # 2) Сводим вердикт: заражённый exe → malicious; иначе эвристика → suspicious.
    findings: list[dict] = []
    for pid, name, exe in procs:
        key = os.path.normcase(exe) if exe else ""
        if key and key in infected_exes:
            findings.append({"pid": pid, "name": name, "exe": exe,
                             "status": "malicious",
                             "reason": "движок: " + infected_exes[key]})
            continue
        reason = looks_suspicious({"exe": exe, "name": name})
        if reason:
            findings.append({"pid": pid, "name": name, "exe": exe,
                             "status": "suspicious", "reason": reason})
    return {"checked": len(procs), "findings": findings, "error": None}


def scan_network() -> dict:
    """СЕТЕВОЙ МОНИТОР: активные исходящие подключения по процессам. Помечает
    подозрительные — процесс запущен из Temp/Downloads (типичное поведение стилеров/C2,
    которые «звонят домой»). Read-only. Возвращает {connections:[...], error}.

    Подключения к «плохим» адресам по фиду (ThreatFox) — на потом (нужен ключ/сеть)."""
    if psutil is None:
        return {"connections": [], "error": "psutil недоступен"}
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as e:
        return {"connections": [], "error": f"нет доступа к сетевым данным ({e}); попробуйте от админа"}

    procinfo: dict[int, tuple] = {}
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            procinfo[p.info["pid"]] = (p.info.get("name") or "", p.info.get("exe") or "")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    import ipaddress

    def _is_local(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_unspecified or a.is_reserved)
        except ValueError:
            return False

    conns: list[dict] = []
    seen: set = set()
    for c in raw:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        rip = c.raddr.ip
        if _is_local(rip):                        # внешние подключения, без локальных/приватных
            continue
        pid = c.pid or 0
        name, exe = procinfo.get(pid, ("", ""))
        key = (pid, rip, c.raddr.port)
        if key in seen:
            continue
        seen.add(key)
        reason = looks_suspicious({"exe": exe, "name": name})
        conns.append({"pid": pid, "name": name, "exe": exe,
                      "raddr": f"{rip}:{c.raddr.port}",
                      "suspicious": bool(reason), "reason": reason})
    conns.sort(key=lambda x: (not x["suspicious"], x["name"]))   # подозрительные вперёд
    return {"connections": conns, "error": None}


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
