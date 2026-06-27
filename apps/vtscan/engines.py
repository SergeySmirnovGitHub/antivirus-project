#!/usr/bin/env python3
"""
engines — общий интерфейс «движок проверки» и его реализации (этап 2).

Идея: у нас несколько независимых источников вердикта (VirusTotal онлайн,
ClamAV офлайн, в будущем — другие базы). Каждый движок умеет проверить файл и
вернуть единый EngineResult. Агрегатор объединяет их в итоговый вердикт.

Сам VirusTotal живёт в vtscan.py (там много специфики API); здесь — локальные
движки и общий контракт. Так проще наращивать источники, не переписывая остальное.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


def data_dir() -> Path:
    """СТАБИЛЬНАЯ папка данных приложения (ключи, источники, ClamAV, карантин, белый список).

    Для собранного exe — ВСЕГДА одно и то же место на пользователя, чтобы данные
    НЕ терялись при переустановке/обновлении и не зависели от того, откуда запущен exe:
      Windows → %LOCALAPPDATA%\\VTScan,  иначе → ~/.vtscan.
    В режиме разработки (запуск .py) — рядом со скриптом (так удобнее тестировать).
    Всё в ОДНОЙ папке (критерий «одна папка»); ключи хранятся только локально, наружу
    не уходят (кроме самих запросов к выбранным сервисам).
    """
    if getattr(sys, "frozen", False):
        if os.name == "nt":
            root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
            d = Path(root) / "VTScan"
        else:
            d = Path(os.path.expanduser("~")) / ".vtscan"
    else:
        d = Path(__file__).resolve().parent
    d.mkdir(parents=True, exist_ok=True)
    return d


def clamav_install_dir() -> Path:
    """Папка, куда ставится локальный ClamAV (внутри папки данных — «одна папка»)."""
    return data_dir() / "engines" / "clamav"


# --------------------------------------------------------------------------- #
#  Белый список (исключения) — по SHA-256. «Разрешить» добавляет сюда, и тогда
#  файл считается чистым (как у Defender — иначе он бы снова попал в карантин).
# --------------------------------------------------------------------------- #
def whitelist_path() -> Path:
    return data_dir() / "whitelist.json"


def load_whitelist() -> list[dict]:
    p = whitelist_path()
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
    return []


def is_whitelisted(sha256: str) -> bool:
    return any(x.get("hash") == sha256 for x in load_whitelist())


def add_to_whitelist(sha256: str, name: str = "") -> None:
    data = load_whitelist()
    if not any(x.get("hash") == sha256 for x in data):
        data.append({"hash": sha256, "name": name,
                     "ts": time.strftime("%Y-%m-%d %H:%M")})
        try:
            whitelist_path().write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
        except OSError:
            pass


def find_in_dir(root: Path, name: str) -> Path | None:
    """Рекурсивно ищет файл по имени внутри папки (устойчиво к вложенности архива)."""
    if not root.is_dir():
        return None
    for p in root.rglob(name):
        if p.is_file():
            return p
    return None


def _no_window_kwargs() -> dict:
    """На Windows скрываем консольное окно дочернего процесса — иначе при каждом
    вызове clamscan/freshclam мигает окно cmd (особенно в GUI без консоли)."""
    if os.name == "nt":
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


# Официальная портативная сборка ClamAV для Windows (редирект на CDN). Обновлять по мере выхода.
CLAMAV_WIN_URL = "https://www.clamav.net/downloads/production/clamav-1.4.3.win.x64.zip"


def provision_clamav(log: Callable[[str], None] = print) -> bool:
    """ЗАГРУЗЧИК: качает портативный ClamAV в папку приложения и обновляет базу.

    Реализует критерий «одна папка»: всё (clamscan + базы) ложится в
    data_dir()/engines/clamav, своя папка создаётся автоматически. Только Windows.
    """
    if os.name != "nt":
        log("Авто-установка ClamAV поддерживается только на Windows "
            "(на Mac движок ставится через Homebrew для разработки).")
        return False

    import zipfile
    try:
        import requests
    except ImportError:
        log("Нет библиотеки requests.")
        return False

    target = clamav_install_dir()
    target.mkdir(parents=True, exist_ok=True)
    zip_path = target / "_clamav_download.zip"

    log("Скачиваю ClamAV для Windows...")
    try:
        with requests.get(CLAMAV_WIN_URL, stream=True, timeout=180) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0))
            done = 0
            last_bucket = -1
            mb_total = total / (1024 * 1024) if total else 0
            with open(zip_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 256):
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = int(done * 100 / total)
                        bucket = pct // 5          # отчёт каждые 5%
                        if bucket > last_bucket:
                            last_bucket = bucket
                            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                            log(f"  [{bar}] {pct:3d}%  "
                                f"({done/1048576:.0f} из {mb_total:.0f} МБ)")
            if not total:
                log(f"  загружено {done/1048576:.0f} МБ")
    except Exception as e:  # noqa: BLE001
        log(f"Ошибка загрузки: {e}")
        return False

    log("Распаковываю...")
    try:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(target)
    except Exception as e:  # noqa: BLE001
        log(f"Архив повреждён: {e}")
        return False
    finally:
        try:
            zip_path.unlink()
        except OSError:
            pass

    clamscan = find_in_dir(target, "clamscan.exe")
    if clamscan is None:
        log("В архиве не найден clamscan.exe.")
        return False
    log(f"clamscan установлен: {clamscan}")

    # Обновляем базу сигнатур в свою папку db.
    db = target / "db"
    db.mkdir(exist_ok=True)
    freshclam = find_in_dir(target, "freshclam.exe")
    if freshclam is not None:
        log("Обновляю базу сигнатур (freshclam ~300 МБ, это надолго)...")
        conf = target / "freshclam.conf"
        conf.write_text(f"DatabaseMirror database.clamav.net\nDatabaseDirectory {db}\n",
                        encoding="utf-8")
        try:
            import subprocess
            subprocess.run([str(freshclam), f"--config-file={conf}", f"--datadir={db}"],
                           timeout=2400, **_no_window_kwargs())
        except Exception as e:  # noqa: BLE001
            log(f"freshclam не доработал ({e}); база подтянется при первом обновлении.")
    log("Готово: ClamAV в папке приложения. Перезапустите — он подключится автоматически.")
    return True

# Возможные статусы одного движка (и агрегированного вердикта):
#   clean        — движок проверил, угроз нет
#   malicious    — движок считает файл вредоносным
#   suspicious   — подозрительно
#   unknown      — движок не знает этот файл (напр., нет в базе VirusTotal)
#   error        — ошибка при проверке
#   unavailable  — движок не установлен/не настроен на этой машине


@dataclass
class EngineResult:
    engine: str                 # имя движка, напр. "VirusTotal" / "ClamAV"
    status: str                 # один из статусов выше
    detail: str = ""            # короткое человекочитаемое пояснение


def aggregate_status(statuses: list[str]) -> str:
    """Итоговый вердикт из набора статусов движков (по убыванию значимости).
    'unavailable' игнорируется — это не мнение, а отсутствие движка."""
    for level in ("malicious", "suspicious", "clean", "unknown", "skipped", "error"):
        if level in statuses:
            return level
    return "unknown"


class ClamAVEngine:
    """Локальный движок ClamAV: вызывает clamscan как отдельный процесс.

    Плюсы: офлайн, не упирается в лимиты VirusTotal, проверяет содержимое файла
    (а не только хэш) — поэтому даёт вердикт даже для неизвестных VirusTotal файлов.
    """

    name = "ClamAV"

    # Где искать clamscan, если его нет в PATH (типичные пути установки на Windows).
    _WINDOWS_FALLBACKS = (
        r"C:\Program Files\ClamAV\clamscan.exe",
        r"C:\Program Files (x86)\ClamAV\clamscan.exe",
        r"C:\ClamAV\clamscan.exe",
    )

    def __init__(self) -> None:
        self.bin: str | None = None
        self.db_dir: str | None = None      # папка с базой сигнатур (если своя, бундленная)
        self._locate()

    def _locate(self) -> None:
        exe_name = "clamscan.exe" if os.name == "nt" else "clamscan"
        # 1) ПРИОРИТЕТ — бундл в папке данных приложения (критерий «одна папка»).
        #    Ищем рекурсивно: zip ClamAV может распаковаться во вложенную папку.
        clam_root = clamav_install_dir()
        bundled = find_in_dir(clam_root, exe_name)
        if bundled is not None:
            self.bin = str(bundled)
            db = clam_root / "db"
            if db.is_dir():
                self.db_dir = str(db)
            return
        # 2) Системный PATH (удобно для разработки).
        found = shutil.which("clamscan")
        if found:
            self.bin = found
            return
        # 3) Типичные пути установки на Windows (на крайний случай).
        if os.name == "nt":
            for cand in self._WINDOWS_FALLBACKS:
                if Path(cand).is_file():
                    self.bin = cand
                    return

    def is_available(self) -> bool:
        return self.bin is not None

    def scan(self, path: Path) -> EngineResult:
        if not self.bin:
            return EngineResult(self.name, "unavailable", "не установлен")
        cmd = [self.bin, "--no-summary", "--stdout"]
        if self.db_dir:
            cmd.append(f"--database={self.db_dir}")
        cmd.append(str(path))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                                  **_no_window_kwargs())
        except (OSError, subprocess.SubprocessError) as e:
            return EngineResult(self.name, "error", str(e))

        out = (proc.stdout or "").strip()
        # Коды возврата clamscan: 0 — чисто, 1 — найден вирус, 2 — ошибка.
        if proc.returncode == 0:
            return EngineResult(self.name, "clean", "чисто")
        if proc.returncode == 1:
            name = _parse_clamav_detection(out)
            return EngineResult(self.name, "malicious", name or "обнаружено")
        err = (proc.stderr or out).strip().splitlines()
        return EngineResult(self.name, "error", err[-1] if err else "ошибка clamscan")


def _parse_clamav_detection(output: str) -> str:
    """Достаёт имя детекта из строки вида '<path>: Win.Test.EICAR_HDB-1 FOUND'."""
    for line in output.splitlines():
        line = line.strip()
        if line.endswith("FOUND"):
            after_colon = line.split(":", 1)[-1].strip()
            return after_colon[: -len("FOUND")].strip()
    return ""
