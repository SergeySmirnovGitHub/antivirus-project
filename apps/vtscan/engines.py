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

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def _exe_or_script_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _is_writable(p: Path) -> bool:
    try:
        t = p / ".vtscan_write_test"
        t.write_text("x", encoding="utf-8")
        t.unlink()
        return True
    except OSError:
        return False


def data_dir() -> Path:
    """Папка для данных приложения (ключ, локальные движки, базы) — КРИТЕРИЙ «одна папка».

    Портативный режим: рядом с exe/скриптом, если туда можно писать.
    Установленный режим (exe в Program Files, запись запрещена): %LOCALAPPDATA%\\VTScan
    (на других ОС — ~/.vtscan). Так всё лежит в ОДНОМ месте, а не разбросано.
    """
    base = _exe_or_script_dir()
    if _is_writable(base):
        return base
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = Path(root) / "VTScan"
    else:
        d = Path(os.path.expanduser("~")) / ".vtscan"
    d.mkdir(parents=True, exist_ok=True)
    return d

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
        bundled = data_dir() / "engines" / "clamav" / exe_name
        if bundled.is_file():
            self.bin = str(bundled)
            db = bundled.parent / "db"
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
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
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
