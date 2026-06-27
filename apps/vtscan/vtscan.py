#!/usr/bin/env python3
"""
vtscan — простой CLI-сканер файлов на базе VirusTotal API v3.

Что делает:
  1. Считает SHA-256 каждого файла.
  2. Спрашивает VirusTotal по этому хэшу (быстро, файл никуда не загружается).
  3. Если хэш неизвестен — по флагу --upload может загрузить сам файл на анализ.
  4. Печатает понятный вердикт: сколько движков считают файл вредоносным.

Документация API: https://docs.virustotal.com/reference/overview
Ключ берётся (в порядке приоритета): --api-key  →  переменная окружения VT_API_KEY
                                     →  файл .vtkey рядом со скриптом.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Не установлена библиотека 'requests'. Выполни:  pip install requests")

# Локальные движки проверки (этап 2): ClamAV и общий контракт «движок проверки».
from engines import (ClamAVEngine, EngineResult, aggregate_status, data_dir,
                     provision_clamav, is_whitelisted)
import sources  # доп. онлайн-источники (MalwareBazaar, OTX, Kaspersky)

# colorama включает поддержку ANSI-цветов в консоли Windows (cmd/PowerShell).
# Не критична: если её нет — просто выводим без цвета.
try:
    import colorama
    colorama.just_fix_windows_console()
except Exception:
    pass

VERSION = "0.25"
# Репозиторий для проверки обновлений (публичные релизы GitHub).
GITHUB_REPO = "SergeySmirnovGitHub/antivirus-project"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

# --------------------------------------------------------------------------- #
#  ANSI-цвета (кибер-вывод). Гасятся, если вывод не в терминал (пайп/файл).
# --------------------------------------------------------------------------- #
_COLOR_ENABLED = sys.stdout.isatty()


def _paint(text: str, code: str) -> str:
    if not _COLOR_ENABLED:
        return text
    return f"\033[{code}m{text}\033[0m"


def red(s: str) -> str:    return _paint(s, "91")
def green(s: str) -> str:  return _paint(s, "92")
def amber(s: str) -> str:  return _paint(s, "93")
def cyan(s: str) -> str:   return _paint(s, "96")
def dim(s: str) -> str:    return _paint(s, "90")
def bold(s: str) -> str:   return _paint(s, "1")


VT_API_BASE = "https://www.virustotal.com/api/v3"
# Лимит публичного (бесплатного) ключа: 4 запроса в минуту -> ждём ~16 сек между запросами.
PUBLIC_RATE_DELAY = 16.0
# Максимальный размер файла для загрузки на бесплатном тарифе.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024

# Короткие пояснения по типам угроз (категории из VirusTotal popular_threat_classification).
# Ключ — категория в нижнем регистре, значение — понятное описание «чем опасен».
THREAT_DESCRIPTIONS: dict[str, str] = {
    "trojan": "троян — маскируется под безобидную программу, а внутри делает вредоносное",
    "stealer": "стилер — крадёт пароли, токены, данные браузера и крипто-кошельков",
    "ransomware": "шифровальщик-вымогатель — шифрует файлы и требует выкуп",
    "spyware": "шпион — скрытно следит и собирает данные о пользователе",
    "keylogger": "кейлоггер — перехватывает нажатия клавиш (пароли, переписку)",
    "backdoor": "бэкдор — открывает злоумышленнику скрытый удалённый доступ",
    "rat": "RAT — троян удалённого управления, даёт полный контроль над ПК",
    "worm": "червь — сам распространяется по сети и съёмным носителям",
    "virus": "вирус — внедряется в другие файлы и заражает их",
    "rootkit": "руткит — прячет своё присутствие глубоко в системе",
    "downloader": "загрузчик — тихо подтягивает и ставит другие вредоносы",
    "dropper": "дроппер — несёт внутри и распаковывает вредоносную нагрузку",
    "adware": "рекламное ПО — навязывает рекламу, подменяет поисковую выдачу",
    "miner": "майнер — тайно нагружает ваше железо для добычи криптовалюты",
    "coinminer": "майнер — тайно нагружает ваше железо для добычи криптовалюты",
    "exploit": "эксплойт — использует уязвимость, чтобы запустить чужой код",
    "hacktool": "хак-инструмент — утилита для взлома и обхода защиты",
    "pua": "PUA — потенциально нежелательная программа: не вирус, но навязчивая/рискованная",
    "pup": "PUP — потенциально нежелательная программа: не вирус, но навязчивая/рискованная",
}


def describe_threat(category: str) -> str:
    """Возвращает пояснение по категории угрозы (или пустую строку, если её нет в словаре)."""
    return THREAT_DESCRIPTIONS.get(category.lower(), "")


# --------------------------------------------------------------------------- #
#  Модель результата
# --------------------------------------------------------------------------- #
@dataclass
class ScanResult:
    path: Path
    sha256: str
    size: int
    status: str                       # clean | malicious | suspicious | unknown | error | skipped
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    engines_total: int = 0
    top_detections: list[str] = field(default_factory=list)
    threat_label: str = ""                          # сводная метка VirusTotal, напр. "trojan.eicar/test"
    threat_categories: list[str] = field(default_factory=list)  # типы угрозы: trojan, stealer, ...
    threat_names: list[str] = field(default_factory=list)       # имена семейств: eicar, agenttesla, ...
    engine_results: list = field(default_factory=list)          # разбивка по источникам (EngineResult)
    message: str = ""

    @property
    def verdict_label(self) -> str:
        return {
            "clean": "ЧИСТО",
            "malicious": "ВРЕДОНОСНЫЙ",
            "suspicious": "ПОДОЗРИТЕЛЬНЫЙ",
            "unknown": "НЕИЗВЕСТЕН",
            "error": "ОШИБКА",
            "skipped": "ПРОПУЩЕН",
        }.get(self.status, self.status.upper())


# --------------------------------------------------------------------------- #
#  Работа с ключом и хэшами
# --------------------------------------------------------------------------- #
def key_file_path() -> Path:
    """Путь к .vtkey — в писчей папке данных приложения (рядом с exe для портативной
    версии, %LOCALAPPDATA%\\VTScan для установленной). Единая «одна папка»."""
    return data_dir() / ".vtkey"


def resolve_api_key(cli_key: str | None) -> str | None:
    if cli_key:
        return cli_key.strip()
    env_key = os.environ.get("VT_API_KEY")
    if env_key:
        return env_key.strip()
    key_file = key_file_path()
    if key_file.is_file():
        return key_file.read_text(encoding="utf-8").strip()
    return None


def save_api_key(key: str) -> Path:
    """Сохраняет ключ в .vtkey рядом с программой. Возвращает путь к файлу."""
    path = key_file_path()
    path.write_text(key.strip(), encoding="utf-8")
    return path


def sha256_of_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
#  Запросы к VirusTotal
# --------------------------------------------------------------------------- #
class VirusTotalClient:
    def __init__(self, api_key: str, timeout: float = 30.0):
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "accept": "application/json"})
        self.timeout = timeout

    def lookup_hash(self, sha256: str) -> dict | None:
        """Возвращает объект файла или None, если хэш неизвестен (404)."""
        url = f"{VT_API_BASE}/files/{sha256}"
        resp = self.session.get(url, timeout=self.timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def upload_file(self, path: Path) -> str:
        """Загружает файл, возвращает analysis_id."""
        url = f"{VT_API_BASE}/files"
        with path.open("rb") as f:
            resp = self.session.post(url, files={"file": (path.name, f)}, timeout=120)
        resp.raise_for_status()
        return resp.json()["data"]["id"]

    def wait_for_analysis(self, analysis_id: str, max_wait: float = 300.0) -> dict:
        """Опрашивает статус анализа, пока он не завершится."""
        url = f"{VT_API_BASE}/analyses/{analysis_id}"
        waited = 0.0
        while True:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            if data["data"]["attributes"]["status"] == "completed":
                return data
            if waited >= max_wait:
                raise TimeoutError("Анализ не завершился за отведённое время.")
            time.sleep(PUBLIC_RATE_DELAY)
            waited += PUBLIC_RATE_DELAY


# --------------------------------------------------------------------------- #
#  Разбор статистики движков
# --------------------------------------------------------------------------- #
def build_result_from_attributes(path: Path, sha256: str, size: int, attrs: dict) -> ScanResult:
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total = malicious + suspicious + harmless + undetected + int(stats.get("timeout", 0))

    if malicious > 0:
        status = "malicious"
    elif suspicious > 0:
        status = "suspicious"
    else:
        status = "clean"

    # Имена движков, которые задетектили (до 5 штук).
    top: list[str] = []
    for engine, res in (attrs.get("last_analysis_results") or {}).items():
        if res.get("category") in ("malicious", "suspicious"):
            label = res.get("result") or res.get("category")
            top.append(f"{engine}: {label}")
        if len(top) >= 5:
            break

    # Классификация угрозы: чем именно опасен файл (тип + имя семейства).
    ptc = attrs.get("popular_threat_classification") or {}
    threat_label = (ptc.get("suggested_threat_label") or "").strip()
    threat_categories = [c.get("value") for c in (ptc.get("popular_threat_category") or []) if c.get("value")]
    threat_names = [n.get("value") for n in (ptc.get("popular_threat_name") or []) if n.get("value")]

    return ScanResult(
        path=path, sha256=sha256, size=size, status=status,
        malicious=malicious, suspicious=suspicious, harmless=harmless,
        undetected=undetected, engines_total=total, top_detections=top,
        threat_label=threat_label, threat_categories=threat_categories,
        threat_names=threat_names,
    )


# Один экземпляр локального движка ClamAV на сеанс (бинарь ищется один раз).
_clamav_engine: ClamAVEngine | None = None


def clamav_engine() -> ClamAVEngine:
    global _clamav_engine
    if _clamav_engine is None:
        _clamav_engine = ClamAVEngine()
    return _clamav_engine


def _scan_virustotal(client: VirusTotalClient, path: Path, digest: str,
                     size: int, do_upload: bool) -> ScanResult:
    """Проверка через VirusTotal (хэш уже посчитан). Статус — мнение только VT."""
    try:
        data = client.lookup_hash(digest)
        if data is not None:
            attrs = data["data"]["attributes"]
            return build_result_from_attributes(path, digest, size, attrs)

        # Хэш неизвестен.
        if not do_upload:
            return ScanResult(path=path, sha256=digest, size=size, status="unknown",
                              message="Хэш не найден в базе VirusTotal (используй --upload, чтобы загрузить файл).")

        if size > MAX_UPLOAD_BYTES:
            return ScanResult(path=path, sha256=digest, size=size, status="skipped",
                              message=f"Файл больше {MAX_UPLOAD_BYTES // (1024*1024)} МБ — пропущен (лимит бесплатного API).")

        analysis_id = client.upload_file(path)
        client.wait_for_analysis(analysis_id)
        # После анализа перечитываем объект файла, чтобы получить агрегированную статистику.
        data = client.lookup_hash(digest)
        if data is None:
            return ScanResult(path=path, sha256=digest, size=size, status="unknown",
                              message="Файл загружен, но отчёт ещё не готов. Повтори позже.")
        attrs = data["data"]["attributes"]
        return build_result_from_attributes(path, digest, size, attrs)

    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else "?"
        msg = f"HTTP {code}"
        if code == 401:
            msg += " — неверный API-ключ."
        elif code == 429:
            msg += " — превышен лимит запросов, подожди минуту."
        return ScanResult(path=path, sha256=digest, size=size, status="error", message=msg)
    except (requests.RequestException, TimeoutError) as e:
        return ScanResult(path=path, sha256=digest, size=size, status="error", message=str(e))


def _vt_engine_result(r: ScanResult) -> EngineResult:
    """Строка-источник 'VirusTotal' для разбивки по движкам."""
    detail = {
        "malicious": (f"{r.malicious}/{r.engines_total} опасен" if r.engines_total else "опасен"),
        "suspicious": f"{r.suspicious} подозрительных",
        "clean": "чисто",
        "unknown": "нет в базе",
        "skipped": "пропущен",
    }.get(r.status, r.message or "ошибка")
    return EngineResult("VirusTotal", r.status, detail)


def scan_one(client: VirusTotalClient, path: Path, do_upload: bool) -> ScanResult:
    """Проверяет файл всеми доступными движками и агрегирует итоговый вердикт."""
    try:
        size = path.stat().st_size
        digest = sha256_of_file(path)
    except OSError as e:
        return ScanResult(path=path, sha256="", size=0, status="error", message=str(e))

    # 0) Белый список (исключения): пользователь сам разрешил этот файл — считаем чистым.
    if is_whitelisted(digest):
        r = ScanResult(path=path, sha256=digest, size=size, status="clean",
                       message="в белом списке (разрешён вами)")
        r.engine_results = [EngineResult("Белый список", "clean", "разрешён вами")]
        return r

    # 1) VirusTotal (онлайн, по хэшу).
    result = _scan_virustotal(client, path, digest, size, do_upload)
    engines: list[EngineResult] = [_vt_engine_result(result)]

    # 2) ClamAV (локально, офлайн) — проверяет содержимое файла.
    #    scan() сам вернёт 'unavailable', если движок не установлен/не бундлен.
    engines.append(clamav_engine().scan(path))

    # 3) Доп. онлайн-источники по хэшу (только те, для которых задан ключ).
    for src, key in sources.configured_sources():
        engines.append(src.scan_hash(digest, key))

    # 4) Агрегируем вердикт по всем источникам.
    result.engine_results = engines
    result.status = aggregate_status([e.status for e in engines])
    return result


# --------------------------------------------------------------------------- #
#  Сбор файлов
# --------------------------------------------------------------------------- #
def collect_files(target: Path, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        it = target.rglob("*") if recursive else target.glob("*")
        return sorted(p for p in it if p.is_file())
    return []


# --------------------------------------------------------------------------- #
#  Вывод
# --------------------------------------------------------------------------- #
def print_human(result: ScanResult) -> None:
    icon = {
        "clean": "[+]", "malicious": "[!]", "suspicious": "[?]",
        "unknown": "[ ]", "error": "[x]", "skipped": "[-]",
    }.get(result.status, "[ ]")
    paint = {
        "clean": green, "malicious": red, "suspicious": amber,
        "unknown": dim, "error": red, "skipped": dim,
    }.get(result.status, lambda s: s)

    print(f"{paint(icon + ' ' + result.verdict_label)}   {result.path.name}")
    # Чем именно опасен: тип угрозы + понятное описание (из VirusTotal).
    if result.threat_categories:
        primary = result.threat_categories[0]
        print(dim("      тип угрозы: ") + amber(describe_threat(primary) or primary))
        others = result.threat_categories[1:]
        if others:
            print(dim("        также отмечен как: ") + ", ".join(others))
    if result.threat_names:
        print(dim("      семейство: ") + amber(", ".join(result.threat_names[:3])))
    # Разбивка по источникам (движкам).
    marks = {
        "malicious": red("●"), "suspicious": amber("●"), "clean": green("●"),
        "unknown": dim("○"), "skipped": dim("○"), "error": dim("x"),
        "unavailable": dim("·"),
    }
    n = len(result.engine_results)
    for i, er in enumerate(result.engine_results):
        branch = "└" if i == n - 1 else "├"
        mark = marks.get(er.status, dim("○"))
        print(f"      {dim(branch)} {er.engine:<13}{mark} {dim(er.detail)}")
    if result.message and result.status in ("unknown", "skipped", "error"):
        print(dim(f"      {result.message}"))
    print(dim(f"      sha256: {result.sha256}"))


def print_summary(results: list[ScanResult]) -> None:
    mal = sum(1 for r in results if r.status == "malicious")
    sus = sum(1 for r in results if r.status == "suspicious")
    unk = sum(1 for r in results if r.status == "unknown")
    err = sum(1 for r in results if r.status == "error")
    clean = sum(1 for r in results if r.status == "clean")
    print("\n" + dim("=" * 50))
    print(f"Итого: {len(results)} файл(ов) | чисто: {green(str(clean))} | "
          f"вредоносных: {red(str(mal))} | подозрительных: {amber(str(sus))} | "
          f"неизвестных: {unk} | ошибок: {err}")
    if mal:
        print(red(bold("ВНИМАНИЕ: обнаружены вредоносные файлы!")))


# --------------------------------------------------------------------------- #
#  Запуск сканирования (общий для обычного и интерактивного режима)
# --------------------------------------------------------------------------- #
def run_scan(client: VirusTotalClient, target: Path, recursive: bool = False,
             upload: bool = False, delay: float = PUBLIC_RATE_DELAY,
             as_json: bool = False) -> list[ScanResult]:
    files = collect_files(target, recursive)
    if not files:
        print(red(f"Не найдено файлов по пути: {target}"))
        return []

    if not as_json:
        print(dim(f"Проверяю {len(files)} файл(ов)...\n"))

    results: list[ScanResult] = []
    for i, path in enumerate(files):
        result = scan_one(client, path, upload)
        results.append(result)
        if not as_json:
            print_human(result)
        # Пауза между сетевыми запросами, кроме последнего файла.
        if i < len(files) - 1 and result.status not in ("error", "skipped"):
            time.sleep(delay)

    if as_json:
        print(json.dumps([{
            "path": str(r.path), "sha256": r.sha256, "size": r.size,
            "status": r.status, "malicious": r.malicious, "suspicious": r.suspicious,
            "engines_total": r.engines_total, "top_detections": r.top_detections,
            "threat_label": r.threat_label, "threat_categories": r.threat_categories,
            "threat_names": r.threat_names, "message": r.message,
        } for r in results], ensure_ascii=False, indent=2))
    else:
        print_summary(results)

    return results


def has_malicious(results: list[ScanResult]) -> bool:
    return any(r.status == "malicious" for r in results)


# --------------------------------------------------------------------------- #
#  Сканирование компьютера (быстрый/полный скан через ClamAV офлайн)
# --------------------------------------------------------------------------- #
#  VirusTotal для массового скана не годится (лимит ~4 файла/мин на бесплатном
#  ключе), поэтому скан компьютера идёт через локальный ClamAV — без лимитов и сети.
def quick_scan_dirs() -> list[Path]:
    """Папки повышенного риска для БЫСТРОГО скана (там заводится большинство заразы)."""
    home = Path.home()
    env = os.environ
    cands: list[Path | None] = [
        home / "Downloads",
        home / "Desktop",
        Path(env["TEMP"]) if env.get("TEMP") else None,
        (Path(env["LOCALAPPDATA"]) / "Temp") if env.get("LOCALAPPDATA") else None,
        (Path(env["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        if env.get("APPDATA") else None,
    ]
    seen: set[Path] = set()
    out: list[Path] = []
    for c in cands:
        if c and c.is_dir():
            rc = c.resolve()
            if rc not in seen:
                seen.add(rc)
                out.append(c)
    return out


def full_scan_dirs(root: Path | None = None) -> list[Path]:
    """Папки для ПОЛНОГО скана. По умолчанию — весь профиль пользователя."""
    if root is not None:
        return [root]
    return [Path.home()]


def usb_scan_dirs() -> list[Path]:
    """Корни подключённых СЪЁМНЫХ дисков (USB-флешки) — для скана съёмных носителей."""
    out: list[Path] = []
    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            if "removable" in (part.opts or "").lower() and part.mountpoint:
                p = Path(part.mountpoint)
                if p.exists():
                    out.append(p)
    except Exception:  # noqa: BLE001
        pass
    return out


def count_files(dirs: list[Path]) -> int:
    """Сколько файлов предстоит проверить (для прогресса «X из N»). Это ОЦЕНКА:
    clamscan может считать иначе (заглядывает в архивы, пропускает спецфайлы)."""
    total = 0
    for d in dirs:
        d = Path(d)
        if d.is_file():
            total += 1
            continue
        for _root, _subdirs, files in os.walk(d):
            total += len(files)
    return total


def run_computer_scan(mode: str = "quick", root: Path | None = None) -> int:
    """Скан компьютера в консоли: прогресс в одну строку + предложение карантина.
    Возвращает код возврата: 1 — найдена зараза, 2 — ошибка/нет движка, 0 — чисто."""
    eng = clamav_engine()
    if not eng.is_available():
        print(amber("Для сканирования компьютера нужен офлайн-движок ClamAV "
                    "(VirusTotal не подходит — лимит запросов)."))
        print(dim("Установите его командой: ") + bold("setup-clamav"))
        return 2
    if mode == "usb":
        dirs = usb_scan_dirs()
    elif mode == "quick":
        dirs = quick_scan_dirs()
    else:
        dirs = full_scan_dirs(root)
    if not dirs:
        if mode == "usb":
            print(amber("Съёмные диски (USB) не найдены — вставьте флешку и повторите."))
        else:
            print(red("Не найдено папок для проверки."))
        return 2
    label = {"quick": "Быстрый", "full": "Полный", "usb": "USB"}.get(mode, "")
    print(cyan(bold(f"{label} скан компьютера")) + dim("  (ClamAV, офлайн)"))
    print(dim("Папки: " + ", ".join(str(d) for d in dirs)))
    print(dim("Считаю файлы..."), end="\r", flush=True)
    total = count_files(dirs)
    print(dim(f"Всего файлов: ~{total}.  Ctrl+C — прервать.") + " " * 20 + "\n")

    state = {"last": 0.0}

    def on_file(n: int, path: str) -> None:
        now = time.time()
        if now - state["last"] >= 0.3:        # не чаще ~3 раз в секунду — не спамим консоль
            state["last"] = now
            left = max(0, total - n)
            short = path if len(path) <= 50 else "…" + path[-49:]
            print(dim(f"  проверено {n} из ~{total} (осталось ~{left})   {short}").ljust(96),
                  end="\r", flush=True)

    try:
        res = eng.scan_tree(dirs, on_file=on_file)
    except KeyboardInterrupt:
        print("\n" + dim("Прервано."))
        return 1
    print(" " * 90, end="\r")               # стереть строку прогресса
    if res.get("error"):
        print(red(f"Ошибка скана: {res['error']}"))
        return 2
    infected = res.get("infected", [])
    print(dim("=" * 50))
    if infected:
        print(f"Проверено файлов: {res['scanned']}   " +
              red(bold(f"заражённых: {len(infected)}")))
        for it in infected:
            print(red(f"  [!] {it['name']}  ") + dim(it["path"]))
        try:
            ans = input(amber("\nПоместить найденные в карантин? (y/n): ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = "n"
        if ans in ("y", "yes", "д", "да"):
            import monitor as monitor_mod
            done = sum(1 for it in infected
                       if monitor_mod.quarantine_file(Path(it["path"])))
            print(green(f"В карантин помещено: {done} из {len(infected)}."))
        return 1
    print(f"Проверено файлов: {res['scanned']}   " + green("угроз не найдено"))
    return 0


def _clamav_scan_tree():
    """Метод scan_tree движка ClamAV (для пакетного скана exe процессов) или None."""
    eng = clamav_engine()
    return eng.scan_tree if eng.is_available() else None


def run_memory_scan() -> int:
    """Скан памяти: проверка запущенных процессов (эвристика + скан exe движком),
    с предложением заморозить подозрительные. Возвращает 1 если найдено, иначе 0."""
    import monitor as monitor_mod
    print(cyan(bold("Скан памяти — запущенные процессы")))
    st = _clamav_scan_tree()
    if st is None:
        print(dim("ClamAV не установлен — проверка только по поведению (без скана файлов). "
                  "Полнее с ClamAV: ") + bold("setup-clamav"))

    state = {"last": 0.0}

    def on_progress(n: int, total: int, name: str) -> None:
        now = time.time()
        if now - state["last"] >= 0.2:
            state["last"] = now
            print(dim(f"  скан exe: {n}/{total}   {name}").ljust(72), end="\r", flush=True)

    res = monitor_mod.scan_processes(scan_tree=st, on_progress=on_progress)
    print(" " * 72, end="\r")
    if res.get("error"):
        print(red(f"Ошибка: {res['error']}"))
        return 2
    findings = res["findings"]
    print(dim("=" * 50))
    if not findings:
        print(green(f"Проверено процессов: {res['checked']}. Подозрительных не найдено."))
        return 0
    print(f"Проверено: {res['checked']}   " + red(bold(f"подозрительных: {len(findings)}")))
    for it in findings:
        paint = red if it["status"] == "malicious" else amber
        mark = "!" if it["status"] == "malicious" else "?"
        print(paint(f"  [{mark}] {it['name']} (pid {it['pid']})") + dim(f"  — {it['reason']}"))
        if it["exe"]:
            print(dim(f"      {it['exe']}"))
    try:
        ans = input(amber("\nЗаморозить (приостановить) подозрительные процессы? (y/n): ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        ans = "n"
    if ans in ("y", "yes", "д", "да"):
        done = sum(1 for it in findings if monitor_mod.suspend_process(it["pid"]))
        print(green(f"Заморожено: {done} из {len(findings)} (обратимо — resume вернёт)."))
    return 1


def run_network_scan() -> int:
    """Сетевой монитор: активные внешние подключения по процессам, подозрительные —
    вперёд, с предложением заморозить. Возвращает 1 если есть подозрительные, иначе 0."""
    import monitor as monitor_mod
    print(cyan(bold("Сетевой монитор — активные подключения")))
    res = monitor_mod.scan_network()
    if res.get("error"):
        print(amber(res["error"]))
        return 2
    conns = res["connections"]
    if not conns:
        print(green("Активных внешних подключений не найдено."))
        return 0
    susp = [c for c in conns if c["suspicious"]]
    print(dim(f"Всего подключений: {len(conns)}, подозрительных: {len(susp)}\n"))
    for c in conns:
        if c["suspicious"]:
            print(amber(f"  [?] {c['name']} (pid {c['pid']}) → {c['raddr']}")
                  + dim(f"  — {c['reason']}"))
        else:
            print(dim(f"      {c['name']} (pid {c['pid']}) → {c['raddr']}"))
    if susp:
        try:
            ans = input(amber("\nЗаморозить подозрительные процессы? (y/n): ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            ans = "n"
        if ans in ("y", "yes", "д", "да"):
            done = len({c["pid"] for c in susp if monitor_mod.suspend_process(c["pid"])})
            print(green(f"Заморожено процессов: {done}."))
        return 1
    return 0


# --------------------------------------------------------------------------- #
#  Интерактивный кибер-терминал
# --------------------------------------------------------------------------- #
def print_banner() -> None:
    print()
    print("  " + cyan(bold("VTSCAN")) + dim(f"  // кибер-сканер файлов  v{VERSION}"))
    sources = "VirusTotal" + (" + ClamAV" if clamav_engine().is_available() else "")
    print("  " + dim(f"источники: {sources}   ·   help — команды, exit — выход"))
    print()


_HELP_BASIC = [
    ("scan <путь>", "проверить файл или папку"),
    ("quickscan", "быстрый скан опасных папок (ClamAV)"),
    ("fullscan", "полный скан профиля (ClamAV)"),
    ("scan memory", "скан запущенных процессов (память)"),
    ("scan network", "активные сетевые подключения"),
    ("scan usb", "скан подключённых USB-флешек"),
    ("monitor", "фоновая защита (Ctrl+C — стоп)"),
    ("key", "ввести / обновить ключ VirusTotal"),
    ("clear", "очистить экран"),
    ("help", "команды (help advanced — продвинутые)"),
    ("exit", "выйти"),
]
_HELP_ADVANCED = [
    ("keys", "доп. источники (MalwareBazaar, Kaspersky…) и их ключи"),
    ("autostart", "запуск фоновой защиты с Windows (on/off)"),
    ("admin", "права администратора (статус / перезапуск с UAC)"),
    ("where", "показать папку данных приложения"),
    ("setup-clamav", "скачать локальный движок ClamAV"),
    ("make-eicar", "создать безвредные тест-файлы (EICAR)"),
    ("selftest", "проверка уведомлений (имитация)"),
    ("check-update", "проверить и установить обновление"),
    ("cd <путь>", "сменить текущую папку"),
    ("version", "версия программы"),
]


_HELP_TEST = [
    ("selftest", "имитация уведомления + тестовый карантин"),
    ("make-eicar", "создать безвредные EICAR-файлы для проверки детекта"),
    ("test-ransomware", "имитация срабатывания приманки-шифровальщика"),
    ("test-autostart", "имитация алерта «новое в автозагрузке»"),
]


def print_help(tier: str = "basic") -> None:
    rows = {"basic": _HELP_BASIC, "advanced": _HELP_ADVANCED, "test": _HELP_TEST}.get(tier, _HELP_BASIC)
    title = {"basic": "Команды:", "advanced": "Продвинутые команды:",
             "test": "Тестовые команды:"}.get(tier, "Команды:")
    print(bold(title))
    for cmd, desc in rows:
        print("  " + cyan(f"{cmd:<16}") + dim(desc))
    if tier == "basic":
        print("  " + dim("ещё: ") + cyan("help advanced") + dim(" · ") + cyan("help test"))
    print()


def make_prompt() -> str:
    # Prompt подстраивается под компьютер: показываем реальную текущую папку.
    return cyan("vtscan ") + dim(os.getcwd()) + cyan("> ")


def ask_and_save_key() -> str | None:
    """Спрашивает ключ у пользователя и сохраняет его рядом с программой."""
    print(amber("Нужен бесплатный ключ VirusTotal: https://www.virustotal.com/gui/join-us"))
    try:
        key = input("Вставьте ключ (Enter — отмена): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not key:
        return None
    path = save_api_key(key)
    print(green(f"Ключ сохранён: {path}"))
    return key


# --------------------------------------------------------------------------- #
#  Интеграция в правый клик Windows (контекстное меню)
# --------------------------------------------------------------------------- #
def _exe_command() -> str:
    """Командная строка для запуска сканера с выбранным файлом (%1)."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --pause "%1"'
    script = os.path.abspath(__file__)
    return f'"{sys.executable}" "{script}" --pause "%1"'


def install_context_menu(quiet: bool = False) -> None:
    """Регистрирует пункт правого клика «Проверить VT-сканером» для всех файлов.
    Пишем в HKEY_CURRENT_USER — без прав администратора. Идемпотентно
    (вызывается автоматически при каждом запуске)."""
    if os.name != "nt":
        if not quiet:
            print(red("Контекстное меню доступно только в Windows."))
        return
    import winreg
    base = r"Software\Classes\*\shell\VTScan"
    icon = sys.executable if getattr(sys, "frozen", False) else ""
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, "Проверить VT-сканером")
            if icon:
                winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, icon)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, base + r"\command") as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _exe_command())
        if not quiet:
            print(green("Готово! Правый клик по файлу → «Проверить VT-сканером»."))
            print(dim("В Windows 11 пункт ищи в «Показать дополнительные параметры»."))
    except OSError as e:
        if not quiet:
            print(red(f"Не удалось добавить пункт меню: {e}"))


def remove_context_menu() -> None:
    """Убирает пункт правого клика."""
    if os.name != "nt":
        print(red("Только для Windows."))
        return
    import winreg
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\*\shell\VTScan\command")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\*\shell\VTScan")
        print(green("Пункт меню удалён."))
    except FileNotFoundError:
        print(dim("Пункт меню не найден (уже удалён?)."))
    except OSError as e:
        print(red(f"Не удалось удалить: {e}"))


# --------------------------------------------------------------------------- #
#  Автозапуск с Windows (фоновая защита стартует при входе в систему)
# --------------------------------------------------------------------------- #
#  Два механизма:
#   • Запланированная задача с наивысшими правами (если есть админ) — стартует
#     ELEVATED при каждом входе БЕЗ окна UAC. Это «всегда максимальные права».
#   • Ключ HKCU\...\Run — обычный автозапуск (без повышения), запасной вариант,
#     когда прав администратора нет (создать задачу с /RL HIGHEST нельзя без админа).
_AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_AUTOSTART_NAME = "VTScan"
_TASK_NAME = "VTScan"


def _no_window_kwargs() -> dict:
    return {"creationflags": 0x08000000} if os.name == "nt" else {}   # CREATE_NO_WINDOW


def _autostart_command() -> str:
    """Команда автозапуска. Флаг --tray = старт в трее с фоновой защитой (без окна)."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --tray'
    pyw = Path(sys.executable).with_name("pythonw.exe")
    py = str(pyw) if pyw.exists() else sys.executable
    gui = Path(__file__).resolve().parent / "gui.py"
    return f'"{py}" "{gui}" --tray'


# --- запланированная задача (elevated autostart) ---
def _task_exists() -> bool:
    if os.name != "nt":
        return False
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", _TASK_NAME],
                           capture_output=True, **_no_window_kwargs())
        return r.returncode == 0
    except OSError:
        return False


def _create_task() -> bool:
    """Задача: запуск при входе с наивысшими правами. Нужен админ (один раз)."""
    if os.name != "nt":
        return False
    try:
        r = subprocess.run(
            ["schtasks", "/Create", "/TN", _TASK_NAME, "/TR", _autostart_command(),
             "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"],
            capture_output=True, text=True, **_no_window_kwargs())
        return r.returncode == 0
    except OSError:
        return False


def _delete_task() -> bool:
    if os.name != "nt":
        return False
    try:
        r = subprocess.run(["schtasks", "/Delete", "/TN", _TASK_NAME, "/F"],
                           capture_output=True, **_no_window_kwargs())
        return r.returncode == 0
    except OSError:
        return False


# --- ключ реестра (обычный автозапуск) ---
def _run_key_exists() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY) as k:
            winreg.QueryValueEx(k, _AUTOSTART_NAME)
            return True
    except OSError:
        return False


def _set_run_key() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY) as k:
            winreg.SetValueEx(k, _AUTOSTART_NAME, 0, winreg.REG_SZ, _autostart_command())
        return True
    except OSError:
        return False


def _remove_run_key() -> bool:
    if os.name != "nt":
        return True
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _AUTOSTART_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, _AUTOSTART_NAME)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


# --- общий интерфейс автозапуска ---
def autostart_enabled() -> bool:
    return _task_exists() or _run_key_exists()


def autostart_mode() -> str:
    """'task' — elevated (задача), 'run' — обычный (реестр), 'off' — выключен."""
    if _task_exists():
        return "task"
    if _run_key_exists():
        return "run"
    return "off"


def enable_autostart() -> bool:
    """Включить автозапуск. С правами админа — задача с наивысшими правами (всегда
    elevated при входе). Без админа — обычный ключ реестра (без повышения)."""
    if os.name != "nt":
        return False
    if is_admin() and _create_task():
        _remove_run_key()              # убираем дублирующий обычный автозапуск
        return True
    return _set_run_key()              # запасной путь без админа


def disable_autostart() -> bool:
    if os.name != "nt":
        return False
    ok_task = _delete_task() if _task_exists() else True
    ok_run = _remove_run_key()
    return ok_task and ok_run


# --------------------------------------------------------------------------- #
#  Права администратора (уровень прав 2): запуск с повышением через UAC
# --------------------------------------------------------------------------- #
def is_admin() -> bool:
    """Запущены ли мы с правами администратора."""
    if os.name != "nt":
        return bool(getattr(os, "geteuid", lambda: 1)() == 0)
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _quote_arg(a: str) -> str:
    return f'"{a}"' if (not a or " " in a) else a


def relaunch_as_admin() -> bool:
    """Перезапуск с правами администратора через UAC (ShellExecute 'runas').
    True — повышение инициировано (текущий процесс надо закрыть); False — уже админ,
    UAC отменён или не Windows. Манифест не нужен: повышаем по требованию, не каждый старт."""
    if os.name != "nt" or is_admin():
        return False
    try:
        import ctypes
        if getattr(sys, "frozen", False):
            exe = sys.executable                # собранный GUI-exe (без консоли)
            args = sys.argv[1:]
        else:
            # dev: запускаем через pythonw.exe — иначе всплывает лишнее окно консоли,
            # которое к тому же является родителем GUI (закрыл консоль → закрылось всё).
            pyw = Path(sys.executable).with_name("pythonw.exe")
            exe = str(pyw) if pyw.exists() else sys.executable
            script = (os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0]
                      else os.path.abspath(__file__))
            args = [script] + sys.argv[1:]
        params = " ".join(_quote_arg(a) for a in args)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(rc) > 32                    # >32 = успех (иначе ошибка/отмена UAC)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
#  Авто-обновление (проверка публичных релизов на GitHub)
# --------------------------------------------------------------------------- #
def exe_dir() -> Path:
    """Папка, где лежит программа (рядом с exe или со скриптом)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _version_tuple(s: str) -> tuple:
    nums = []
    for part in s.strip().lstrip("vV").split("."):
        if part.isdigit():
            nums.append(int(part))
        else:
            break
    return tuple(nums)


def fetch_latest_release(timeout: float = 6.0):
    """Возвращает (версия, [(имя_ассета, ссылка), ...]) последнего релиза или None."""
    resp = requests.get(GITHUB_API_LATEST, timeout=timeout,
                        headers={"accept": "application/vnd.github+json"})
    if resp.status_code != 200:
        return None
    data = resp.json()
    tag = (data.get("tag_name") or "").strip()
    if not tag:
        return None
    assets = [(a.get("name") or "", a.get("browser_download_url"))
              for a in data.get("assets", []) if a.get("browser_download_url")]
    return tag.lstrip("vV"), assets


def _asset_url_for_current_exe(assets: list) -> str | None:
    """Выбирает ассет под текущий запущенный exe (их в релизе несколько: GUI и CLI)."""
    cur = Path(sys.executable).name.lower()
    for name, url in assets:
        if name.lower() == cur:
            return url
    for name, url in assets:  # запасной вариант — любой .exe
        if name.lower().endswith(".exe"):
            return url
    return None


def _old_exe_path() -> Path:
    # Имя временного файла зависит от текущего exe (чтобы GUI и CLI не конфликтовали).
    stem = Path(sys.executable).stem if getattr(sys, "frozen", False) else "vtscan"
    return exe_dir() / f"{stem}-old.exe"


def cleanup_old_update() -> None:
    """Удаляет остаток прошлого обновления (<exe>-old.exe)."""
    try:
        old = _old_exe_path()
        if old.exists():
            old.unlink()
    except OSError:
        pass


def notify_if_update_available() -> None:
    """Тихая проверка при старте — только уведомление, без скачивания."""
    try:
        latest = fetch_latest_release(timeout=4.0)
    except Exception:
        return  # офлайн/недоступно — молча пропускаем
    if not latest:
        return
    ver, _ = latest
    if _version_tuple(ver) > _version_tuple(VERSION):
        print(amber(f"  Доступна новая версия {ver} (у вас {VERSION}). ") +
              dim("Команда ") + bold("check-update") + dim(" — обновить."))
        print()


def _apply_update(exe_url: str, ver: str, log=None) -> bool:
    """Скачивает новый exe и заменяет текущий (на Windows — через переименование).
    log(text) — куда писать прогресс (по умолчанию в консоль). Возвращает успех."""
    if log is None:
        log = lambda m: print(dim(m))
    if not getattr(sys, "frozen", False):
        log("Режим разработки (.py): обновление применяется только к собранному .exe.")
        return False
    if not exe_url:
        log("В релизе нет файла .exe.")
        return False
    cur = Path(sys.executable).resolve()
    new = cur.with_name(cur.stem + "-new.exe")
    log(f"Скачиваю версию {ver}...")
    try:
        with requests.get(exe_url, stream=True, timeout=180) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", 0))
            done = 0
            last = -1
            with new.open("wb") as f:
                for chunk in r.iter_content(chunk_size=262144):
                    f.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = int(done * 100 / total)
                        if pct // 10 > last:
                            last = pct // 10
                            log(f"  загрузка: {pct}%")
    except Exception as e:
        log(f"Ошибка скачивания: {e}")
        return False
    try:
        old = _old_exe_path()
        if old.exists():
            old.unlink()
        cur.rename(old)        # запущенный exe можно переименовать
        new.rename(cur)        # новый занимает его место
    except OSError as e:
        log(f"Не удалось применить обновление: {e}")
        return False
    log(f"Обновлено до версии {ver}! Перезапустите программу.")
    return True


def check_update() -> None:
    """Проверяет новую версию и предлагает установить (команда check-update)."""
    print(dim("Проверяю обновления..."))
    try:
        latest = fetch_latest_release()
    except Exception as e:
        print(red(f"Не удалось проверить обновления: {e}"))
        return
    if not latest:
        print(amber("Не удалось получить релизы (возможно, их ещё нет)."))
        return
    ver, assets = latest
    if _version_tuple(ver) <= _version_tuple(VERSION):
        print(green(f"У вас последняя версия ({VERSION})."))
        return
    print(amber(f"Доступна новая версия: {ver} (у вас {VERSION})."))
    try:
        ans = input("Установить сейчас? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return
    if ans in ("y", "yes", "д", "да"):
        _apply_update(_asset_url_for_current_exe(assets), ver)
    else:
        print(dim("Отменено."))


# --------------------------------------------------------------------------- #
#  Фоновая защита (этап 3)
# --------------------------------------------------------------------------- #
def _monitor_scan_callback(client: VirusTotalClient):
    def cb(path: str) -> str:
        try:
            return scan_one(client, Path(path), False).status
        except Exception:
            return "error"
    return cb


def run_monitor(args: argparse.Namespace) -> int:
    """Фоновая защита: следит за автозагрузкой, процессами и новыми файлами.
    Реакция по умолчанию обратимая: карантин файла / пауза процесса (не удаление)."""
    import monitor as monitor_mod

    api_key = resolve_api_key(args.api_key)
    client = VirusTotalClient(api_key) if api_key else None
    cb = _monitor_scan_callback(client) if client else None

    def on_event(ev) -> None:
        paint = {"info": dim, "warn": amber, "danger": red}.get(ev.severity, dim)
        print(paint(f"{ev.title}: {ev.detail}" if ev.detail else ev.title))
        # В консоли кнопок нет — файл-угрозу кладём в карантин автоматически (обратимо)
        # с умным обезвреживанием: остановить процесс + снять автозагрузку + копии.
        if ev.kind == "threat-file" and ev.path:
            rep = monitor_mod.remediate(ev.path, kill=True)
            dest = monitor_mod.quarantine_file(Path(ev.path))
            if dest:
                print(red(f"  → помещён в карантин: {dest}"))
                if rep["stopped"]:
                    print(dim(f"     остановлено процессов: {len(rep['stopped'])}"))
                if rep["autostart_removed"]:
                    print(dim(f"     убрано из автозагрузки: {len(rep['autostart_removed'])}"))
                copies = sum(1 for c in rep["copies"]
                             if monitor_mod.quarantine_file(Path(c)))
                if copies:
                    print(dim(f"     копий в карантин: {copies}"))

    mon = monitor_mod.Monitor(
        on_event, scan_callback=cb,
        notifier=lambda ev: monitor_mod.toast(ev.title, ev.detail))
    print(cyan(bold("Фоновая защита включена.")) + dim("   Ctrl+C — остановить."))
    if client is None:
        print(amber("Ключ VirusTotal не задан — новые файлы не сканируются "
                    "(только алерты автозагрузки/процессов)."))
    mon.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mon.stop()
        print(dim("\nЗащита остановлена."))
    return 0


def run_setup_clamav() -> None:
    """Загрузчик ClamAV: качает движок + базу в папку приложения."""
    global _clamav_engine
    ok = provision_clamav(log=lambda m: print(dim(m)))
    if ok:
        _clamav_engine = None  # пересоздать движок, чтобы подхватить новый clamscan
        print(green("ClamAV подключён."))


# Стандартная тест-строка EICAR в base64 (хранится не как литерал, чтобы НАШ exe
# не флагали антивирусы). При создании файла раскодируется в настоящий EICAR.
_EICAR_B64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="


def make_eicar_samples(dest_dir: Path) -> list[Path]:
    """Создаёт 3 безвредных тест-файла EICAR (детектятся всеми антивирусами как тест)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    data = base64.b64decode(_EICAR_B64)
    created: list[Path] = []
    for name in ("eicar-test-1.txt", "eicar-test-2.txt", "eicar-test-3.txt"):
        try:
            p = dest_dir / name
            p.write_bytes(data)
            created.append(p)
        except OSError:
            pass
    return created


def run_make_eicar() -> None:
    """Создаёт безвредные тест-файлы для проверки детекта."""
    dest = Path.home() / "Desktop" / "VTScan-test"
    files = make_eicar_samples(dest)
    if not files:
        print(red("Не удалось создать тест-файлы."))
        return
    print(green(f"Создано {len(files)} безвредных тест-файлов (EICAR):"))
    print(dim(f"  папка: {dest}"))
    for f in files:
        print(dim(f"    - {f.name}"))
    print(amber("Это стандартные EICAR — их детектят ВСЕ антивирусы как тест (не настоящий вирус)."))
    print(dim("Проверка детекта:  scan " + str(dest) + " -r"))
    print(dim("Проверка фоновой защиты: включи monitor и скопируй один файл в Downloads."))


def run_selftest() -> None:
    """Самопроверка: показывает 2 системных уведомления и реально кладёт безобидный
    файл в карантин — чтобы убедиться, что уведомления и реакция работают."""
    import monitor as monitor_mod
    print(cyan(bold("Самопроверка: уведомления + карантин")))

    print(amber("[1] эмулирую подозрительный процесс → уведомление..."))
    monitor_mod.toast("Подозрительный процесс (тест)",
                      r"C:\Users\you\Downloads\suspicious.exe")
    time.sleep(2)

    demo = data_dir() / "selftest-sample.txt"
    dest = None
    try:
        demo.write_text("Тестовый файл VTScan для проверки карантина.", encoding="utf-8")
        dest = monitor_mod.quarantine_file(demo)
    except OSError:
        pass
    print(red("[2] эмулирую вредоносный файл → карантин + уведомление..."))
    monitor_mod.toast("Файл помещён в карантин (тест)",
                      str(dest) if dest else "selftest-sample.txt")

    print(green("Готово. Если справа всплыли 2 уведомления — всё работает."))
    if dest:
        print(dim(f"Тестовый файл лежит в карантине: {dest}"))


def run_interactive(args: argparse.Namespace) -> int:
    """Интерактивный режим: ввод команд (scan/help/key/cd/clear/exit)."""
    # Очищаем экран при старте — убираем служебную шапку cmd (копирайт Microsoft).
    os.system("cls" if os.name == "nt" else "clear")
    print_banner()
    cleanup_old_update()
    notify_if_update_available()
    print_help()  # сразу показываем доступные команды, чтобы не вводить help вручную
    api_key = resolve_api_key(args.api_key)
    client = VirusTotalClient(api_key) if api_key else None

    while True:
        try:
            line = input(make_prompt()).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, rest = parts[0].lower(), parts[1:]

        try:
            if cmd in ("exit", "quit", "q"):
                break
            elif cmd in ("help", "?"):
                arg = rest[0].lower() if rest else ""
                tier = ("advanced" if arg in ("advanced", "adv", "настройки")
                        else "test" if arg in ("test", "тест") else "basic")
                print_help(tier)
            elif cmd in ("test-ransomware",):
                import monitor as monitor_mod
                print(red(bold("ТЕСТ: ВОЗМОЖЕН ШИФРОВАЛЬЩИК! Тронут файл-приманка")))
                print(dim("это имитация — реальной угрозы нет, ничего не заморожено"))
                monitor_mod.toast("ТЕСТ: шифровальщик (приманка)", "имитация, угрозы нет")
            elif cmd in ("test-autostart",):
                import monitor as monitor_mod
                print(amber("ТЕСТ: Новое в автозагрузке — C:\\Users\\you\\AppData\\evil.exe"))
                monitor_mod.toast("ТЕСТ: новое в автозагрузке", "имитация")
            elif cmd in ("version", "ver"):
                print(f"vtscan {VERSION}")
            elif cmd in ("clear", "cls"):
                os.system("cls" if os.name == "nt" else "clear")
            elif cmd == "cd":
                if not rest:
                    print(dim(os.getcwd()))
                else:
                    os.chdir(os.path.expanduser(rest[0]))
            elif cmd == "key":
                new_key = ask_and_save_key()
                if new_key:
                    client = VirusTotalClient(new_key)
            elif cmd in ("check-update", "update"):
                check_update()
            elif cmd in ("monitor", "guard"):
                run_monitor(args)
            elif cmd == "autostart":
                arg = rest[0].lower() if rest else ""
                if arg in ("on", "вкл", "да", "yes"):
                    print(green("Автозапуск с Windows включён.") if enable_autostart()
                          else red("Не удалось включить автозапуск."))
                elif arg in ("off", "выкл", "нет", "no"):
                    print(green("Автозапуск с Windows выключен.") if disable_autostart()
                          else red("Не удалось выключить автозапуск."))
                else:
                    mode = autostart_mode()
                    label = {"task": green("включён (с правами администратора)"),
                             "run": amber("включён (обычные права)"),
                             "off": dim("выключен")}[mode]
                    print(dim("Автозапуск с Windows: ") + label)
                    if mode == "run" and not is_admin():
                        print(dim("  для запуска всегда с админ-правами: включите автозапуск, "
                                  "будучи администратором (команда ") + bold("admin") + dim(")"))
                    print(dim("Команды: ") + bold("autostart on") + dim(" / ") + bold("autostart off"))
            elif cmd == "admin":
                if is_admin():
                    print(green("Запущено с правами администратора (уровень прав 2)."))
                else:
                    print(amber("Сейчас обычные права (user-mode)."))
                    try:
                        ans = input("Перезапустить от администратора (UAC)? (y/n): ").strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        ans = "n"
                    if ans in ("y", "yes", "д", "да"):
                        if relaunch_as_admin():
                            print(dim("Запускаю с повышением прав... текущий сеанс закрывается."))
                            return 0
                        print(red("Не удалось повысить права (UAC отменён?)."))
            elif cmd in ("where", "folder"):
                print(dim("Папка данных приложения (ключ, ClamAV, карантин):"))
                print("  " + cyan(str(data_dir())))
            elif cmd == "keys":
                if len(rest) >= 2:
                    sources.save_key(rest[0].lower(), rest[1])
                    print(green(f"Ключ для «{rest[0]}» сохранён."))
                else:
                    print(bold("Доп. источники проверки (ключ бесплатный):"))
                    for s in sources.source_catalog():
                        mark = green("есть ключ") if s["has_key"] else dim("нет ключа")
                        print("  " + cyan(f"{s['id']:<14}") + f"{s['name']:<16}" + mark)
                        print(dim(f"                {s['signup']}"))
                    print(dim("Добавить ключ:  keys <id> <ключ>"))
            elif cmd in ("setup-clamav", "install-clamav"):
                run_setup_clamav()
            elif cmd in ("selftest", "test"):
                run_selftest()
            elif cmd in ("make-eicar", "maketest"):
                run_make_eicar()
            elif cmd in ("quickscan", "quick-scan", "scan-pc"):
                run_computer_scan("quick")
            elif cmd in ("fullscan", "full-scan"):
                root = Path(os.path.expanduser(rest[0])) if rest else None
                run_computer_scan("full", root)
            elif cmd in ("usbscan", "scan-usb"):
                run_computer_scan("usb")
            elif cmd in ("memscan", "scan-memory"):
                run_memory_scan()
            elif cmd in ("netscan", "scan-network"):
                run_network_scan()
            elif cmd == "scan":
                # scan memory / scan network — режимы проверки процессов и сети.
                if rest and rest[0].lower() in ("memory", "mem", "память", "процессы"):
                    run_memory_scan()
                    continue
                if rest and rest[0].lower() in ("network", "net", "сеть"):
                    run_network_scan()
                    continue
                paths = [p for p in rest if not p.startswith("-")]
                if not paths:
                    print(dim("Использование: ") + "scan <путь> [-r] [--upload]")
                    continue
                if client is None:
                    new_key = ask_and_save_key()
                    if not new_key:
                        continue
                    client = VirusTotalClient(new_key)
                recursive = any(f in ("-r", "--recursive") for f in rest)
                upload = "--upload" in rest
                results = run_scan(client, Path(os.path.expanduser(paths[0])),
                                   recursive=recursive, upload=upload, delay=args.delay)
                # Файл неизвестен базе VirusTotal → предложить загрузить его на анализ.
                if not upload:
                    unknown = [r for r in results if r.status == "unknown"]
                    if len(unknown) == 1:
                        try:
                            ans = input(amber("Файл неизвестен базе. ") +
                                        "Загрузить его на анализ? (y/n): ").strip().lower()
                        except (EOFError, KeyboardInterrupt):
                            print()
                            ans = "n"
                        if ans in ("y", "yes", "д", "да"):
                            run_scan(client, Path(unknown[0].path),
                                     upload=True, delay=args.delay)
            else:
                print(dim("Неизвестная команда. Введите ") + bold("help") + dim("."))
        except Exception as e:  # одна кривая команда не должна ронять весь сеанс
            print(red(f"Ошибка: {e}"))

    print(dim("Пока!"))
    return 0


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Сканер файлов через VirusTotal API (проверка по SHA-256).")
    parser.add_argument("target", nargs="?", type=Path,
                        help="Файл или папка для проверки. Без аргумента — интерактивный режим.")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Запустить интерактивный кибер-терминал.")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="Рекурсивно обходить вложенные папки.")
    parser.add_argument("--upload", action="store_true",
                        help="Загружать на VirusTotal файлы, которых нет в базе (медленнее, файл уходит на сервер).")
    parser.add_argument("--api-key", help="API-ключ VirusTotal (иначе берётся из VT_API_KEY или .vtkey).")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="Вывести результат в формате JSON.")
    parser.add_argument("--delay", type=float, default=PUBLIC_RATE_DELAY,
                        help=f"Пауза между запросами в секундах (по умолчанию {PUBLIC_RATE_DELAY} для бесплатного ключа).")
    parser.add_argument("--pause", action="store_true",
                        help="После сканирования ждать Enter (удобно при запуске из правого клика).")
    parser.add_argument("--remove-menu", action="store_true",
                        help=argparse.SUPPRESS)  # скрытый «аварийный» способ убрать пункт правого клика
    parser.add_argument("--check-update", action="store_true",
                        help="Проверить и установить обновление, затем выйти.")
    parser.add_argument("--monitor", action="store_true",
                        help="Запустить фоновую защиту (автозагрузка, процессы, новые файлы).")
    parser.add_argument("--setup-clamav", action="store_true",
                        help="Скачать локальный движок ClamAV в папку приложения и выйти.")
    parser.add_argument("--selftest", action="store_true",
                        help="Проверка уведомлений и карантина, затем выйти.")
    parser.add_argument("--make-eicar", action="store_true",
                        help="Создать безвредные тест-файлы EICAR и выйти.")
    args = parser.parse_args(argv)

    cleanup_old_update()
    # Пункт правого клика регистрируется автоматически (тихо), без всяких команд.
    if getattr(sys, "frozen", False):
        install_context_menu(quiet=True)

    if args.remove_menu:
        remove_context_menu()
        return 0
    if args.check_update:
        check_update()
        return 0
    if args.monitor:
        return run_monitor(args)
    if args.setup_clamav:
        run_setup_clamav()
        return 0
    if args.selftest:
        run_selftest()
        return 0
    if args.make_eicar:
        run_make_eicar()
        return 0

    # Без цели (двойной клик по exe) или с флагом -i → интерактивный кибер-терминал.
    if args.interactive or args.target is None:
        return run_interactive(args)

    # Разовый скан (в т.ч. из правого клика). Если ключа нет — спросим прямо здесь.
    api_key = resolve_api_key(args.api_key)
    if not api_key and not args.as_json and sys.stdout.isatty():
        api_key = ask_and_save_key()
    if not api_key:
        print(red("Не найден ключ VirusTotal."))
        print(dim("Запусти программу без аргументов и введи ключ командой ") + bold("key") +
              dim(", или положи его в файл .vtkey рядом с программой."))
        code = 2
    else:
        client = VirusTotalClient(api_key)
        results = run_scan(client, args.target, recursive=args.recursive,
                           upload=args.upload, delay=args.delay, as_json=args.as_json)
        code = 1 if has_malicious(results) else 0

    if args.pause:
        try:
            input("\nНажмите Enter, чтобы закрыть...")
        except EOFError:
            pass
    return code


if __name__ == "__main__":
    raise SystemExit(main())
