#!/usr/bin/env python3
"""
sources — дополнительные онлайн-источники проверки по хэшу (этап 2, мульти-источник).

Чтобы вердикт был максимально объективным, агрегатор объединяет VirusTotal + ClamAV
+ эти источники. Каждый источник по SHA-256 спрашивает свою базу и возвращает EngineResult.

Каждому источнику нужен свой БЕСПЛАТНЫЙ API-ключ (как у VirusTotal). Ключи хранятся
локально в data_dir/keys.json. Источник без ключа просто пропускается.

ВНИМАНИЕ: эндпоинты/форматы у каждого сервиса свои; протестировать можно только с
реальными ключами (на Mac у разработчика их нет — проверяется на стороне пользователя).
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

from engines import EngineResult, data_dir


# --------------------------------------------------------------------------- #
#  Хранилище ключей источников (data_dir/keys.json)
# --------------------------------------------------------------------------- #
def keys_path() -> Path:
    return data_dir() / "keys.json"


def load_keys() -> dict:
    p = keys_path()
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def save_key(source_id: str, key: str) -> None:
    keys = load_keys()
    keys[source_id] = key.strip()
    try:
        keys_path().write_text(json.dumps(keys, ensure_ascii=False, indent=2),
                               encoding="utf-8")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  Источники
# --------------------------------------------------------------------------- #
class _Source:
    name = ""
    source_id = ""
    signup = ""   # где взять бесплатный ключ

    def scan_hash(self, sha256: str, key: str) -> EngineResult:
        raise NotImplementedError


class MalwareBazaar(_Source):
    name = "MalwareBazaar"
    source_id = "malwarebazaar"
    signup = "auth.abuse.ch — бесплатный Auth-Key"

    def scan_hash(self, sha256, key):
        try:
            r = requests.post("https://mb-api.abuse.ch/api/v1/",
                              data={"query": "get_info", "hash": sha256},
                              headers={"Auth-Key": key}, timeout=20)
            d = r.json()
            st = d.get("query_status")
            if st == "ok":
                data = (d.get("data") or [{}])[0]
                sig = data.get("signature") or "известный образец"
                return EngineResult(self.name, "malicious", str(sig))
            if st in ("hash_not_found", "no_results"):
                return EngineResult(self.name, "unknown", "нет в базе")
            return EngineResult(self.name, "error", str(st))
        except Exception as e:  # noqa: BLE001
            return EngineResult(self.name, "error", str(e))


class AlienVaultOTX(_Source):
    name = "AlienVault OTX"
    source_id = "otx"
    signup = "otx.alienvault.com — бесплатный API key"

    def scan_hash(self, sha256, key):
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
                headers={"X-OTX-API-KEY": key}, timeout=20)
            if r.status_code == 404:
                return EngineResult(self.name, "unknown", "нет данных")
            d = r.json()
            pulses = (d.get("pulse_info") or {}).get("count", 0)
            if pulses and int(pulses) > 0:
                return EngineResult(self.name, "malicious", f"в {pulses} отчётах об угрозах")
            return EngineResult(self.name, "unknown", "нет упоминаний")
        except Exception as e:  # noqa: BLE001
            return EngineResult(self.name, "error", str(e))


class KasperskyOpenTIP(_Source):
    name = "Kaspersky"
    source_id = "kaspersky"
    signup = "opentip.kaspersky.com — бесплатный API token"

    def scan_hash(self, sha256, key):
        try:
            r = requests.get("https://opentip.kaspersky.com/api/v1/search/hash",
                             params={"request": sha256},
                             headers={"x-api-key": key}, timeout=20)
            if r.status_code == 404:
                return EngineResult(self.name, "unknown", "нет в базе")
            d = r.json()
            zone = str(d.get("Zone") or d.get("zone") or "").lower()
            m = {
                "red": ("malicious", "опасен (Red)"),
                "orange": ("suspicious", "подозрителен (Orange)"),
                "yellow": ("suspicious", "подозрителен (Yellow)"),
                "green": ("clean", "чисто (Green)"),
                "grey": ("unknown", "нет данных (Grey)"),
                "gray": ("unknown", "нет данных (Grey)"),
            }
            st, detail = m.get(zone, ("unknown", zone or "нет данных"))
            return EngineResult(self.name, st, detail)
        except Exception as e:  # noqa: BLE001
            return EngineResult(self.name, "error", str(e))


ALL_SOURCES = [MalwareBazaar(), AlienVaultOTX(), KasperskyOpenTIP()]


def configured_sources() -> list:
    """Источники, для которых задан ключ — (источник, ключ)."""
    keys = load_keys()
    return [(s, keys[s.source_id]) for s in ALL_SOURCES if keys.get(s.source_id)]


def source_catalog() -> list:
    """Все источники: id, имя, где взять ключ, есть ли ключ (для команды keys)."""
    keys = load_keys()
    return [{"id": s.source_id, "name": s.name, "signup": s.signup,
             "has_key": bool(keys.get(s.source_id))} for s in ALL_SOURCES]
