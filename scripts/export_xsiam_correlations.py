#!/usr/bin/env python3
"""
Export existing Cortex XSIAM correlation rules into the repo.

Outputs:
- rules/correlations/*.json              (sanitized, insert-ready candidate)
- exports/correlations_raw/*.json        (raw objects as returned by GET)

Notes:
- We remove rule_id/id from the managed version so reconcile can upsert by name cleanly.
- We keep a whitelist of keys known to be accepted by correlations/insert.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout


RAW_DIR = Path(os.getenv("EXPORT_RAW_DIR", "exports/correlations_raw"))
OUT_DIR = Path(os.getenv("EXPORT_OUT_DIR", "rules/correlations"))

# Optional filters
ONLY_ENABLED = os.getenv("EXPORT_ONLY_ENABLED", "false").lower() in ("1", "true", "yes")
NAME_PREFIX = os.getenv("EXPORT_NAME_PREFIX", "").strip()  # export only rules starting with this prefix
LIMIT = int(os.getenv("EXPORT_LIMIT", "0"))  # 0 = no limit

DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")


def must_env(name: str) -> str:
    v = (os.environ.get(name) or "").strip()
    if not v:
        raise SystemExit(f"Missing required environment variable: {name}")
    return v


def normalize_base_url(fqdn_or_url: str) -> str:
    v = fqdn_or_url.strip()
    if v.startswith("http://") or v.startswith("https://"):
        return v.rstrip("/")
    return ("https://" + v).rstrip("/")


def http_post(session: requests.Session, base_url: str, path: str, payload: dict) -> dict:
    url = f"{base_url}{path}"
    last_exc: Exception | None = None

    for attempt in range(1, 6):
        try:
            r = session.post(url, json=payload, timeout=(10, 180))

            if r.status_code in (429, 500, 502, 503, 504, 599):
                body = (r.text or "")[:1200]
                raise HTTPError(f"HTTP {r.status_code} from {url}. Body: {body}", response=r)

            r.raise_for_status()
            data = r.json()

            errors = data.get("errors") or []
            if errors:
                raise SystemExit(f"XSIAM API returned errors for {path}: {errors}")

            rep = data.get("reply")
            if isinstance(rep, dict) and rep.get("err_code"):
                raise SystemExit(
                    f"XSIAM API error for {path}: err_code={rep.get('err_code')} "
                    f"err_msg={rep.get('err_msg')} err_extra={rep.get('err_extra')}"
                )

            return data

        except (ConnectionError, Timeout, HTTPError) as e:
            last_exc = e
            if attempt < 5:
                time.sleep(2 ** (attempt - 1))
                continue
            break

    raise SystemExit(f"XSIAM request failed after retries: {url}\nLast error: {last_exc}")


def parse_objects(resp: dict) -> List[dict]:
    if isinstance(resp.get("objects"), list):
        return resp["objects"]
    rep = resp.get("reply")
    if isinstance(rep, dict) and isinstance(rep.get("objects"), list):
        return rep["objects"]
    return []


def parse_objects_count(resp: dict) -> Optional[int]:
    if isinstance(resp.get("objects_count"), int):
        return resp["objects_count"]
    rep = resp.get("reply")
    if isinstance(rep, dict) and isinstance(rep.get("objects_count"), int):
        return rep.get("objects_count")
    return None


def paged_get_all_correlations(session: requests.Session, base_url: str, page_size: int = 100) -> List[dict]:
    if page_size <= 0 or page_size > 100:
        raise ValueError("page_size must be 1..100")

    out: List[dict] = []
    start = 0
    while True:
        payload = {"request_data": {"extended_view": True, "search_from": start, "search_to": start + page_size}}
        resp = http_post(session, base_url, "/public_api/v1/correlations/get", payload)
        objs = parse_objects(resp)
        out.extend(objs)

        count = parse_objects_count(resp)
        if count is not None and len(out) >= count:
            break
        if not objs:
            break
        start += page_size

        if LIMIT and len(out) >= LIMIT:
            return out[:LIMIT]

    return out


def safe_filename(name: str) -> str:
    name = name.strip()
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:180] if len(name) > 180 else name


# Keys we want to store in rules/correlations (insert-ready “candidate” payload)
INSERT_KEYS = {
    "name",
    "severity",
    "xql_query",
    "is_enabled",
    "description",
    "alert_name",
    "alert_category",
    "alert_type",
    "alert_description",
    "alert_domain",
    "alert_fields",
    "execution_mode",
    "search_window",
    "simple_schedule",
    "timezone",
    "crontab",
    "suppression_enabled",
    "suppression_duration",
    "suppression_fields",
    "dataset",
    "user_defined_severity",
    "user_defined_category",
    "mitre_defs",
    "investigation_query_link",
    "drilldown_query_timeframe",
    "mapping_strategy",
    "action",
    "lookup_mapping",
}


def sanitize_for_insert(obj: dict) -> dict:
    # keep only known insert keys; drop IDs
    out = {k: obj.get(k) for k in INSERT_KEYS if k in obj}

    # ensure name exists
    if not (out.get("name") or "").strip():
        out["name"] = (obj.get("name") or "").strip()

    # remove any id/rule_id if present (we upsert by name later)
    out.pop("id", None)
    out.pop("rule_id", None)

    return out


def passes_filters(obj: dict) -> bool:
    name = (obj.get("name") or "").strip()
    if NAME_PREFIX and not name.startswith(NAME_PREFIX):
        return False
    if ONLY_ENABLED and not bool(obj.get("is_enabled", False)):
        return False
    return True


def main() -> None:
    base_url = normalize_base_url(must_env("XSIAM_FQDN"))
    api_key = must_env("XSIAM_API_KEY")
    api_key_id = must_env("XSIAM_API_KEY_ID")

    if urlparse(base_url).scheme != "https":
        raise SystemExit("XSIAM base URL must be https")

    s = requests.Session()
    s.headers.update(
        {
            "Authorization": api_key,
            "x-xdr-auth-id": api_key_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    all_rules = paged_get_all_correlations(s, base_url, page_size=100)
    rules = [r for r in all_rules if passes_filters(r)]

    print(f"[EXPORT] fetched={len(all_rules)} after_filters={len(rules)}")
    print(f"[EXPORT] raw_dir={RAW_DIR.resolve()}")
    print(f"[EXPORT] out_dir={OUT_DIR.resolve()}")
    print(f"[EXPORT] filters: ONLY_ENABLED={ONLY_ENABLED} NAME_PREFIX={NAME_PREFIX!r} LIMIT={LIMIT}")

    written = 0
    for r in rules:
        name = (r.get("name") or "").strip()
        if not name:
            continue

        base = safe_filename(name)

        raw_path = RAW_DIR / f"{base}.json"
        out_path = OUT_DIR / f"{base}.json"

        raw_text = json.dumps(r, indent=2, sort_keys=True) + "\n"
        out_text = json.dumps(sanitize_for_insert(r), indent=2, sort_keys=False) + "\n"

        if DRY_RUN:
            print(f"[EXPORT] DRY_RUN would write: {out_path.name}")
            continue

        raw_path.write_text(raw_text, encoding="utf-8")
        out_path.write_text(out_text, encoding="utf-8")
        written += 1

    print(f"[EXPORT] wrote={written} rules")


if __name__ == "__main__":
    main()
