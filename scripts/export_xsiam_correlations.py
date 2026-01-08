#!/usr/bin/env python3
"""
Export existing Cortex XSIAM objects into the repo:

- Correlations  -> rules/correlations/         + exports/correlations_raw/
- IOCs          -> rules/iocs/                 + exports/iocs_raw/
- BIOCs         -> rules/biocs/                + exports/biocs_raw/   (if supported)

Notes:
- "Sanitized" output aims to be insert-ready candidates:
  - Removes ids/rule_id.
  - Keeps a whitelist of keys commonly accepted by INSERT endpoints.
- Raw output stores full objects as returned by GET (useful for troubleshooting).
- BIOCs may be unsupported in some tenants. If API returns "BIOC not supported", BIOCs are skipped
  unless STRICT_BIOC=true.

Usage (GitHub Actions / CLI):
  export XSIAM_FQDN, XSIAM_API_KEY, XSIAM_API_KEY_ID
  python -u scripts/export_xsiam_objects.py
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

# ---------------- Env / Config ----------------
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")

EXPORT_CORRELATIONS = os.getenv("EXPORT_CORRELATIONS", "true").lower() in ("1", "true", "yes")
EXPORT_IOCS = os.getenv("EXPORT_IOCS", "true").lower() in ("1", "true", "yes")
EXPORT_BIOCS = os.getenv("EXPORT_BIOCS", "true").lower() in ("1", "true", "yes")

STRICT_BIOC = os.getenv("STRICT_BIOC", "false").lower() in ("1", "true", "yes")

# Optional filters
ONLY_ENABLED = os.getenv("EXPORT_ONLY_ENABLED", "false").lower() in ("1", "true", "yes")
NAME_PREFIX = os.getenv("EXPORT_NAME_PREFIX", "").strip()  # correlations/BIOCs only
LIMIT = int(os.getenv("EXPORT_LIMIT", "0"))  # 0 = no limit per object type

# Output paths
CORR_OUT_DIR = Path(os.getenv("EXPORT_CORR_OUT_DIR", "rules/correlations"))
IOC_OUT_DIR = Path(os.getenv("EXPORT_IOC_OUT_DIR", "rules/iocs"))
BIOC_OUT_DIR = Path(os.getenv("EXPORT_BIOC_OUT_DIR", "rules/biocs"))

CORR_RAW_DIR = Path(os.getenv("EXPORT_CORR_RAW_DIR", "exports/correlations_raw"))
IOC_RAW_DIR = Path(os.getenv("EXPORT_IOC_RAW_DIR", "exports/iocs_raw"))
BIOC_RAW_DIR = Path(os.getenv("EXPORT_BIOC_RAW_DIR", "exports/biocs_raw"))


# ---------------- Exceptions ----------------
class NonRetryableHTTP(Exception):
    def __init__(self, status_code: int, url: str, body: str):
        super().__init__(f"HTTP {status_code} {url}")
        self.status_code = status_code
        self.url = url
        self.body = body


# ---------------- Helpers ----------------
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
    """
    - Raises NonRetryableHTTP for 4xx (except 429)
    - Retries on 429/5xx/599
    """
    url = f"{base_url}{path}"
    last_exc: Exception | None = None

    for attempt in range(1, 6):
        try:
            r = session.post(url, json=payload, timeout=(10, 180))

            # Non-retryable 4xx (except 429)
            if 400 <= r.status_code < 500 and r.status_code != 429:
                body = (r.text or "")[:6000]
                raise NonRetryableHTTP(r.status_code, url, body)

            # Retry-worthy
            if r.status_code in (429, 500, 502, 503, 504, 599):
                body = (r.text or "")[:1200]
                raise HTTPError(f"HTTP {r.status_code} from {url}. Body: {body}", response=r)

            r.raise_for_status()
            data = r.json()

            # Some endpoints return top-level "errors"
            errors = data.get("errors") or []
            if errors:
                raise SystemExit(f"XSIAM API returned errors for {path}: {errors}")

            # Some endpoints return {"reply": {"err_code": ...}}
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


def safe_filename(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    return s[:180] if len(s) > 180 else s


def ensure_dirs(*dirs: Path) -> None:
    if DRY_RUN:
        return
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: Any) -> None:
    if DRY_RUN:
        print(f"[DRY_RUN] would write {path}")
        return
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def bioc_unsupported(body: str) -> bool:
    return "bioc not supported" in (body or "").lower()


# ---------------- Filters ----------------
def passes_name_enabled_filters(obj: dict) -> bool:
    # Used for correlations + BIOCs (have a 'name' and 'is_enabled' or 'status')
    name = (obj.get("name") or "").strip()
    if NAME_PREFIX and not name.startswith(NAME_PREFIX):
        return False

    if ONLY_ENABLED:
        # correlations: is_enabled: bool
        if "is_enabled" in obj:
            return bool(obj.get("is_enabled")) is True
        # BIOCs: status can vary, keep lenient
        status = str(obj.get("status") or "").lower().strip()
        if status and status not in ("enabled", "enable", "true", "on"):
            return False

    return True


def passes_ioc_filters(obj: dict) -> bool:
    # IOCs do not have name; enabled concept differs.
    # We'll only apply LIMIT to IOCs, and ignore NAME_PREFIX.
    return True


# ---------------- Sanitize (insert-ready candidates) ----------------
CORRELATION_INSERT_KEYS = {
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

IOC_INSERT_KEYS = {
    # Required in your tenant: expiration_date appears required.
    "indicator",
    "type",
    "severity",
    "reputation",
    "reliability",
    "comment",
    "default_expiration_enabled",
    "expiration_date",
    # Some tenants include these; safe to keep if present:
    "source",
    "vendor",
}

BIOC_INSERT_KEYS = {
    # BIOC schemas vary per tenant; keep a conservative allowlist.
    "name",
    "type",
    "severity",
    "comment",
    "status",
    "is_xql",
    "indicator",
    "mitre_tactic_id_and_name",
    "mitre_technique_id_and_name",
    "tags",
    "description",
}


def sanitize(obj: dict, keys: set[str]) -> dict:
    out = {k: obj.get(k) for k in keys if k in obj}
    # strip IDs
    out.pop("id", None)
    out.pop("rule_id", None)
    out.pop("ruleId", None)
    return out


# ---------------- Get paged helpers ----------------
def paged_get_all(
    session: requests.Session,
    base_url: str,
    get_path: str,
    *,
    page_size: int = 100,
    extended_view: bool = True,
    limit: int = 0,
) -> List[dict]:
    if page_size <= 0 or page_size > 100:
        raise ValueError("page_size must be 1..100")

    out: List[dict] = []
    start = 0
    while True:
        payload = {
            "request_data": {
                "extended_view": extended_view,
                "search_from": start,
                "search_to": start + page_size,
            }
        }
        resp = http_post(session, base_url, get_path, payload)
        objs = parse_objects(resp)
        out.extend(objs)

        if limit and len(out) >= limit:
            return out[:limit]

        count = parse_objects_count(resp)
        if count is not None and len(out) >= count:
            break
        if not objs:
            break

        start += page_size

    return out


# ---------------- Export routines ----------------
def export_correlations(session: requests.Session, base_url: str) -> int:
    ensure_dirs(CORR_OUT_DIR, CORR_RAW_DIR)

    all_rules = paged_get_all(session, base_url, "/public_api/v1/correlations/get", limit=LIMIT)
    rules = [r for r in all_rules if passes_name_enabled_filters(r)]

    print(f"[CORR] fetched={len(all_rules)} after_filters={len(rules)} out={CORR_OUT_DIR} raw={CORR_RAW_DIR}")

    written = 0
    for r in rules:
        name = (r.get("name") or "").strip()
        if not name:
            continue
        fn = safe_filename(name)

        raw_path = CORR_RAW_DIR / f"{fn}.json"
        out_path = CORR_OUT_DIR / f"{fn}.json"

        write_json(raw_path, r)
        write_json(out_path, sanitize(r, CORRELATION_INSERT_KEYS))
        written += 1

    return written


def export_iocs(session: requests.Session, base_url: str) -> int:
    ensure_dirs(IOC_OUT_DIR, IOC_RAW_DIR)

    all_iocs = paged_get_all(session, base_url, "/public_api/v1/indicators/get", limit=LIMIT)
    iocs = [i for i in all_iocs if passes_ioc_filters(i)]

    print(f"[IOC] fetched={len(all_iocs)} after_filters={len(iocs)} out={IOC_OUT_DIR} raw={IOC_RAW_DIR}")

    written = 0
    for i in iocs:
        ind = (i.get("indicator") or "").strip()
        t = (i.get("type") or "").strip()
        if not ind or not t:
            continue

        # Use stable filename based on key
        fn = safe_filename(f"{t}__{ind}")
        raw_path = IOC_RAW_DIR / f"{fn}.json"
        out_path = IOC_OUT_DIR / f"{fn}.json"

        write_json(raw_path, i)
        write_json(out_path, sanitize(i, IOC_INSERT_KEYS))
        written += 1

    return written


def export_biocs(session: requests.Session, base_url: str) -> int:
    ensure_dirs(BIOC_OUT_DIR, BIOC_RAW_DIR)

    try:
        all_biocs = paged_get_all(session, base_url, "/public_api/v1/bioc/get", limit=LIMIT)
    except NonRetryableHTTP as e:
        if e.status_code == 400 and bioc_unsupported(e.body) and not STRICT_BIOC:
            print("[BIOC] BIOC not supported in this tenant/api-key. Skipping BIOC export.")
            return 0
        raise SystemExit(f"[BIOC] Failed to fetch BIOCs: HTTP {e.status_code} {e.url}\n{e.body}")

    biocs = [b for b in all_biocs if passes_name_enabled_filters(b)]

    print(f"[BIOC] fetched={len(all_biocs)} after_filters={len(biocs)} out={BIOC_OUT_DIR} raw={BIOC_RAW_DIR}")

    written = 0
    for b in biocs:
        name = (b.get("name") or "").strip()
        if not name:
            continue
        fn = safe_filename(name)

        raw_path = BIOC_RAW_DIR / f"{fn}.json"
        out_path = BIOC_OUT_DIR / f"{fn}.json"

        write_json(raw_path, b)
        write_json(out_path, sanitize(b, BIOC_INSERT_KEYS))
        written += 1

    return written


# ---------------- Main ----------------
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

    print("=== EXPORT_XSIAM_OBJECTS START ===")
    print(f"[CFG] base_url={base_url}")
    print(f"[CFG] DRY_RUN={DRY_RUN}")
    print(f"[CFG] export: correlations={EXPORT_CORRELATIONS} iocs={EXPORT_IOCS} biocs={EXPORT_BIOCS}")
    print(f"[CFG] filters: ONLY_ENABLED={ONLY_ENABLED} NAME_PREFIX={NAME_PREFIX!r} LIMIT={LIMIT}")
    print(f"[CFG] strict_bioc={STRICT_BIOC}")

    total_written = 0

    if EXPORT_CORRELATIONS:
        total_written += export_correlations(s, base_url)
    if EXPORT_IOCS:
        total_written += export_iocs(s, base_url)
    if EXPORT_BIOCS:
        total_written += export_biocs(s, base_url)

    print(f"[DONE] total_written={total_written}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise
