#!/usr/bin/env python3
"""
Reconcile Cortex XSIAM objects from repo:
- Correlations (supported)
- IOCs (supported)
- BIOCs (optional; some tenants return "BIOC not supported")

Folders (defaults):
- rules/correlations/*.json
- rules/iocs/*.json
- rules/biocs/*.json   (optional)

Upsert keys:
- Correlations: name
- IOCs: (type, indicator)
- BIOCs: name

Endpoints:
- correlations: /public_api/v1/correlations/get, /public_api/v1/correlations/insert
- iocs:         /public_api/v1/indicators/get,  /public_api/v1/indicators/insert
- biocs:        /public_api/v1/bioc/get,        /public_api/v1/bioc/insert

Behavior:
- CREATE: insert with rule_id omitted (fallback rule_id=null)
- UPDATE: insert with rule_id populated from GET results
- VERIFY after each upsert

Resilience:
- If BIOC endpoints return "BIOC not supported", BIOCs are skipped for the run (unless STRICT_BIOC=true).
- BIOC payloads are sanitized to allowed fields to avoid 400 "Got also the fields: [...]"
- IOC payloads are normalized to include required fields (some tenants require expiration_date).
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout

# ------------------ Config (env) ------------------
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")

ENABLE_CORRELATIONS = os.getenv("ENABLE_CORRELATIONS", "true").lower() in ("1", "true", "yes")
ENABLE_IOCS = os.getenv("ENABLE_IOCS", "true").lower() in ("1", "true", "yes")
ENABLE_BIOCS = os.getenv("ENABLE_BIOCS", "true").lower() in ("1", "true", "yes")

# If BIOC is unsupported and STRICT_BIOC=false, we skip BIOCs instead of failing the run.
STRICT_BIOC = os.getenv("STRICT_BIOC", "false").lower() in ("1", "true", "yes")

CORR_DIR = Path(os.getenv("CORRELATIONS_DIR", "rules/correlations"))
IOC_DIR = Path(os.getenv("IOCS_DIR", "rules/iocs"))
BIOC_DIR = Path(os.getenv("BIOCS_DIR", "rules/biocs"))

# Optional enforcement toggles (OFF by default)
ENFORCE_PREFIX = os.getenv("ENFORCE_PREFIX", "false").lower() in ("1", "true", "yes")
ENFORCE_MARKER = os.getenv("ENFORCE_MARKER", "false").lower() in ("1", "true", "yes")
DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ").strip() or "DAC: "
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")

IOC_DEFAULT_EXPIRATION_DAYS = int(os.getenv("IOC_DEFAULT_EXPIRATION_DAYS", "365"))

# ------------------ Errors ------------------
@dataclass
class NonRetryableHTTP(Exception):
    status_code: int
    url: str
    body: str


# ------------------ Helpers ------------------
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

    if DRY_RUN and (path.endswith("/insert") or path.endswith("/insert_jsons") or path.endswith("/insert_csv")):
        print(f"[HTTP] DRY_RUN skip POST {url}")
        return {"dry_run": True, "path": path, "payload": payload, "errors": []}

    last_exc: Exception | None = None
    for attempt in range(1, 6):
        try:
            r = session.post(url, json=payload, timeout=(10, 180))

            # Non-retryable 4xx (except 429)
            if 400 <= r.status_code < 500 and r.status_code != 429:
                body = (r.text or "")[:4000]
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

        except NonRetryableHTTP:
            raise
        except (ConnectionError, Timeout, HTTPError) as e:
            last_exc = e
            if attempt < 5:
                sleep_s = 2 ** (attempt - 1)
                print(f"[HTTP] attempt {attempt}/5 failed: {e} -> retry in {sleep_s}s")
                time.sleep(sleep_s)
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


def _ensure_list_of_objects(parsed: Any, path: Path) -> List[dict]:
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and all(isinstance(x, dict) for x in parsed):
        return parsed
    raise SystemExit(f"[LOCAL] {path} must be a JSON object or list of objects.")


def _load_json_dir(dir_path: Path, label: str) -> List[dict]:
    if not dir_path.exists():
        print(f"[LOCAL] {label}_dir missing, skipping: {dir_path.resolve()}")
        return []

    files = sorted([p for p in dir_path.glob("*.json") if p.name != ".gitkeep"])
    print(f"[LOCAL] {label}_dir={dir_path.resolve()} files={len(files)}")
    if not files:
        return []

    out: List[dict] = []
    for p in files:
        parsed = json.loads(p.read_text(encoding="utf-8"))
        out.extend(_ensure_list_of_objects(parsed, p))
    return out


def _maybe_enforce_name_and_marker(obj: dict) -> None:
    """
    Optional enforcement for objects that have a 'name' field.
    OFF by default.
    """
    name = (obj.get("name") or "").strip()
    if not name:
        return

    if ENFORCE_PREFIX and not name.startswith(DAC_PREFIX):
        obj["name"] = f"{DAC_PREFIX}{name}"

    if ENFORCE_MARKER:
        desc = obj.get("description")
        if desc is None:
            desc = ""
        desc = str(desc).strip()
        if DAC_MARKER not in desc:
            obj["description"] = (desc + "\n\n" + DAC_MARKER).strip()


def _extract_rule_id(existing: dict) -> Any:
    return existing.get("id") or existing.get("rule_id") or existing.get("ruleId")


def _is_bioc_unsupported_error(body: str) -> bool:
    return "bioc not supported" in (body or "").lower()


# ------------------ IOC normalization ------------------
IOC_ALLOWED_FIELDS = {
    "indicator",
    "type",
    "severity",
    "reputation",
    "reliability",
    "comment",
    "default_expiration_enabled",
    "expiration_date",
    "rule_id",
}


def ensure_ioc_required_fields(obj: dict) -> dict:
    """
    Some tenants require expiration_date even when default_expiration_enabled=true.
    Also keeps IOC payload restricted to known fields.
    """
    out = {k: obj.get(k) for k in IOC_ALLOWED_FIELDS if k in obj}

    # Required-ish defaults (tenant-specific, but safe)
    out.setdefault("default_expiration_enabled", True)
    out.setdefault("reputation", "BAD")
    out.setdefault("reliability", "A")
    out.setdefault("severity", "SEV_020_MEDIUM")
    out.setdefault("comment", out.get("comment") or "Managed by detections-as-code")

    if not out.get("expiration_date"):
        dt = datetime.now(timezone.utc) + timedelta(days=IOC_DEFAULT_EXPIRATION_DAYS)
        out["expiration_date"] = dt.isoformat()

    # never allow rule_id=0
    if out.get("rule_id") == 0:
        out.pop("rule_id", None)

    return out


# ------------------ BIOC sanitation ------------------
BIOC_ALLOWED_FIELDS = {
    "mitre_tactic_id_and_name",
    "mitre_technique_id_and_name",
    "type",
    "name",
    "rule_id",
    "indicator",
    "comment",
    "severity",
    "status",
    "is_xql",
}


def bioc_sanitize_for_insert(obj: dict) -> dict:
    """
    bioc/insert accepts ONLY BIOC_ALLOWED_FIELDS.
    Strip all other keys (creation_time/modification_time/source/etc.).
    """
    clean = {k: obj.get(k) for k in BIOC_ALLOWED_FIELDS if k in obj}

    # Normalize rule_id behavior: never pass 0
    if clean.get("rule_id") == 0:
        clean.pop("rule_id", None)

    return clean


# ------------------ Correlations ------------------
def correlation_get_by_name(session: requests.Session, base_url: str, name: str) -> List[dict]:
    payload = {
        "request_data": {
            "extended_view": True,
            "filters": [{"field": "name", "operator": "EQ", "value": name}],
            "search_from": 0,
            "search_to": 1,
        }
    }
    return parse_objects(http_post(session, base_url, "/public_api/v1/correlations/get", payload))


def correlation_create_with_shape_fallback(session: requests.Session, base_url: str, obj: dict) -> dict:
    shapes = ["omit_rule_id", "rule_id_null"]
    last_400: Optional[str] = None

    for shape in shapes:
        payload_obj = dict(obj)
        if shape == "omit_rule_id":
            payload_obj.pop("rule_id", None)
        else:
            payload_obj["rule_id"] = None

        print(f"[correlation] create attempt shape={shape}")
        try:
            return http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [payload_obj]})
        except NonRetryableHTTP as e:
            if e.status_code != 400:
                raise SystemExit(f"[correlation] Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")
            last_400 = e.body
            continue

    raise SystemExit(f"[correlation] Create failed. Last 400 body:\n{last_400 or ''}")


def correlation_update(session: requests.Session, base_url: str, obj: dict, rule_id: Any) -> dict:
    payload_obj = dict(obj)
    payload_obj["rule_id"] = rule_id
    print(f"[correlation] update rule_id={rule_id}")
    return http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [payload_obj]})


# ------------------ IOCs ------------------
def ioc_key(obj: dict) -> Tuple[str, str]:
    t = (obj.get("type") or "").strip()
    ind = (obj.get("indicator") or "").strip()
    if not t or not ind:
        raise SystemExit(f"[IOC] IOC missing required fields: type={t!r} indicator={ind!r}")
    return (t, ind)


def ioc_get_by_key(session: requests.Session, base_url: str, t: str, indicator: str) -> List[dict]:
    payload = {
        "request_data": {
            "extended_view": True,
            "filters": [
                {"field": "type", "operator": "EQ", "value": [t]},
                {"field": "indicator", "operator": "EQ", "value": [indicator]},
            ],
            "search_from": 0,
            "search_to": 1,
        }
    }
    return parse_objects(http_post(session, base_url, "/public_api/v1/indicators/get", payload))


def ioc_create_with_shape_fallback(session: requests.Session, base_url: str, obj: dict) -> dict:
    shapes = ["omit_rule_id", "rule_id_null"]
    last_400: Optional[str] = None

    for shape in shapes:
        payload_obj = ensure_ioc_required_fields(obj)

        if shape == "omit_rule_id":
            payload_obj.pop("rule_id", None)
        else:
            payload_obj["rule_id"] = None

        print(f"[ioc] create attempt shape={shape}")
        try:
            return http_post(session, base_url, "/public_api/v1/indicators/insert", {"request_data": [payload_obj]})
        except NonRetryableHTTP as e:
            if e.status_code != 400:
                raise SystemExit(f"[ioc] Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")
            last_400 = e.body
            continue

    raise SystemExit(f"[ioc] Create failed. Last 400 body:\n{last_400 or ''}")


def ioc_update(session: requests.Session, base_url: str, obj: dict, rule_id: Any) -> dict:
    payload_obj = ensure_ioc_required_fields(obj)
    payload_obj["rule_id"] = rule_id
    print(f"[ioc] update rule_id={rule_id}")
    try:
        return http_post(session, base_url, "/public_api/v1/indicators/insert", {"request_data": [payload_obj]})
    except NonRetryableHTTP as e:
        raise SystemExit(f"[ioc] Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")


# ------------------ BIOCs ------------------
def bioc_get_by_name(session: requests.Session, base_url: str, name: str) -> List[dict]:
    payload = {
        "request_data": {
            "extended_view": True,
            "filters": [{"field": "name", "operator": "EQ", "value": name}],
            "search_from": 0,
            "search_to": 1,
        }
    }
    return parse_objects(http_post(session, base_url, "/public_api/v1/bioc/get", payload))


def bioc_create_with_shape_fallback(session: requests.Session, base_url: str, obj: dict) -> dict:
    shapes = ["omit_rule_id", "rule_id_null"]
    last_400: Optional[str] = None

    for shape in shapes:
        payload_obj = bioc_sanitize_for_insert(obj)

        if shape == "omit_rule_id":
            payload_obj.pop("rule_id", None)
        else:
            payload_obj["rule_id"] = None

        print(f"[bioc] create attempt shape={shape}")
        try:
            return http_post(session, base_url, "/public_api/v1/bioc/insert", {"request_data": [payload_obj]})
        except NonRetryableHTTP as e:
            # Graceful skip if unsupported
            if e.status_code == 400 and _is_bioc_unsupported_error(e.body) and not STRICT_BIOC:
                print("[bioc] BIOC not supported in this tenant/api-key. Skipping BIOCs for this run.")
                return {"skipped": True, "reason": "BIOC not supported"}

            if e.status_code != 400:
                raise SystemExit(f"[bioc] Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")

            last_400 = e.body
            continue

    raise SystemExit(f"[bioc] Create failed. Last 400 body:\n{last_400 or ''}")


def bioc_update(session: requests.Session, base_url: str, obj: dict, rule_id: Any) -> dict:
    payload_obj = bioc_sanitize_for_insert(obj)
    payload_obj["rule_id"] = rule_id
    print(f"[bioc] update rule_id={rule_id}")
    try:
        return http_post(session, base_url, "/public_api/v1/bioc/insert", {"request_data": [payload_obj]})
    except NonRetryableHTTP as e:
        if e.status_code == 400 and _is_bioc_unsupported_error(e.body) and not STRICT_BIOC:
            print("[bioc] BIOC not supported in this tenant/api-key. Skipping BIOCs for this run.")
            return {"skipped": True, "reason": "BIOC not supported"}
        raise SystemExit(f"[bioc] Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")


# ------------------ Main ------------------
def main() -> None:
    print("=== RECONCILE_XSIAM.PY START ===")
    print(f"[RECON] cwd={Path.cwd()}")
    print(f"[RECON] DRY_RUN={DRY_RUN}")
    print(f"[RECON] enable: correlations={ENABLE_CORRELATIONS} iocs={ENABLE_IOCS} biocs={ENABLE_BIOCS}")
    print(f"[RECON] strict_bioc={STRICT_BIOC}")
    print(f"[RECON] enforce_prefix={ENFORCE_PREFIX} enforce_marker={ENFORCE_MARKER}")
    print(f"[RECON] ioc_default_expiration_days={IOC_DEFAULT_EXPIRATION_DAYS}")

    base_url = normalize_base_url(must_env("XSIAM_FQDN"))
    api_key = must_env("XSIAM_API_KEY")
    api_key_id = must_env("XSIAM_API_KEY_ID")

    print(f"[RECON] base_url={base_url}")
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

    created = updated = 0

    # -------- Correlations --------
    if ENABLE_CORRELATIONS:
        corrs = _load_json_dir(CORR_DIR, "correlations")
        seen_names: set[str] = set()
        for obj in corrs:
            if "name" not in obj:
                raise SystemExit("[correlation] Missing 'name' in a correlation object.")
            _maybe_enforce_name_and_marker(obj)
            n = (obj.get("name") or "").strip()
            if not n:
                raise SystemExit("[correlation] Empty 'name' after processing.")
            if n in seen_names:
                raise SystemExit(f"[correlation] Duplicate name in local repo: {n}")
            seen_names.add(n)

        print(f"[RECON] correlations desired={len(corrs)}")
        for obj in corrs:
            name = obj["name"].strip()
            print(f"[correlation] upsert by name: {name}")

            existing_list = correlation_get_by_name(s, base_url, name)
            existing = existing_list[0] if existing_list else None

            if existing:
                rid = _extract_rule_id(existing)
                if not rid:
                    raise SystemExit(f"[correlation] Could not determine id for existing rule: {name}")
                correlation_update(s, base_url, obj, rid)
                updated += 1
            else:
                correlation_create_with_shape_fallback(s, base_url, obj)
                created += 1

            verify = correlation_get_by_name(s, base_url, name)
            if not verify:
                raise SystemExit(f"[correlation] Verify failed: not found after upsert: {name}")
            print(f"[correlation] verify ok: id={_extract_rule_id(verify[0])}")

    # -------- IOCs --------
    if ENABLE_IOCS:
        iocs = _load_json_dir(IOC_DIR, "iocs")
        seen_keys: set[Tuple[str, str]] = set()
        for obj in iocs:
            obj_norm = ensure_ioc_required_fields(obj)
            k = ioc_key(obj_norm)
            if k in seen_keys:
                raise SystemExit(f"[ioc] Duplicate IOC in local repo: type={k[0]} indicator={k[1]}")
            seen_keys.add(k)

        print(f"[RECON] iocs desired={len(iocs)}")
        for obj in iocs:
            obj = ensure_ioc_required_fields(obj)
            t, ind = ioc_key(obj)
            print(f"[ioc] upsert by key: type={t} indicator={ind}")

            existing_list = ioc_get_by_key(s, base_url, t, ind)
            existing = existing_list[0] if existing_list else None

            if existing:
                rid = _extract_rule_id(existing)
                if not rid:
                    raise SystemExit(f"[ioc] Could not determine id for existing IOC: type={t} indicator={ind}")
                ioc_update(s, base_url, obj, rid)
                updated += 1
            else:
                ioc_create_with_shape_fallback(s, base_url, obj)
                created += 1

            verify = ioc_get_by_key(s, base_url, t, ind)
            if not verify:
                raise SystemExit(f"[ioc] Verify failed: not found after upsert: type={t} indicator={ind}")
            print(f"[ioc] verify ok: id={_extract_rule_id(verify[0])}")

    # -------- BIOCs --------
    if ENABLE_BIOCS:
        biocs = _load_json_dir(BIOC_DIR, "biocs")
        if biocs:
            seen_names: set[str] = set()
            for obj in biocs:
                if "name" not in obj:
                    raise SystemExit("[bioc] Missing 'name' in a BIOC object.")
                _maybe_enforce_name_and_marker(obj)
                n = (obj.get("name") or "").strip()
                if not n:
                    raise SystemExit("[bioc] Empty 'name' after processing.")
                if n in seen_names:
                    raise SystemExit(f"[bioc] Duplicate BIOC name in local repo: {n}")
                seen_names.add(n)

            print(f"[RECON] biocs desired={len(biocs)}")
            bioc_supported = True

            for obj in biocs:
                if not bioc_supported:
                    print("[bioc] Skipping remaining BIOCs (BIOC not supported).")
                    break

                name = obj["name"].strip()
                print(f"[bioc] upsert by name: {name}")

                try:
                    existing_list = bioc_get_by_name(s, base_url, name)
                except NonRetryableHTTP as e:
                    if e.status_code == 400 and _is_bioc_unsupported_error(e.body) and not STRICT_BIOC:
                        print("[bioc] BIOC not supported in this tenant/api-key. Skipping BIOCs for this run.")
                        bioc_supported = False
                        break
                    raise

                existing = existing_list[0] if existing_list else None

                if existing:
                    rid = _extract_rule_id(existing)
                    if not rid:
                        raise SystemExit(f"[bioc] Could not determine id for existing BIOC: {name}")
                    resp = bioc_update(s, base_url, obj, rid)
                    if resp.get("skipped"):
                        bioc_supported = False
                        break
                    updated += 1
                else:
                    resp = bioc_create_with_shape_fallback(s, base_url, obj)
                    if resp.get("skipped"):
                        bioc_supported = False
                        break
                    created += 1

                verify = bioc_get_by_name(s, base_url, name)
                if not verify:
                    raise SystemExit(f"[bioc] Verify failed: not found after upsert: {name}")
                print(f"[bioc] verify ok: id={_extract_rule_id(verify[0])}")

    print(f"[RECON] Summary: created={created} updated={updated}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise
