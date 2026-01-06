#!/usr/bin/env python3
# scripts/reconcile_xsiam.py

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")


def must_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"Missing env var: {name}")
    return v


def normalize_base_url(fqdn_or_url: str) -> str:
    v = fqdn_or_url.strip()
    if v.startswith("http://") or v.startswith("https://"):
        return v.rstrip("/")
    return ("https://" + v).rstrip("/")


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
        return rep["objects_count"]
    return None


def raise_on_api_errors(endpoint: str, resp: dict) -> None:
    # errors array form
    errors = resp.get("errors") or []
    if errors:
        raise SystemExit(f"XSIAM API returned errors for {endpoint}: {errors}")

    # err_code/err_msg form (doc shows this for invalid XQL, etc.) :contentReference[oaicite:3]{index=3}
    if "err_code" in resp and resp.get("err_code"):
        raise SystemExit(
            f"XSIAM API error for {endpoint}: err_code={resp.get('err_code')} "
            f"err_msg={resp.get('err_msg')} err_extra={resp.get('err_extra')}"
        )


def http_post(session: requests.Session, base_url: str, path: str, payload: dict) -> dict:
    url = f"{base_url}{path}"

    if DRY_RUN and (path.endswith("/insert") or path.endswith("/delete")):
        print(f"[HTTP] DRY_RUN skip POST {url}")
        return {"dry_run": True, "path": path, "payload": payload, "errors": []}

    last_exc: Exception | None = None
    for attempt in range(1, 6):
        try:
            r = session.post(url, json=payload, timeout=(10, 180))

            # Non-retryable 4xx (except 429)
            if 400 <= r.status_code < 500 and r.status_code != 429:
                body = (r.text or "")[:4000]
                raise SystemExit(f"Non-retryable HTTP {r.status_code} from {url}\nBody:\n{body}")

            # Retry-worthy statuses
            if r.status_code in (429, 500, 502, 503, 504, 599):
                body = (r.text or "")[:1200]
                raise HTTPError(f"HTTP {r.status_code} from {url}. Body: {body}", response=r)

            r.raise_for_status()
            data = r.json()
            raise_on_api_errors(path, data)
            return data

        except SystemExit:
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


def paged_get_all(session: requests.Session, base_url: str, endpoint: str, page_size: int = 100) -> List[dict]:
    if page_size <= 0 or page_size > 100:
        raise ValueError("page_size must be 1..100")

    out: List[dict] = []
    start = 0
    while True:
        payload = {"request_data": {"extended_view": True, "search_from": start, "search_to": start + page_size}}
        resp = http_post(session, base_url, endpoint, payload)
        objs = parse_objects(resp)
        out.extend(objs)

        count = parse_objects_count(resp)
        if count is not None and len(out) >= count:
            break
        if not objs:
            break

        start += page_size
    return out


def index_by_name(objs: List[dict]) -> Dict[str, dict]:
    m: Dict[str, dict] = {}
    for o in objs:
        n = (o.get("name") or "").strip()
        if n and n not in m:
            m[n] = o
    return m


DATASET_RE = re.compile(r"^\s*dataset\s*=\s*([a-zA-Z0-9_]+)\s*\|", re.MULTILINE)


def derive_dataset_from_xql(xql: str) -> str:
    m = DATASET_RE.search(xql or "")
    if m:
        return m.group(1)
    # safe default commonly used in examples
    return "xdr_data"


def normalize_create_payload(obj: dict) -> dict:
    """
    Make the payload more consistent with the documented schema:
    - Ensure dataset matches XQL (common cause of create failure)
    - Ensure required fields exist in expected types
    """
    out = dict(obj)

    xql = (out.get("xql_query") or "").strip()
    out["xql_query"] = xql
    out["dataset"] = derive_dataset_from_xql(xql)

    # Ensure these are objects (not lists)
    if not isinstance(out.get("alert_fields"), dict):
        out["alert_fields"] = {}
    if not isinstance(out.get("mitre_defs"), dict):
        out["mitre_defs"] = {}

    # Ensure drilldown_query_timeframe is valid enum (QUERY/ALERT) :contentReference[oaicite:4]{index=4}
    if out.get("drilldown_query_timeframe") not in ("QUERY", "ALERT"):
        out["drilldown_query_timeframe"] = "QUERY"

    # Clamp severity to allowed values (max SEV_040_HIGH) :contentReference[oaicite:5]{index=5}
    if out.get("severity") not in ("SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"):
        out["severity"] = "SEV_030_MEDIUM"

    # Keep timezone unquoted; many tenants accept IANA tz names
    tz = out.get("timezone")
    if isinstance(tz, str):
        out["timezone"] = tz.replace('"', "").strip()

    return out


def create_correlation(session: requests.Session, base_url: str, d: dict) -> Tuple[dict, str]:
    """
    Tenant behavior differs:
    - Doc example uses rule_id=0 for create :contentReference[oaicite:6]{index=6}
    - Some tenants treat rule_id=0 as an update attempt ("ID 0 does not exist")

    So we try:
      A) rule_id=0
      B) omit rule_id (only if A fails with the "ID 0 update" pattern)
    """
    base = normalize_create_payload(d)

    # Variant A: rule_id = 0 (documented)
    a = dict(base)
    a["rule_id"] = 0
    try:
        resp = http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [a]})
        return resp, "create_rule_id_0"
    except SystemExit as e:
        msg = str(e)

        # If tenant treats rule_id=0 as update-id-0, try omitting rule_id
        if "Correlation rule: 0 does not exist" in msg or "Failed to update correlation rule with the ID: 0" in msg:
            pass
        else:
            print("[correlation] create payload (rule_id=0) that failed:")
            print(json.dumps(a, indent=2)[:2000])
            raise

    # Variant B: omit rule_id
    b = dict(base)
    b.pop("rule_id", None)
    try:
        resp = http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [b]})
        return resp, "create_no_rule_id"
    except SystemExit:
        print("[correlation] create payload (no rule_id) that failed:")
        print(json.dumps(b, indent=2)[:2000])
        raise


def load_desired_correlations() -> List[dict]:
    corr_dir = Path("generated/correlations")
    files = sorted([p for p in corr_dir.glob("*.json") if p.name != ".gitkeep"]) if corr_dir.exists() else []
    print(f"[RECON] corr_dir={corr_dir.resolve()} exists={corr_dir.exists()} files={len(files)}")
    print(f"[RECON] corr_files={ [p.name for p in files[:50]] }")

    if not files:
        raise SystemExit("[RECON] ERROR: No generated/correlations/*.json found. Nothing to upload.")

    desired: List[dict] = []
    for p in files:
        obj = json.loads(p.read_text(encoding="utf-8"))

        if not obj["name"].startswith(DAC_PREFIX):
            obj["name"] = f"{DAC_PREFIX}{obj['name']}"

        desc = (obj.get("description") or "").strip()
        if DAC_MARKER not in desc:
            obj["description"] = (desc + "\n\n" + DAC_MARKER).strip()

        desired.append(obj)

    return desired


def get_correlation_by_name(session: requests.Session, base_url: str, name: str) -> List[dict]:
    payload = {
        "request_data": {
            "extended_view": True,
            "filters": [{"field": "name", "operator": "EQ", "value": name}],
            "search_from": 0,
            "search_to": 1,
        }
    }
    resp = http_post(session, base_url, "/public_api/v1/correlations/get", payload)
    return parse_objects(resp)


def main() -> None:
    print("=== RECONCILE_XSIAM.PY START ===")
    print(f"[RECON] cwd={Path.cwd()}")
    print(f"[RECON] DRY_RUN={DRY_RUN}")

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

    desired = load_desired_correlations()
    print(f"[RECON] desired correlations={len(desired)}")

    remote = paged_get_all(s, base_url, "/public_api/v1/correlations/get", page_size=100)
    remote_by_name = index_by_name(remote)
    print(f"[RECON] remote correlations fetched={len(remote)}")

    created = updated = unchanged = 0

    for d in desired:
        name = d["name"].strip()
        print(f"[correlation] attempting upsert: {name}")

        existing = remote_by_name.get(name)

        if existing:
            upd = dict(d)
            upd["rule_id"] = existing.get("id")
            resp = http_post(s, base_url, "/public_api/v1/correlations/insert", {"request_data": [upd]})
            add_n = len(resp.get("added_objects") or [])
            upd_n = len(resp.get("updated_objects") or [])
            print(f"[correlation] update response: added={add_n} updated={upd_n}")
            if upd_n > 0:
                updated += 1
            else:
                unchanged += 1
        else:
            resp, variant = create_correlation(s, base_url, d)
            add_n = len(resp.get("added_objects") or [])
            upd_n = len(resp.get("updated_objects") or [])
            print(f"[correlation] create response({variant}): added={add_n} updated={upd_n}")
            if add_n > 0:
                created += 1
            else:
                raise SystemExit(f"[correlation] ERROR: expected add, got added={add_n} updated={upd_n}. Full response: {resp}")

        # Verify
        objs = get_correlation_by_name(s, base_url, name)
        ids = [o.get("id") for o in objs]
        print(f"[correlation] verify after upsert: count={len(objs)} ids={ids}")
        if len(objs) == 0:
            raise SystemExit(f"[correlation] ERROR: verify failed; correlation not found by name after upsert: {name}")

    print(f"[RECON] Summary: created={created} updated={updated} unchanged={unchanged}")


if __name__ == "__main__":
    main()
