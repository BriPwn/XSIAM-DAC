#!/usr/bin/env python3
"""
Correlation-only reconciliation for Cortex XSIAM.

- Source of truth: rules/correlations/*.json
- Upsert key: correlation "name" (string, unique)
- Create: /public_api/v1/correlations/insert with rule_id omitted (fallback rule_id=null)
- Update: /public_api/v1/correlations/insert with rule_id set to existing id
- Verifies existence by name after each upsert
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout

# -------- Config (env) --------
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")
DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ").strip() or "DAC: "
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")

CORR_DIR = Path(os.getenv("CORRELATIONS_DIR", "rules/correlations"))


# -------- Errors --------
@dataclass
class NonRetryableHTTP(Exception):
    status_code: int
    url: str
    body: str


# -------- Helpers --------
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

    if DRY_RUN and path.endswith("/insert"):
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

    return out


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


def index_by_name(objs: List[dict]) -> Dict[str, dict]:
    m: Dict[str, dict] = {}
    for o in objs:
        n = (o.get("name") or "").strip()
        if n and n not in m:
            m[n] = o
    return m


def load_local_correlations() -> List[dict]:
    if not CORR_DIR.exists():
        raise SystemExit(f"Correlation directory not found: {CORR_DIR.resolve()}")

    files = sorted([p for p in CORR_DIR.glob("*.json") if p.name != ".gitkeep"])
    print(f"[LOCAL] correlations_dir={CORR_DIR.resolve()} files={len(files)}")
    if not files:
        raise SystemExit(f"[LOCAL] No correlation JSON files found in {CORR_DIR.resolve()}")

    correlations: List[dict] = []
    seen_names: Dict[str, Path] = {}

    for p in files:
        obj = json.loads(p.read_text(encoding="utf-8"))

        name = (obj.get("name") or "").strip()
        if not name:
            raise SystemExit(f"[LOCAL] Missing required field 'name' in {p}")

        # Optional: enforce DAC prefix and marker
        if not name.startswith(DAC_PREFIX):
            obj["name"] = f"{DAC_PREFIX}{name}"
            name = obj["name"]

        desc = (obj.get("description") or "").strip()
        if DAC_MARKER not in desc:
            obj["description"] = (desc + "\n\n" + DAC_MARKER).strip()

        if name in seen_names:
            raise SystemExit(
                f"[LOCAL] Duplicate correlation name detected:\n"
                f"  name: {name}\n"
                f"  files: {seen_names[name]} and {p}"
            )
        seen_names[name] = p

        correlations.append(obj)

    return correlations


def create_with_shape_fallback(session: requests.Session, base_url: str, obj: dict) -> dict:
    """
    Some tenants interpret rule_id=0 as update. We never use 0.
    We try:
      1) omit rule_id
      2) rule_id = null
    """
    shapes = ["omit_rule_id", "rule_id_null"]
    last_400: Optional[str] = None

    for shape in shapes:
        payload_obj = dict(obj)
        if shape == "omit_rule_id":
            payload_obj.pop("rule_id", None)
        elif shape == "rule_id_null":
            payload_obj["rule_id"] = None

        print(f"[correlation] create insert attempt shape={shape}")
        try:
            return http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [payload_obj]})
        except NonRetryableHTTP as e:
            if e.status_code != 400:
                raise SystemExit(f"Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")
            last_400 = e.body
            continue

    raise SystemExit(
        "[correlation] Create failed for all shapes.\n"
        f"Last 400 body:\n{(last_400 or '')}"
    )


def update_rule(session: requests.Session, base_url: str, obj: dict, rule_id: Any) -> dict:
    payload_obj = dict(obj)
    payload_obj["rule_id"] = rule_id
    print(f"[correlation] update insert rule_id={rule_id}")
    try:
        return http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [payload_obj]})
    except NonRetryableHTTP as e:
        raise SystemExit(f"Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")


def main() -> None:
    print("=== RECONCILE_XSIAM.PY START (correlations only) ===")
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

    local = load_local_correlations()
    print(f"[RECON] desired correlations={len(local)}")

    remote = paged_get_all_correlations(s, base_url, page_size=100)
    remote_by_name = index_by_name(remote)
    print(f"[RECON] remote correlations fetched={len(remote)}")

    created = updated = unchanged = 0

    for obj in local:
        name = obj["name"].strip()
        print(f"[correlation] upsert by name: {name}")

        existing = remote_by_name.get(name)

        if existing:
            rid = existing.get("id") or existing.get("rule_id") or existing.get("ruleId")
            if not rid:
                # fallback: attempt name query to grab ID
                by_name = get_correlation_by_name(s, base_url, name)
                if by_name:
                    rid = by_name[0].get("id") or by_name[0].get("rule_id") or by_name[0].get("ruleId")
            if not rid:
                raise SystemExit(f"[correlation] Could not determine rule_id for existing correlation: {name}")

            resp = update_rule(s, base_url, obj, rid)
            add_n = len(resp.get("added_objects") or [])
            upd_n = len(resp.get("updated_objects") or [])
            print(f"[correlation] update response: added={add_n} updated={upd_n}")
            if upd_n > 0:
                updated += 1
            else:
                unchanged += 1
        else:
            resp = create_with_shape_fallback(s, base_url, obj)
            add_n = len(resp.get("added_objects") or [])
            upd_n = len(resp.get("updated_objects") or [])
            print(f"[correlation] create response: added={add_n} updated={upd_n}")
            if add_n > 0:
                created += 1
            else:
                raise SystemExit(f"[correlation] Create returned no added_objects. Full response: {resp}")

        # Verify it exists by name
        verify = get_correlation_by_name(s, base_url, name)
        ids = [v.get("id") for v in verify]
        print(f"[correlation] verify: count={len(verify)} ids={ids}")
        if not verify:
            raise SystemExit(f"[correlation] Verify failed: correlation not found after upsert: {name}")

    print(f"[RECON] Summary: created={created} updated={updated} unchanged={unchanged}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise
