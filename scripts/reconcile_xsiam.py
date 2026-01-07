#!/usr/bin/env python3
# scripts/reconcile_xsiam.py

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")

DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")
VALIDATE_XQL = os.getenv("VALIDATE_XQL", "true").lower() in ("1", "true", "yes")


@dataclass
class NonRetryableHTTP(Exception):
    status_code: int
    url: str
    body: str


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
        return rep.get("objects_count")
    return None


def raise_on_api_errors(endpoint: str, resp: dict) -> None:
    errors = resp.get("errors") or []
    if errors:
        raise SystemExit(f"XSIAM API returned errors for {endpoint}: {errors}")

    rep = resp.get("reply")
    if isinstance(rep, dict) and rep.get("err_code"):
        raise SystemExit(
            f"XSIAM API error for {endpoint}: err_code={rep.get('err_code')} "
            f"err_msg={rep.get('err_msg')} err_extra={rep.get('err_extra')}"
        )

    if "err_code" in resp and resp.get("err_code"):
        raise SystemExit(
            f"XSIAM API error for {endpoint}: err_code={resp.get('err_code')} "
            f"err_msg={resp.get('err_msg')} err_extra={resp.get('err_extra')}"
        )


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

            # Retry-worthy statuses
            if r.status_code in (429, 500, 502, 503, 504, 599):
                body = (r.text or "")[:1200]
                raise HTTPError(f"HTTP {r.status_code} from {url}. Body: {body}", response=r)

            r.raise_for_status()
            data = r.json()
            raise_on_api_errors(path, data)
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


def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def validate_xql_or_die(session: requests.Session, base_url: str, xql: str) -> None:
    """
    Optional pre-validation to surface detailed XQL errors.
    """
    if not VALIDATE_XQL:
        return

    q = (xql or "").strip()
    if not q:
        raise SystemExit("[XQL] Empty xql_query in desired payload")

    if "| limit" not in q.lower():
        q = q + " | limit 1"

    now = datetime.now(timezone.utc)
    frm = now - timedelta(hours=1)

    payload = {
        "request_data": {
            "query": q,
            "tenants": [],
            "timeframe": {"from": _epoch_ms(frm), "to": _epoch_ms(now)},
        }
    }

    try:
        resp = http_post(session, base_url, "/public_api/v1/xql/start_xql_query", payload)
    except NonRetryableHTTP as e:
        # If validation itself fails, print body and exit (this is useful detail)
        raise SystemExit(f"[XQL] Validation failed: HTTP {e.status_code} {e.url}\nBody:\n{e.body}")

    rep = resp.get("reply")
    if isinstance(rep, dict) and rep.get("query_id"):
        print(f"[XQL] validate ok: query_id={rep.get('query_id')}")
    else:
        print("[XQL] validate ok")


def _try_insert_with_shapes(
    session: requests.Session,
    base_url: str,
    correlation_obj: dict,
    shapes: List[str],
) -> dict:
    """
    Attempt /correlations/insert with multiple create 'shapes' because some tenants
    inconsistently handle rule_id for create. Docs show rule_id=0 in samples, but some
    tenants treat rule_id=0 as update. :contentReference[oaicite:1]{index=1}
    """
    last_err: Optional[str] = None
    for shape in shapes:
        obj = dict(correlation_obj)

        if shape == "omit_rule_id":
            obj.pop("rule_id", None)
        elif shape == "rule_id_null":
            obj["rule_id"] = None
        else:
            raise ValueError(f"Unknown shape: {shape}")

        print(f"[correlation] insert attempt shape={shape}")

        try:
            resp = http_post(session, base_url, "/public_api/v1/correlations/insert", {"request_data": [obj]})
            return resp
        except NonRetryableHTTP as e:
            # Only try another shape on 400 (Bad Request). For anything else, stop.
            if e.status_code != 400:
                raise SystemExit(f"Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")

            last_err = e.body
            # If tenant explicitly complains about update(id=0), don't keep trying zero.
            if "Correlation rule: 0 does not exist" in e.body:
                print("[correlation] server treated rule_id=0 as update; will not use rule_id_zero for create")
                continue

            # Generic "Failed to create correlation rule" -> try next shape
            continue

    raise SystemExit(
        "All create-shape attempts failed for /correlations/insert.\n"
        f"Last 400 body:\n{(last_err or '')}"
    )


def main() -> None:
    print("=== RECONCILE_XSIAM.PY START ===")
    print(f"[RECON] cwd={Path.cwd()}")
    print(f"[RECON] DRY_RUN={DRY_RUN}")
    print(f"[RECON] VALIDATE_XQL={VALIDATE_XQL}")

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

        validate_xql_or_die(s, base_url, d.get("xql_query", ""))

        existing = remote_by_name.get(name)

        if existing:
            # UPDATE: set rule_id to existing id
            d2 = dict(d)
            d2["rule_id"] = existing.get("id")
            try:
                resp = http_post(s, base_url, "/public_api/v1/correlations/insert", {"request_data": [d2]})
            except NonRetryableHTTP as e:
                raise SystemExit(f"Non-retryable HTTP {e.status_code} from {e.url}\nBody:\n{e.body}")

            add_n = len(resp.get("added_objects") or [])
            upd_n = len(resp.get("updated_objects") or [])
            print(f"[correlation] update response: added={add_n} updated={upd_n}")
            if upd_n > 0:
                updated += 1
            else:
                unchanged += 1
        else:
            # CREATE: try multiple shapes (omit/null/0)
            resp = _try_insert_with_shapes(
                s,
                base_url,
                d,
                shapes=["omit_rule_id", "rule_id_null"],
            )
            add_n = len(resp.get("added_objects") or [])
            upd_n = len(resp.get("updated_objects") or [])
            print(f"[correlation] create response: added={add_n} updated={upd_n}")
            if add_n > 0:
                created += 1
            else:
                raise SystemExit(f"[correlation] ERROR: expected add, got added={add_n} updated={upd_n}. Full response: {resp}")

        # Verify after upsert
        objs = get_correlation_by_name(s, base_url, name)
        ids = [o.get("id") for o in objs]
        print(f"[correlation] verify after upsert: count={len(objs)} ids={ids}")
        if len(objs) == 0:
            raise SystemExit(f"[correlation] ERROR: verify failed; correlation not found by name after upsert: {name}")

    print(f"[RECON] Summary: created={created} updated={updated} unchanged={unchanged}")


if __name__ == "__main__":
    main()

