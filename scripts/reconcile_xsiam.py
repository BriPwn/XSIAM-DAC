#!/usr/bin/env python3
# scripts/reconcile_xsiam.py
"""
Full reconciliation for Cortex XSIAM (Git = source of truth)

Manages:
- Correlation rules (by name) from generated/correlations/*.json
- BIOCs (by name) from rules/biocs/biocs.yaml
- IOCs (by (type, indicator)) from rules/iocs/iocs.yaml

Behavior:
- Create if missing
- Update if changed (idempotent compare on managed keys)
- Delete if remote object is managed-by-this-pipeline AND missing from desired state

Reliability:
- Normalizes XSIAM_FQDN so it can be either a bare host or a full https:// URL
- Retries on transient network errors and 429/5xx/599
- **Fix applied:** XSIAM paging constraint enforced: 1 <= search_size <= 100
- **Fix applied:** Non-retryable 599 handling when body indicates a deterministic client error
- FAILS if API returns errors/failures in JSON even when HTTP=200

Env vars:
Required:
- XSIAM_FQDN  (either api-tenant.xdr... OR https://api-tenant.xdr...)
- XSIAM_API_KEY
- XSIAM_API_KEY_ID

Optional:
- DAC_PREFIX (default "DAC: ")
- DAC_MARKER (default "Managed by detections-as-code")
- DRY_RUN    (default "false")
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import yaml
from requests.exceptions import ConnectionError, HTTPError, Timeout

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")


# ----------------------------
# Utilities
# ----------------------------
def must_env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"Missing env var: {name}")
    return v


def normalize_base_url(fqdn_or_url: str) -> str:
    """
    Accepts either:
      - api-tenant.xdr.us.paloaltonetworks.com
      - https://api-tenant.xdr.us.paloaltonetworks.com
    Returns a clean base URL with no trailing slash.
    """
    v = fqdn_or_url.strip()
    if v.startswith("http://") or v.startswith("https://"):
        return v.rstrip("/")
    return ("https://" + v).rstrip("/")


def load_yaml(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def normalize_value(v: Any) -> Any:
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, list):
        # sort simple lists for deterministic compare
        if all(not isinstance(x, dict) for x in v):
            return sorted(normalize_value(x) for x in v)
        return [normalize_value(x) for x in v]
    if isinstance(v, dict):
        return {k: normalize_value(v[k]) for k in sorted(v.keys())}
    return v


def normalize_for_compare(obj: Dict[str, Any], allowed_keys: set[str]) -> Dict[str, Any]:
    filtered = {k: obj.get(k) for k in allowed_keys if k in obj}
    return normalize_value(filtered)


def is_managed_by_pipeline(name: str, text_field: str) -> bool:
    return name.startswith(DAC_PREFIX) and (DAC_MARKER in (text_field or ""))


def parse_objects(resp: dict) -> List[dict]:
    # common patterns in Cortex APIs
    if isinstance(resp.get("objects"), list):
        return resp["objects"]
    rep = resp.get("reply")
    if isinstance(rep, dict):
        if isinstance(rep.get("objects"), list):
            return rep["objects"]
        if isinstance(rep.get("data"), list):
            return rep["data"]
    return []


def parse_objects_count(resp: dict) -> Optional[int]:
    if isinstance(resp.get("objects_count"), int):
        return resp["objects_count"]
    rep = resp.get("reply")
    if isinstance(rep, dict) and isinstance(rep.get("objects_count"), int):
        return rep["objects_count"]
    return None


def raise_on_api_errors(endpoint: str, resp: dict) -> None:
    """
    Fail the run if API indicates errors/failures, even if HTTP 200.
    This prevents "pipeline succeeded but nothing changed".
    """
    errors = resp.get("errors") or []
    if errors:
        raise SystemExit(f"XSIAM API returned errors for {endpoint}: {errors}")

    failures = resp.get("failed_objects") or resp.get("failed") or []
    if failures:
        raise SystemExit(f"XSIAM API returned failures for {endpoint}: {failures}")

    # Some Cortex APIs use reply.err_code/err_msg for failures
    rep = resp.get("reply")
    if isinstance(rep, dict):
        err_code = rep.get("err_code")
        if isinstance(err_code, int) and err_code != 0:
            # This is a generic "error wrapper" many endpoints use
            err_msg = rep.get("err_msg")
            err_extra = rep.get("err_extra")
            raise SystemExit(f"XSIAM API error for {endpoint}: err_code={err_code} err_msg={err_msg} err_extra={err_extra}")

    if resp.get("success") is False:
        raise SystemExit(f"XSIAM API indicates success=false for {endpoint}: {resp}")


# ----------------------------
# HTTP with retries
# ----------------------------
def _is_non_retryable_599(body_json: dict) -> bool:
    """
    XSIAM sometimes returns deterministic validation errors with HTTP 599.
    If so, retries will never fix it.
    """
    rep = body_json.get("reply") if isinstance(body_json, dict) else None
    if not isinstance(rep, dict):
        return False
    extra = rep.get("err_extra") or ""
    msg = rep.get("err_msg") or ""
    combined = f"{msg} {extra}".lower()
    # Add patterns here as you discover them
    if "search size" in combined or "search_size" in combined:
        return True
    return False


def http_post(session: requests.Session, base_url: str, path: str, payload: dict) -> dict:
    url = f"{base_url}{path}"

    # Dry run should still read remote state; only skip mutations
    if DRY_RUN and (path.endswith("/insert") or path.endswith("/delete")):
        return {"dry_run": True, "path": path, "payload": payload, "errors": []}

    last_exc: Exception | None = None
    for attempt in range(1, 6):
        try:
            r = session.post(url, json=payload, timeout=(10, 180))  # (connect, read)

            # Handle "weird" 599 that actually contains a deterministic error body
            if r.status_code == 599:
                try:
                    j = r.json()
                    if _is_non_retryable_599(j):
                        raise SystemExit(f"Non-retryable XSIAM 599 error from {url}: {j}")
                except ValueError:
                    # Not JSON; treat as retryable below
                    pass

            # Retry-worthy HTTP statuses (including 599 emitted by some proxies/LBs)
            if r.status_code in (429, 500, 502, 503, 504, 599):
                body = (r.text or "")[:800]
                raise HTTPError(
                    f"HTTP {r.status_code} from {url}. Body (first 800 chars): {body}",
                    response=r,
                )

            r.raise_for_status()

            # Some APIs may return non-json on error; raise to surface it
            try:
                data = r.json()
            except Exception:
                raise SystemExit(f"Non-JSON response from {url} (status {r.status_code}): {(r.text or '')[:800]}")

            raise_on_api_errors(path, data)
            return data

        except SystemExit:
            # Non-retryable deterministic validation error
            raise

        except (ConnectionError, Timeout, HTTPError) as e:
            last_exc = e
            if attempt < 5:
                sleep_s = 2 ** (attempt - 1)
                print(f"Request failed (attempt {attempt}/5): {e}\nRetrying in {sleep_s}s...")
                time.sleep(sleep_s)
                continue
            break

    raise SystemExit(f"XSIAM request failed after retries: {url}\nLast error: {last_exc}")


def paged_get_all(
    session: requests.Session,
    base_url: str,
    endpoint: str,
    extended_view: bool = True,
    page_size: int = 100,  # <-- IMPORTANT: XSIAM requires 1..100 (search_size constraint)
) -> List[dict]:
    """
    Paginates using search_from/search_to with a strict maximum search_size of 100.
    XSIAM error: "0 < search_size <= 100" if exceeded.
    """
    if page_size <= 0 or page_size > 100:
        raise ValueError("page_size must be in range 1..100 for XSIAM public API")

    out: List[dict] = []
    start = 0
    while True:
        payload = {
            "request_data": {
                "extended_view": extended_view,
                "search_from": start,
                "search_to": start + page_size,  # size = page_size, must be <= 100
            }
        }
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


def index_by_name(objs: List[dict]) -> Dict[str, List[dict]]:
    m: Dict[str, List[dict]] = {}
    for o in objs:
        n = (o.get("name") or "").strip()
        if n:
            m.setdefault(n, []).append(o)
    return m


# ------------------------
# Desired state loaders
# ------------------------
def load_desired_correlations() -> List[dict]:
    corr_dir = Path("generated/correlations")
    if not corr_dir.exists():
        return []
    desired: List[dict] = []
    for p in sorted(corr_dir.glob("*.json")):
        obj = json.loads(p.read_text(encoding="utf-8"))
        # Enforce managed scoping for safety
        if not obj["name"].startswith(DAC_PREFIX):
            obj["name"] = f"{DAC_PREFIX}{obj['name']}"
        desc = (obj.get("description") or "").strip()
        if DAC_MARKER not in desc:
            obj["description"] = (desc + "\n\n" + DAC_MARKER).strip()
        desired.append(obj)
    return desired


def load_desired_biocs() -> List[dict]:
    p = Path("rules/biocs/biocs.yaml")
    if not p.exists():
        return []
    data = load_yaml(p) or {}
    items = data.get("rules", []) if isinstance(data, dict) else []
    desired: List[dict] = []
    for obj in items:
        if not obj["name"].startswith(DAC_PREFIX):
            obj["name"] = f"{DAC_PREFIX}{obj['name']}"
        comment = (obj.get("comment") or "").strip()
        if DAC_MARKER not in comment:
            obj["comment"] = (comment + "\n\n" + DAC_MARKER).strip()
        desired.append(obj)
    return desired


def load_desired_iocs() -> List[dict]:
    p = Path("rules/iocs/iocs.yaml")
    if not p.exists():
        return []
    data = load_yaml(p) or {}
    items = data.get("indicators", []) if isinstance(data, dict) else []
    desired: List[dict] = []
    for obj in items:
        comment = (obj.get("comment") or "").strip()
        if DAC_MARKER not in comment:
            obj["comment"] = (comment + "\n\n" + DAC_MARKER).strip()
        desired.append(obj)
    return desired


# ------------------------
# Upsert/Delete helpers
# ------------------------
def upsert_by_name(
    session: requests.Session,
    base_url: str,
    obj_type: str,
    desired: dict,
    remote_index: Dict[str, List[dict]],
    insert_endpoint: str,
    managed_keys: set[str],
) -> str:
    name = desired["name"].strip()
    existing_list = remote_index.get(name, [])

    if len(existing_list) > 1:
        raise SystemExit(f"Remote has duplicate {obj_type} objects named '{name}'. Cannot reconcile safely.")

    if not existing_list:
        payload = {"request_data": [desired]}
        resp = http_post(session, base_url, insert_endpoint, payload)
        added = resp.get("added_objects") or []
        updated = resp.get("updated_objects") or []
        print(f"[{obj_type}] insert response: added={len(added)} updated={len(updated)}")
        return "created"

    existing = existing_list[0]
    desired_for_update = dict(desired)
    desired_for_update["rule_id"] = existing.get("id")

    if normalize_for_compare(desired_for_update, managed_keys) == normalize_for_compare(existing, managed_keys):
        return "unchanged"

    payload = {"request_data": [desired_for_update]}
    resp = http_post(session, base_url, insert_endpoint, payload)
    added = resp.get("added_objects") or []
    updated = resp.get("updated_objects") or []
    print(f"[{obj_type}] update response: added={len(added)} updated={len(updated)}")
    return "updated"


def delete_by_name(session: requests.Session, base_url: str, delete_endpoint: str, name: str) -> None:
    payload = {"request_data": {"filters": [{"field": "name", "operator": "EQ", "value": name}]}}
    http_post(session, base_url, delete_endpoint, payload)


def upsert_ioc(
    session: requests.Session,
    base_url: str,
    desired: dict,
    remote_map: Dict[Tuple[str, str], dict],
    managed_keys: set[str],
) -> str:
    key = (str(desired.get("type")), str(desired.get("indicator")))
    existing = remote_map.get(key)

    if existing is None:
        payload = {"request_data": [desired]}
        resp = http_post(session, base_url, "/public_api/v1/indicators/insert", payload)
        added = resp.get("added_objects") or []
        updated = resp.get("updated_objects") or []
        print(f"[ioc] insert response: added={len(added)} updated={len(updated)}")
        return "created"

    desired_for_update = dict(desired)
    desired_for_update["rule_id"] = existing.get("id")

    if normalize_for_compare(desired_for_update, managed_keys) == normalize_for_compare(existing, managed_keys):
        return "unchanged"

    payload = {"request_data": [desired_for_update]}
    resp = http_post(session, base_url, "/public_api/v1/indicators/insert", payload)
    added = resp.get("added_objects") or []
    updated = resp.get("updated_objects") or []
    print(f"[ioc] update response: added={len(added)} updated={len(updated)}")
    return "updated"


def delete_ioc(session: requests.Session, base_url: str, indicator_value: str) -> None:
    payload = {"request_data": {"filters": [{"field": "indicator", "operator": "EQ", "value": indicator_value}]}}
    http_post(session, base_url, "/public_api/v1/indicators/delete", payload)


# ------------------------
# Main
# ------------------------
def main() -> None:
    fqdn = must_env("XSIAM_FQDN")
    api_key = must_env("XSIAM_API_KEY")
    api_key_id = must_env("XSIAM_API_KEY_ID")

    base_url = normalize_base_url(fqdn)
    print(f"Using XSIAM base URL: {base_url}")
    if urlparse(base_url).scheme != "https":
        raise SystemExit("XSIAM base URL must be https.")

    s = requests.Session()
    s.headers.update(
        {
            "Authorization": api_key,
            "x-xdr-auth-id": api_key_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )

    desired_correlations = load_desired_correlations()
    desired_biocs = load_desired_biocs()
    desired_iocs = load_desired_iocs()

    print(f"Desired: correlations={len(desired_correlations)} biocs={len(desired_biocs)} iocs={len(desired_iocs)}")

    # Fetch remote state (read-only calls happen even in DRY_RUN)
    remote_correlations = paged_get_all(s, base_url, "/public_api/v1/correlations/get", extended_view=True, page_size=100)
    remote_biocs = paged_get_all(s, base_url, "/public_api/v1/bioc/get", extended_view=True, page_size=100)
    remote_iocs = paged_get_all(s, base_url, "/public_api/v1/indicators/get", extended_view=True, page_size=100)

    # ------------------------
    # Correlations
    # ------------------------
    corr_idx = index_by_name(remote_correlations)
    corr_keys = {
        "name",
        "severity",
        "xql_query",
        "is_enabled",
        "description",
        "alert_name",
        "alert_category",
        "execution_mode",
        "search_window",
        "simple_schedule",
        "timezone",
        "crontab",
        "suppression_enabled",
        "suppression_duration",
        "suppression_fields",
        "mapping_strategy",
    }

    c_created = c_updated = c_unchanged = c_deleted = 0
    desired_corr_names = set()

    for d in desired_correlations:
        desired_corr_names.add(d["name"])
        status = upsert_by_name(
            s,
            base_url,
            "correlation",
            d,
            corr_idx,
            "/public_api/v1/correlations/insert",
            corr_keys,
        )
        print(f"[correlation] {d['name']}: {status}")
        if status == "created":
            c_created += 1
        elif status == "updated":
            c_updated += 1
        else:
            c_unchanged += 1

    for r in remote_correlations:
        name = (r.get("name") or "").strip()
        desc = (r.get("description") or "").strip()
        if not name:
            continue
        if is_managed_by_pipeline(name, desc) and name not in desired_corr_names:
            print(f"[correlation] {name}: delete")
            if not DRY_RUN:
                delete_by_name(s, base_url, "/public_api/v1/correlations/delete", name)
            c_deleted += 1

    print(f"Correlation reconcile: {c_created} created, {c_updated} updated, {c_unchanged} unchanged, {c_deleted} deleted")

    # ------------------------
    # BIOCs
    # ------------------------
    bioc_idx = index_by_name(remote_biocs)
    bioc_keys = {"name", "type", "severity", "comment", "status", "is_xql", "indicator"}

    b_created = b_updated = b_unchanged = b_deleted = 0
    desired_bioc_names = set()

    for d in desired_biocs:
        desired_bioc_names.add(d["name"])
        status = upsert_by_name(
            s,
            base_url,
            "bioc",
            d,
            bioc_idx,
            "/public_api/v1/bioc/insert",
            bioc_keys,
        )
        print(f"[bioc] {d['name']}: {status}")
        if status == "created":
            b_created += 1
        elif status == "updated":
            b_updated += 1
        else:
            b_unchanged += 1

    for r in remote_biocs:
        name = (r.get("name") or "").strip()
        comment = (r.get("comment") or "").strip()
        if not name:
            continue
        if is_managed_by_pipeline(name, comment) and name not in desired_bioc_names:
            print(f"[bioc] {name}: delete")
            if not DRY_RUN:
                delete_by_name(s, base_url, "/public_api/v1/bioc/delete", name)
            b_deleted += 1

    print(f"BIOC reconcile: {b_created} created, {b_updated} updated, {b_unchanged} unchanged, {b_deleted} deleted")

    # ------------------------
    # IOCs
    # ------------------------
    remote_ioc_map: Dict[Tuple[str, str], dict] = {}
    for r in remote_iocs:
        t = str(r.get("type"))
        ind = str(r.get("indicator"))
        if t and ind:
            remote_ioc_map[(t, ind)] = r

    ioc_keys = {
        "type",
        "indicator",
        "severity",
        "expiration_date",
        "default_expiration_enabled",
        "comment",
        "reputation",
        "reliability",
        "vendor_name",
    }

    i_created = i_updated = i_unchanged = i_deleted = 0
    desired_ioc_keys = set()

    for d in desired_iocs:
        key = (str(d.get("type")), str(d.get("indicator")))
        desired_ioc_keys.add(key)
        status = upsert_ioc(s, base_url, d, remote_ioc_map, ioc_keys)
        print(f"[ioc] {key}: {status}")
        if status == "created":
            i_created += 1
        elif status == "updated":
            i_updated += 1
        else:
            i_unchanged += 1

    for key, r in remote_ioc_map.items():
        comment = (r.get("comment") or "").strip()
        if (DAC_MARKER in comment) and key not in desired_ioc_keys:
            indicator_value = str(r.get("indicator"))
            print(f"[ioc] {key}: delete")
            if not DRY_RUN:
                delete_ioc(s, base_url, indicator_value)
            i_deleted += 1

    print(f"IOC reconcile: {i_created} created, {i_updated} updated, {i_unchanged} unchanged, {i_deleted} deleted")

    if DRY_RUN:
        print("DRY_RUN enabled: no changes were applied.")


if __name__ == "__main__":
    main()

