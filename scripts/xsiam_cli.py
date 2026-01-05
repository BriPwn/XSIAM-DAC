#!/usr/bin/env python3
"""
XSIAM Detection-as-Code CLI (GitHub-friendly)

Commands:
- sync: Upsert Correlation Rules, BIOCs, and (optionally) IOCs from repo JSON into Cortex XSIAM.

Environment variables required:
- XSIAM_API_KEY
- XSIAM_API_KEY_ID

Usage:
  python scripts/xsiam_cli.py sync --repo . --base-url "$XSIAM_BASE_URL"
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


# -----------------------------
# File utilities
# -----------------------------

def load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


# -----------------------------
# Dict merge + normalization helpers
# -----------------------------

def deep_merge(a: dict, b: dict) -> dict:
    """Merge b into a (recursively) and return new dict."""
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def correlation_required_defaults(name: str) -> dict:
    """
    /public_api/v1/correlations/insert requires a large set of fields (even if unused).
    Provide conservative defaults that satisfy the schema.

    IMPORTANT:
    Some tenants do NOT allow rule_id=0 for create. We will omit rule_id for create later.
    """
    return {
        # Identity / core (rule_id handled later)
        "name": name,
        "description": "",
        "severity": "SEV_020_LOW",
        "is_enabled": True,

        # Execution/schedule
        "execution_mode": "SCHEDULED",
        "search_window": "30 minutes",
        "simple_schedule": "5 minutes",
        "crontab": "",  # required by API; keep empty when using simple_schedule
        "timezone": "UTC",

        # Data/query
        "dataset": "alerts",  # required by API (set to your dataset if you prefer)
        "xql_query": "",

        # Alert metadata (required)
        "alert_name": name,
        "alert_description": "",
        "alert_category": "OTHER",
        "alert_domain": "OTHER",  # may be validated by tenant
        "alert_type": "OTHER",    # may be validated by tenant
        "user_defined_category": "",
        "user_defined_severity": "",

        # Mapping/actions (required)
        "mapping_strategy": "AUTO",
        "lookup_mapping": {},
        "alert_fields": {},
        "action": {},

        # UX fields (required)
        "investigation_query_link": "",
        "drilldown_query_timeframe": "30 minutes",

        # MITRE (required)
        "mitre_defs": [],

        # Suppression (required)
        "suppression_enabled": False,
        "suppression_fields": [],
        "suppression_duration": "0 minutes",
    }


def normalize_correlation_payload(rule: dict) -> dict:
    """
    Ensures correlation payload is schema-complete for /correlations/insert.
    """
    name = (rule.get("name") or "unnamed").strip() or "unnamed"
    base = correlation_required_defaults(name)
    merged = deep_merge(base, rule)

    # Ensure required string fields exist
    merged["crontab"] = merged.get("crontab") or ""
    merged["simple_schedule"] = merged.get("simple_schedule") or "5 minutes"
    merged["search_window"] = merged.get("search_window") or "30 minutes"
    merged["timezone"] = merged.get("timezone") or "UTC"
    merged["dataset"] = merged.get("dataset") or "alerts"
    merged["xql_query"] = merged.get("xql_query") or ""

    merged["alert_name"] = merged.get("alert_name") or name
    merged["alert_description"] = merged.get("alert_description") or merged.get("description") or ""
    merged["alert_category"] = merged.get("alert_category") or "OTHER"
    merged["alert_domain"] = merged.get("alert_domain") or "OTHER"
    merged["alert_type"] = merged.get("alert_type") or "OTHER"
    merged["user_defined_category"] = merged.get("user_defined_category") or ""
    merged["user_defined_severity"] = merged.get("user_defined_severity") or ""

    merged["investigation_query_link"] = merged.get("investigation_query_link") or ""
    merged["drilldown_query_timeframe"] = merged.get("drilldown_query_timeframe") or merged["search_window"]

    # Ensure required containers exist
    if merged.get("alert_fields") is None:
        merged["alert_fields"] = {}
    if merged.get("lookup_mapping") is None:
        merged["lookup_mapping"] = {}
    if merged.get("action") is None:
        merged["action"] = {}
    if merged.get("mitre_defs") is None:
        merged["mitre_defs"] = []
    if merged.get("suppression_fields") is None:
        merged["suppression_fields"] = []

    # Coerce booleans
    merged["suppression_enabled"] = bool(merged.get("suppression_enabled", False))
    merged["is_enabled"] = bool(merged.get("is_enabled", True))

    # IMPORTANT: avoid passing an "id" field accidentally
    merged.pop("id", None)

    return merged


# -----------------------------
# XSIAM API client
# -----------------------------

class XsiamClient:
    """
    Minimal XSIAM REST API client for:
    - IOCs: /public_api/v1/indicators/get, /insert
    - BIOCs: /public_api/v1/bioc/get, /insert
    - Correlations: /public_api/v1/correlations/get, /insert
    """

    def __init__(self, base_url: str, api_key: str, api_key_id: str, timeout_s: int = 60):
        self.base_url = base_url.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update(
            {
                "Authorization": api_key,
                "x-xdr-auth-id": api_key_id,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        self.timeout_s = timeout_s

    def post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = self.base_url + path
        r = self.s.post(url, json=payload, timeout=self.timeout_s)
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text}")
        return r.json()

    # IOCs
    def ioc_get(
        self,
        filters: Optional[List[dict]] = None,
        extended_view: bool = False,
        search_from: int = 0,
        search_to: int = 200,
    ) -> Dict[str, Any]:
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/indicators/get", {"request_data": req})

    def ioc_insert(self, iocs: List[dict]) -> Dict[str, Any]:
        return self.post("/public_api/v1/indicators/insert", {"request_data": iocs})

    # BIOCs
    def bioc_get(
        self,
        filters: Optional[List[dict]] = None,
        extended_view: bool = False,
        search_from: int = 0,
        search_to: int = 200,
    ) -> Dict[str, Any]:
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/bioc/get", {"request_data": req})

    def bioc_insert(self, biocs: List[dict]) -> Dict[str, Any]:
        return self.post("/public_api/v1/bioc/insert", {"request_data": biocs})

    # Correlations
    def corr_get(
        self,
        filters: Optional[List[dict]] = None,
        extended_view: bool = False,
        search_from: int = 0,
        search_to: int = 200,
    ) -> Dict[str, Any]:
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/correlations/get", {"request_data": req})

    def corr_insert(self, rules: List[dict]) -> Dict[str, Any]:
        return self.post("/public_api/v1/correlations/insert", {"request_data": rules})


# -----------------------------
# De-dupe helpers
# -----------------------------

def find_existing_id_by_name(client: XsiamClient, kind: str, name: str) -> int:
    filters = [{"field": "name", "operator": "EQ", "value": name}]
    if kind == "bioc":
        data = client.bioc_get(filters=filters, extended_view=False, search_from=0, search_to=1)
        objs = data.get("objects") or []
        return int(objs[0]["rule_id"]) if objs else 0
    if kind == "correlation":
        data = client.corr_get(filters=filters, extended_view=False, search_from=0, search_to=1)
        objs = data.get("objects") or []
        return int(objs[0]["id"]) if objs else 0  # correlations/get returns "id"
    raise ValueError(kind)


# -----------------------------
# Command: sync
# -----------------------------

def cmd_sync(args: argparse.Namespace) -> None:
    base_url = args.base_url
    api_key = os.environ["XSIAM_API_KEY"]
    api_key_id = os.environ["XSIAM_API_KEY_ID"]

    client = XsiamClient(base_url=base_url, api_key=api_key, api_key_id=api_key_id)

    repo = Path(args.repo).resolve()

    corr_dir = repo / "xsiam" / "correlation"
    bioc_dir = repo / "xsiam" / "bioc"
    ioc_dir = repo / "xsiam" / "ioc"

    corr_files = sorted(corr_dir.glob("*.json")) if corr_dir.exists() else []
    bioc_files = sorted(bioc_dir.glob("*.json")) if bioc_dir.exists() else []
    ioc_files = sorted(ioc_dir.glob("*.json")) if ioc_dir.exists() else []

    corr_objs = [load_json(p) for p in corr_files]
    bioc_objs = [load_json(p) for p in bioc_files]
    ioc_objs = [load_json(p) for p in ioc_files]

    # ---- Correlations ----
    # Tenants vary: many do NOT accept rule_id=0 for create.
    # We only include rule_id when updating an existing correlation.
    if corr_objs:
        upserts = []
        for obj in corr_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("Correlation JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "correlation", name)

            o = dict(obj)
            o = normalize_correlation_payload(o)

            if existing_id:
                o["rule_id"] = existing_id  # update existing
            else:
                # create new: omit rule_id entirely
                o.pop("rule_id", None)

            upserts.append(o)

        client.corr_insert(upserts)
        print(f"Synced correlations: {len(upserts)}")

    # ---- BIOCs ----
    # For BIOCs, rule_id=0 is commonly used for create, but some tenants may also accept omit.
    # We'll follow your prior behavior; if you hit a similar error, we can apply same omit-on-create logic.
    if bioc_objs:
        upserts = []
        for obj in bioc_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("BIOC JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "bioc", name)

            o = dict(obj)
            if existing_id:
                o["rule_id"] = existing_id
            else:
                # keep 0 for create (or omit if you prefer)
                o["rule_id"] = 0

            upserts.append(o)

        client.bioc_insert(upserts)
        print(f"Synced BIOCs: {len(upserts)}")

    # ---- IOCs (optional) ----
    # De-dupe by (indicator,type): query to find existing rule_id, then upsert with that rule_id.
    if ioc_objs:
        upserts = []
        for ioc in ioc_objs:
            indicator = ioc.get("indicator")
            ioc_type = ioc.get("type")
            if not indicator or not ioc_type:
                raise ValueError("IOC JSON must include 'indicator' and 'type'")

            filters = [
                {"field": "indicator", "operator": "EQ", "value": [indicator]},
                {"field": "type", "operator": "EQ", "value": [ioc_type]},
            ]
            data = client.ioc_get(filters=filters, extended_view=False, search_from=0, search_to=1)
            objs = data.get("objects") or []
            existing_rule_id = int(objs[0]["rule_id"]) if objs else 0

            o = dict(ioc)
            o["rule_id"] = existing_rule_id  # 0 means create for most tenants
            upserts.append(o)

        client.ioc_insert(upserts)
        print(f"Synced IOCs: {len(upserts)}")


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync", help="Sync JSON artifacts in repo into XSIAM")
    s.add_argument("--repo", default=".")
    s.add_argument("--base-url", required=True, help="Your XSIAM tenant base URL, e.g. https://api-<tenant>")
    s.set_defaults(func=cmd_sync)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
