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
# Dict merge helpers
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


# -----------------------------
# Correlation normalization (schema-complete + correct types)
# -----------------------------
#
# XSIAM correlations/insert has strict schema requirements. In particular:
# - drilldown_query_timeframe is enum: "QUERY" or "ALERT"
# - mapping_strategy is enum: "AUTO" or "CUSTOM"
# - mitre_defs is an OBJECT (map), not a list
# - user_defined_* can be null
# See official API reference. :contentReference[oaicite:4]{index=4}

def correlation_required_defaults(name: str) -> dict:
    """
    Default correlation rule payload that satisfies required fields & types.
    """
    # NOTE: docs show rule_id in body parameters and client snippets use rule_id=0 on insert. :contentReference[oaicite:5]{index=5}
    return {
        "rule_id": 0,  # create semantics typically use 0; we also implement a fallback retry
        "name": name,
        "severity": "SEV_020_LOW",
        "xql_query": "",
        "is_enabled": True,
        "description": "",

        "alert_name": name,
        "alert_category": "OTHER",       # enum; see docs for allowed values :contentReference[oaicite:6]{index=6}
        "alert_description": "",
        "alert_fields": {},

        "execution_mode": "SCHEDULED",   # enum: SCHEDULED / REAL_TIME :contentReference[oaicite:7]{index=7}
        "search_window": "30 minutes",
        "simple_schedule": "5 minutes",
        "timezone": "UTC",
        "crontab": "*/5 * * * *",        # required string; safe default
        "suppression_enabled": False,
        "suppression_duration": "0 minutes",
        "suppression_fields": [],

        "dataset": "alerts",
        "user_defined_severity": None,   # null is acceptable per example :contentReference[oaicite:8]{index=8}
        "user_defined_category": None,   # null is acceptable per example :contentReference[oaicite:9]{index=9}

        "mitre_defs": {},                # must be object/map :contentReference[oaicite:10]{index=10}
        "investigation_query_link": "",  # should be valid XQL or empty; we set to xql_query if missing
        "drilldown_query_timeframe": "ALERT",  # enum: QUERY / ALERT :contentReference[oaicite:11]{index=11}
        "mapping_strategy": "AUTO",      # enum: AUTO / CUSTOM :contentReference[oaicite:12]{index=12}

        # These are in the earlier “required fields” error list you saw.
        # Some tenants accept them absent; yours required them then.
        "lookup_mapping": {},            # keep as object
        "action": {},                    # keep as object
    }


def normalize_correlation_payload(rule: dict) -> dict:
    """
    Ensure payload is schema-correct:
    - required keys exist
    - types match expected schema
    - enums are valid defaults
    """
    name = (rule.get("name") or "unnamed").strip() or "unnamed"
    base = correlation_required_defaults(name)
    merged = deep_merge(base, rule)

    # Drop accidental 'id' field if present (get endpoint returns id; insert uses rule_id). :contentReference[oaicite:13]{index=13}
    merged.pop("id", None)

    # Strings
    merged["name"] = name
    merged["description"] = merged.get("description") or ""
    merged["xql_query"] = merged.get("xql_query") or ""

    merged["alert_name"] = merged.get("alert_name") or name
    merged["alert_description"] = merged.get("alert_description") or merged["description"] or ""

    merged["search_window"] = merged.get("search_window") or "30 minutes"
    merged["simple_schedule"] = merged.get("simple_schedule") or "5 minutes"
    merged["timezone"] = merged.get("timezone") or "UTC"
    merged["crontab"] = merged.get("crontab") or "*/5 * * * *"
    merged["dataset"] = merged.get("dataset") or "alerts"
    merged["suppression_duration"] = merged.get("suppression_duration") or "0 minutes"

    # Required objects
    if merged.get("alert_fields") is None:
        merged["alert_fields"] = {}
    if merged.get("lookup_mapping") is None:
        merged["lookup_mapping"] = {}
    if merged.get("action") is None:
        merged["action"] = {}

    # Required arrays
    if merged.get("suppression_fields") is None:
        merged["suppression_fields"] = []

    # mitre_defs MUST be an object/map, not a list
    if merged.get("mitre_defs") is None or isinstance(merged.get("mitre_defs"), list):
        merged["mitre_defs"] = {}

    # drilldown_query_timeframe MUST be enum QUERY/ALERT
    dtf = merged.get("drilldown_query_timeframe")
    if dtf not in ("QUERY", "ALERT"):
        merged["drilldown_query_timeframe"] = "ALERT"

    # mapping_strategy MUST be enum AUTO/CUSTOM
    ms = merged.get("mapping_strategy")
    if ms not in ("AUTO", "CUSTOM"):
        merged["mapping_strategy"] = "AUTO"

    # execution_mode MUST be enum SCHEDULED/REAL_TIME
    em = merged.get("execution_mode")
    if em not in ("SCHEDULED", "REAL_TIME"):
        merged["execution_mode"] = "SCHEDULED"

    # severity MUST be enum
    sev = merged.get("severity")
    if sev not in ("SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"):
        merged["severity"] = "SEV_020_LOW"

    # alert_category MUST be one of allowed enums; keep OTHER as safe default.
    if not merged.get("alert_category"):
        merged["alert_category"] = "OTHER"

    # booleans
    merged["is_enabled"] = bool(merged.get("is_enabled", True))
    merged["suppression_enabled"] = bool(merged.get("suppression_enabled", False))

    # investigation_query_link: best default is same as xql_query
    if not merged.get("investigation_query_link"):
        merged["investigation_query_link"] = merged["xql_query"]

    # user_defined_* should be null (None) or valid string; normalize "" -> None
    if merged.get("user_defined_category") == "":
        merged["user_defined_category"] = None
    if merged.get("user_defined_severity") == "":
        merged["user_defined_severity"] = None

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
            # Try to include JSON body (sometimes contains more detail than text)
            try:
                errj = r.json()
            except Exception:
                errj = None
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text}\nParsed JSON: {errj}")

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
        return int(objs[0]["id"]) if objs else 0  # correlations/get returns "id" :contentReference[oaicite:14]{index=14}
    raise ValueError(kind)


def corr_insert_with_create_fallback(client: XsiamClient, payloads: List[dict]) -> Dict[str, Any]:
    """
    Some tenants behave oddly regarding create semantics:
    - docs show rule_id=0 is used in client snippets :contentReference[oaicite:15]{index=15}
    - but some environments return "cannot update rule 0"
    So we try:
      1) send as-is
      2) if error contains "does not exist and therefore cannot be updated", retry by omitting rule_id for those creates
    """
    try:
        return client.corr_insert(payloads)
    except RuntimeError as e:
        msg = str(e)
        if "does not exist and therefore cannot be updated" not in msg:
            raise

        # Retry: remove rule_id for rules that have rule_id==0 (creates)
        retry_payloads = []
        for p in payloads:
            pp = dict(p)
            if pp.get("rule_id", 0) == 0:
                pp.pop("rule_id", None)
            retry_payloads.append(pp)
        return client.corr_insert(retry_payloads)


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
    if corr_objs:
        upserts = []
        for obj in corr_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("Correlation JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "correlation", name)

            o = normalize_correlation_payload(dict(obj))

            # Update existing rules by rule_id; create uses rule_id=0 (per docs snippets) :contentReference[oaicite:16]{index=16}
            o["rule_id"] = existing_id if existing_id else 0

            upserts.append(o)

        corr_insert_with_create_fallback(client, upserts)
        print(f"Synced correlations: {len(upserts)}")

    # ---- BIOCs ----
    # If BIOCs later throw "cannot update 0" we can apply same omit/retry logic.
    if bioc_objs:
        upserts = []
        for obj in bioc_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("BIOC JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "bioc", name)
            o = dict(obj)
            o["rule_id"] = existing_id if existing_id else 0
            upserts.append(o)

        client.bioc_insert(upserts)
        print(f"Synced BIOCs: {len(upserts)}")

    # ---- IOCs (optional) ----
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
            o["rule_id"] = existing_rule_id
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
