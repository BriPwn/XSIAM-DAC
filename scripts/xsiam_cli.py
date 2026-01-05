#!/usr/bin/env python3
"""
XSIAM Detection-as-Code CLI (GitHub-friendly)

Commands:
- sync: Update Correlation Rules, BIOCs, and (optionally) IOCs from repo JSON into Cortex XSIAM.

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
# Correlation normalization (schema + tenant constraints)
# -----------------------------
#
# Your tenant constraints from error:
# - If action != ALERTS, then severity + alert_* fields must be empty
# - lookup_mapping must be a LIST
# - rule_id=0 is treated as update and fails; create must OMIT rule_id
#
# We'll enforce:
# - action = "ALERTS"
# - lookup_mapping = []
# - drilldown_query_timeframe = "ALERT" or "QUERY" (enum)
# - mitre_defs = {} (map)
# - create: omit rule_id
# - update: include rule_id

def correlation_required_defaults(name: str) -> dict:
    return {
        # DO NOT set rule_id here (handled per create/update)
        "name": name,
        "description": "",
        "xql_query": "",

        # Must be ALERTS to allow severity + alert_* fields per tenant error
        "action": "ALERTS",

        # Alert fields become valid because action=ALERTS
        "severity": "SEV_020_LOW",
        "alert_name": name,
        "alert_description": "",
        "alert_category": "OTHER",
        "alert_fields": {},

        # Execution/schedule
        "is_enabled": True,
        "execution_mode": "SCHEDULED",
        "search_window": "30 minutes",
        "simple_schedule": "5 minutes",
        "timezone": "UTC",
        "crontab": "*/5 * * * *",

        # Required fields
        "dataset": "alerts",
        "mapping_strategy": "AUTO",          # enum AUTO/CUSTOM
        "lookup_mapping": [],               # MUST be list per tenant error
        "suppression_enabled": False,
        "suppression_duration": "0 minutes",
        "suppression_fields": [],

        # UX
        "investigation_query_link": "",
        "drilldown_query_timeframe": "ALERT",  # enum: ALERT / QUERY

        # MITRE must be map/object
        "mitre_defs": {},

        # often required but can be null
        "user_defined_category": None,
        "user_defined_severity": None,
    }


def normalize_correlation_payload(rule: dict) -> dict:
    name = (rule.get("name") or "unnamed").strip() or "unnamed"
    base = correlation_required_defaults(name)
    merged = deep_merge(base, rule)

    # Never send "id" from GET responses
    merged.pop("id", None)

    # Core strings
    merged["name"] = name
    merged["description"] = merged.get("description") or ""
    merged["xql_query"] = merged.get("xql_query") or ""

    # action must be ALERTS for your tenant
    if merged.get("action") != "ALERTS":
        merged["action"] = "ALERTS"

    # severity enum
    if merged.get("severity") not in ("SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"):
        merged["severity"] = "SEV_020_LOW"

    # alert fields (valid because action=ALERTS)
    merged["alert_name"] = merged.get("alert_name") or name
    merged["alert_description"] = merged.get("alert_description") or merged["description"] or ""
    merged["alert_category"] = merged.get("alert_category") or "OTHER"
    if merged.get("alert_fields") is None:
        merged["alert_fields"] = {}

    # schedule
    merged["execution_mode"] = merged.get("execution_mode") or "SCHEDULED"
    if merged["execution_mode"] not in ("SCHEDULED", "REAL_TIME"):
        merged["execution_mode"] = "SCHEDULED"

    merged["search_window"] = merged.get("search_window") or "30 minutes"
    merged["simple_schedule"] = merged.get("simple_schedule") or "5 minutes"
    merged["timezone"] = merged.get("timezone") or "UTC"
    merged["crontab"] = merged.get("crontab") or "*/5 * * * *"

    # required misc
    merged["dataset"] = merged.get("dataset") or "alerts"
    merged["mapping_strategy"] = merged.get("mapping_strategy") or "AUTO"
    if merged["mapping_strategy"] not in ("AUTO", "CUSTOM"):
        merged["mapping_strategy"] = "AUTO"

    # lookup_mapping must be LIST
    lm = merged.get("lookup_mapping")
    if lm is None:
        merged["lookup_mapping"] = []
    elif isinstance(lm, dict):
        # convert dict -> list if someone provided legacy shape
        merged["lookup_mapping"] = []
    elif not isinstance(lm, list):
        merged["lookup_mapping"] = []

    # suppression
    merged["suppression_enabled"] = bool(merged.get("suppression_enabled", False))
    merged["suppression_duration"] = merged.get("suppression_duration") or "0 minutes"
    if merged.get("suppression_fields") is None:
        merged["suppression_fields"] = []

    # drilldown enum
    dtf = merged.get("drilldown_query_timeframe")
    if dtf not in ("ALERT", "QUERY"):
        merged["drilldown_query_timeframe"] = "ALERT"

    # MITRE map
    if merged.get("mitre_defs") is None or isinstance(merged.get("mitre_defs"), list):
        merged["mitre_defs"] = {}

    # investigation link: safest is reuse xql_query
    if not merged.get("investigation_query_link"):
        merged["investigation_query_link"] = merged["xql_query"]

    # user_defined_* normalize "" -> None
    if merged.get("user_defined_category") == "":
        merged["user_defined_category"] = None
    if merged.get("user_defined_severity") == "":
        merged["user_defined_severity"] = None

    # booleans
    merged["is_enabled"] = bool(merged.get("is_enabled", True))

    return merged


# -----------------------------
# XSIAM API client
# -----------------------------

class XsiamClient:
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
            try:
                errj = r.json()
            except Exception:
                errj = None
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text}\nParsed JSON: {errj}")
        return r.json()

    # IOCs
    def ioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/indicators/get", {"request_data": req})

    def ioc_insert(self, iocs: List[dict]):
        return self.post("/public_api/v1/indicators/insert", {"request_data": iocs})

    # BIOCs
    def bioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/bioc/get", {"request_data": req})

    def bioc_insert(self, biocs: List[dict]):
        return self.post("/public_api/v1/bioc/insert", {"request_data": biocs})

    # Correlations
    def corr_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/correlations/get", {"request_data": req})

    def corr_insert(self, rules: List[dict]):
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
        return int(objs[0]["id"]) if objs else 0
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
    # Your tenant does NOT allow update on rule_id=0. Create must omit rule_id.
    if corr_objs:
        upserts: List[dict] = []
        for obj in corr_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("Correlation JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "correlation", name)

            o = normalize_correlation_payload(dict(obj))

            if existing_id:
                o["rule_id"] = existing_id     # update
            else:
                o.pop("rule_id", None)         # create: OMIT rule_id entirely

            upserts.append(o)

        client.corr_insert(upserts)
        print(f"Synced correlations: {len(upserts)}")

    # ---- BIOCs ----
    # Keep rule_id=0 for create unless you see the same update-0 error for BIOCs.
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
