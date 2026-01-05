#!/usr/bin/env python3
"""
XSIAM Detection-as-Code CLI (GitHub-friendly)

Syncs repo JSON artifacts into Cortex XSIAM:
- Correlation rules:  xsiam/correlation/*.json
- BIOCs:              xsiam/bioc/*.json
- IOCs:               xsiam/ioc/*.json

Environment variables required:
- XSIAM_API_KEY
- XSIAM_API_KEY_ID

Usage:
  python scripts/xsiam_cli.py sync --repo . --base-url "$XSIAM_BASE_URL" --verbose
  python scripts/xsiam_cli.py sync --repo . --base-url "$XSIAM_BASE_URL" --dry-run --verbose

Tenant behaviors incorporated (from your errors/logs):
- correlations/get filter name value MUST be a string (NOT list)
- correlation create: omit rule_id (rule_id=0 treated as update)
- correlation action must be "ALERTS" if alert_* / severity are set
- lookup_mapping must be a list
- mitre_defs must be a map/object
- drilldown_query_timeframe: "ALERT" or "QUERY"
- XQL generator tokens like notcontains(...) must be rewritten to "not contains(...)"
- Bad escape patterns like "$\\" should be corrected to "$"
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


# -----------------------------
# File utilities
# -----------------------------

def load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


def find_json_files(dir_path: Path) -> List[Path]:
    if not dir_path.exists():
        return []
    return sorted([p for p in dir_path.glob("*.json") if p.is_file()])


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
# XQL sanitization helpers
# -----------------------------

def sanitize_xql(xql: str) -> str:
    """
    Make XQL safe for correlation rule validation by fixing common invalid tokens and escapes.
    - notcontains( -> not contains(
    - notstartswith( -> not startswith(
    - notendswith( -> not endswith(
    - fix accidental "$\\" sequence to "$" (common JSON escaping mistake)
    """
    if not xql:
        return xql

    # normalize common bad composite tokens (case-insensitive)
    xql = re.sub(r"\bnotcontains\s*\(", "not contains(", xql, flags=re.IGNORECASE)
    xql = re.sub(r"\bnotstartswith\s*\(", "not startswith(", xql, flags=re.IGNORECASE)
    xql = re.sub(r"\bnotendswith\s*\(", "not endswith(", xql, flags=re.IGNORECASE)

    # fix a very common escaping bug: "$\\" becomes "$\" in XQL -> should be "$"
    xql = xql.replace("$\\", "$")

    return xql


# -----------------------------
# Correlation normalization
# -----------------------------

def correlation_required_defaults(name: str) -> dict:
    """
    Default correlation rule payload satisfying required fields + tenant constraints.
    IMPORTANT: Create must omit rule_id; update includes rule_id.
    """
    return {
        "name": name,
        "description": "",
        "xql_query": "",

        # Tenant constraint: if alert/severity fields exist, action must be ALERTS
        "action": "ALERTS",

        "severity": "SEV_020_LOW",
        "alert_name": name,
        "alert_description": "",
        "alert_category": "OTHER",
        "alert_fields": {},

        "is_enabled": True,
        "execution_mode": "SCHEDULED",
        "search_window": "30 minutes",
        "simple_schedule": "5 minutes",
        "timezone": "UTC",
        "crontab": "*/5 * * * *",

        "dataset": "alerts",
        "mapping_strategy": "AUTO",
        "lookup_mapping": [],  # MUST be list
        "suppression_enabled": False,
        "suppression_duration": "0 minutes",
        "suppression_fields": [],

        "investigation_query_link": "",
        "drilldown_query_timeframe": "ALERT",  # enum ALERT/QUERY

        "mitre_defs": {},

        "user_defined_category": None,
        "user_defined_severity": None,
    }


def normalize_correlation_payload(rule: dict) -> dict:
    name = (rule.get("name") or "unnamed").strip() or "unnamed"
    base = correlation_required_defaults(name)
    merged = deep_merge(base, rule)

    # never send "id" from GET responses
    merged.pop("id", None)

    merged["name"] = name
    merged["description"] = merged.get("description") or ""
    merged["xql_query"] = sanitize_xql(merged.get("xql_query") or "")

    # enforce action=ALERTS for your tenant
    merged["action"] = "ALERTS"

    # severity enum enforcement
    if merged.get("severity") not in ("SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"):
        merged["severity"] = "SEV_020_LOW"

    # alert fields
    merged["alert_name"] = merged.get("alert_name") or name
    merged["alert_description"] = merged.get("alert_description") or merged["description"] or ""
    merged["alert_category"] = merged.get("alert_category") or "OTHER"
    if merged.get("alert_fields") is None:
        merged["alert_fields"] = {}

    # schedule
    em = merged.get("execution_mode") or "SCHEDULED"
    merged["execution_mode"] = em if em in ("SCHEDULED", "REAL_TIME") else "SCHEDULED"
    merged["search_window"] = merged.get("search_window") or "30 minutes"
    merged["simple_schedule"] = merged.get("simple_schedule") or "5 minutes"
    merged["timezone"] = merged.get("timezone") or "UTC"
    merged["crontab"] = merged.get("crontab") or "*/5 * * * *"

    # dataset (string)
    merged["dataset"] = merged.get("dataset") or "alerts"

    # mapping_strategy enum
    ms = merged.get("mapping_strategy") or "AUTO"
    merged["mapping_strategy"] = ms if ms in ("AUTO", "CUSTOM") else "AUTO"

    # lookup_mapping must be list
    merged["lookup_mapping"] = merged.get("lookup_mapping") if isinstance(merged.get("lookup_mapping"), list) else []

    # suppression fields
    merged["suppression_enabled"] = bool(merged.get("suppression_enabled", False))
    merged["suppression_duration"] = merged.get("suppression_duration") or "0 minutes"
    if merged.get("suppression_fields") is None:
        merged["suppression_fields"] = []

    # drilldown timeframe enum
    dtf = merged.get("drilldown_query_timeframe")
    merged["drilldown_query_timeframe"] = dtf if dtf in ("ALERT", "QUERY") else "ALERT"

    # mitre_defs must be dict/map
    merged["mitre_defs"] = merged.get("mitre_defs") if isinstance(merged.get("mitre_defs"), dict) else {}

    # investigation query link: default to xql_query
    if not merged.get("investigation_query_link"):
        merged["investigation_query_link"] = merged["xql_query"]

    # normalize user-defined fields: "" -> None
    if merged.get("user_defined_category") == "":
        merged["user_defined_category"] = None
    if merged.get("user_defined_severity") == "":
        merged["user_defined_severity"] = None

    merged["is_enabled"] = bool(merged.get("is_enabled", True))

    return merged


# -----------------------------
# XSIAM API client
# -----------------------------

class XsiamClient:
    def __init__(self, base_url: str, api_key: str, api_key_id: str, timeout_s: int = 60, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
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
        if self.verbose:
            print(f"\n==> POST {path}")
            print(json.dumps(payload, indent=2)[:4000])

        r = self.s.post(url, json=payload, timeout=self.timeout_s)

        try:
            body = r.json()
        except Exception:
            body = None

        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text}\nParsed JSON: {body}")

        if self.verbose:
            print(f"<== {path} HTTP {r.status_code}")
            print(json.dumps(body, indent=2)[:4000])

        return body if isinstance(body, dict) else {}

    # IOCs
    def ioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/indicators/get", {"request_data": req})

    def ioc_insert(self, iocs: List[dict]) -> Dict[str, Any]:
        return self.post("/public_api/v1/indicators/insert", {"request_data": iocs})

    # BIOCs
    def bioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/bioc/get", {"request_data": req})

    def bioc_insert(self, biocs: List[dict]) -> Dict[str, Any]:
        return self.post("/public_api/v1/bioc/insert", {"request_data": biocs})

    # Correlations
    def corr_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req: Dict[str, Any] = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/correlations/get", {"request_data": req})

    def corr_insert(self, rules: List[dict]) -> Dict[str, Any]:
        return self.post("/public_api/v1/correlations/insert", {"request_data": rules})


# -----------------------------
# Result summarizer
# -----------------------------

def summarize_result(kind: str, res: Dict[str, Any]) -> None:
    added = res.get("added_objects", [])
    updated = res.get("updated_objects", [])
    errors = res.get("errors", [])

    print(f"\n=== {kind} result ===")
    print(f"Added: {len(added)} | Updated: {len(updated)} | Errors: {len(errors)}")

    if errors:
        for e in errors[:10]:
            print(f"- {e}")
        raise RuntimeError(f"{kind} sync returned errors (see above).")


# -----------------------------
# De-dupe helpers (string-only name filter)
# -----------------------------

def find_existing_id_by_name(client: XsiamClient, kind: str, name: str) -> int:
    # Your tenant requires name filter value to be a STRING (not list)
    filters = [{"field": "name", "operator": "EQ", "value": name}]

    if kind == "correlation":
        data = client.corr_get(filters=filters, extended_view=False, search_from=0, search_to=1)
        objs = data.get("objects") or []
        return int(objs[0]["id"]) if objs else 0

    if kind == "bioc":
        data = client.bioc_get(filters=filters, extended_view=False, search_from=0, search_to=1)
        objs = data.get("objects") or []
        return int(objs[0]["rule_id"]) if objs else 0

    raise ValueError(kind)


# -----------------------------
# Command: sync
# -----------------------------

def cmd_sync(args: argparse.Namespace) -> None:
    base_url = args.base_url
    api_key = os.environ["XSIAM_API_KEY"]
    api_key_id = os.environ["XSIAM_API_KEY_ID"]

    client = XsiamClient(base_url=base_url, api_key=api_key, api_key_id=api_key_id, verbose=args.verbose)
    repo = Path(args.repo).resolve()

    corr_dir = repo / "xsiam" / "correlation"
    bioc_dir = repo / "xsiam" / "bioc"
    ioc_dir = repo / "xsiam" / "ioc"

    corr_files = find_json_files(corr_dir)
    bioc_files = find_json_files(bioc_dir)
    ioc_files = find_json_files(ioc_dir)

    print("\n=== Artifact discovery ===")
    print(f"Correlation JSON: {len(corr_files)} in {corr_dir}")
    print(f"BIOC JSON:        {len(bioc_files)} in {bioc_dir}")
    print(f"IOC JSON:         {len(ioc_files)} in {ioc_dir}")

    if args.verbose:
        if corr_files:
            print("Correlation files:", [p.name for p in corr_files])
        if bioc_files:
            print("BIOC files:", [p.name for p in bioc_files])
        if ioc_files:
            print("IOC files:", [p.name for p in ioc_files])

    if not (corr_files or bioc_files or ioc_files):
        raise RuntimeError("No artifacts found to sync. Check repo folder paths and committed JSON files.")

    corr_objs = [load_json(p) for p in corr_files]
    bioc_objs = [load_json(p) for p in bioc_files]
    ioc_objs = [load_json(p) for p in ioc_files]

    # ---- Correlations ----
    if corr_objs:
        upserts: List[dict] = []
        for obj in corr_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("Correlation JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "correlation", name)
            o = normalize_correlation_payload(dict(obj))

            # Create must omit rule_id; update includes it
            if existing_id:
                o["rule_id"] = existing_id
            else:
                o.pop("rule_id", None)

            upserts.append(o)

        if args.dry_run:
            print("\n[DRY RUN] Would sync correlations:", len(upserts))
        else:
            res = client.corr_insert(upserts)
            summarize_result("Correlation rules", res)

    # ---- BIOCs ----
    if bioc_objs:
        upserts = []
        for obj in bioc_objs:
            name = obj.get("name")
            if not name:
                raise ValueError("BIOC JSON missing required 'name' field")

            existing_id = find_existing_id_by_name(client, "bioc", name)
            o = dict(obj)

            # safest: omit rule_id on create
            if existing_id:
                o["rule_id"] = existing_id
            else:
                o.pop("rule_id", None)

            upserts.append(o)

        if args.dry_run:
            print("\n[DRY RUN] Would sync BIOCs:", len(upserts))
        else:
            res = client.bioc_insert(upserts)
            summarize_result("BIOCs", res)

    # ---- IOCs ----
    if ioc_objs:
        upserts = []
        for ioc in ioc_objs:
            indicator = ioc.get("indicator")
            ioc_type = ioc.get("type")
            if not indicator or not ioc_type:
                raise ValueError("IOC JSON must include 'indicator' and 'type'")

            # indicators/get typically expects list values
            filters = [
                {"field": "indicator", "operator": "EQ", "value": [indicator]},
                {"field": "type", "operator": "EQ", "value": [ioc_type]},
            ]
            data = client.ioc_get(filters=filters, extended_view=False, search_from=0, search_to=1)
            objs = data.get("objects") or []
            existing_rule_id = int(objs[0]["rule_id"]) if objs else 0

            o = dict(ioc)
            if existing_rule_id:
                o["rule_id"] = existing_rule_id
            else:
                o.pop("rule_id", None)

            upserts.append(o)

        if args.dry_run:
            print("\n[DRY RUN] Would sync IOCs:", len(upserts))
        else:
            res = client.ioc_insert(upserts)
            summarize_result("IOCs", res)


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync", help="Sync JSON artifacts in repo into XSIAM")
    s.add_argument("--repo", default=".")
    s.add_argument("--base-url", required=True)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--verbose", action="store_true")
    s.set_defaults(func=cmd_sync)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

