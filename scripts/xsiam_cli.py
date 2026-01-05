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

Notes (based on your tenant behavior / errors):
- Correlation create: MUST omit rule_id (rule_id=0 is treated as update and fails)
- Correlation action: MUST be "ALERTS" if you set severity/alert_* fields
- lookup_mapping MUST be a list ([])
- drilldown_query_timeframe enum: "ALERT" or "QUERY"
- mitre_defs must be an object/map ({}), not a list
- XQL validator rejects invalid tokens like "notcontains" => must be "not contains(...)"
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
    Fix common generator tokens that XQL doesn't accept in your tenant:
    - notcontains(...) -> not contains(...)
    - notstartswith(...) -> not startswith(...)
    - notendswith(...) -> not endswith(...)
    """
    if not xql:
        return xql

    xql = re.sub(r"\bnotcontains\s*\(", "not contains(", xql)
    xql = re.sub(r"\bnotstartswith\s*\(", "not startswith(", xql)
    xql = re.sub(r"\bnotendswith\s*\(", "not endswith(", xql)

    # Normalize accidental "notin(" -> "not (field in (...))" cannot be done safely without parsing,
    # so we do not touch it here.

    return xql


# -----------------------------
# Correlation normalization (schema + tenant constraints)
# -----------------------------

def correlation_required_defaults(name: str) -> dict:
    """
    Default correlation rule payload that satisfies required fields & your tenant constraints.
    IMPORTANT: DO NOT set rule_id here. Create must omit rule_id; update includes it.
    """
    return {
        "name": name,
        "description": "",
        "xql_query": "",

        # Must be ALERTS to allow severity + alert_* fields
        "action": "ALERTS",

        # Alert fields (valid because action=ALERTS)
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
        "mapping_strategy": "AUTO",   # enum AUTO/CUSTOM
        "lookup_mapping": [],        # MUST be list
        "suppression_enabled": False,
        "suppression_duration": "0 minutes",
        "suppression_fields": [],

        # UX
        "investigation_query_link": "",
        "drilldown_query_timeframe": "ALERT",  # enum ALERT/QUERY

        # MITRE (must be map/object)
        "mitre_defs": {},

        # can be null
        "user_defined_category": None,
        "user_defined_severity": None,
    }


def normalize_correlation_payload(rule: dict) -> dict:
    """
    Ensure correlation payload matches schema and tenant constraints.
    """
    name = (rule.get("name") or "unnamed").strip() or "unnamed"
    base = correlation_required_defaults(name)
    merged = deep_merge(base, rule)

    # Never send 'id' from GET responses
    merged.pop("id", None)

    # Core strings
    merged["name"] = name
    merged["description"] = merged.get("description") or ""
    merged["xql_query"] = sanitize_xql(merged.get("xql_query") or "")

    # action must be ALERTS for your tenant when using severity/alert fields
    if merged.get("action") != "ALERTS":
        merged["action"] = "ALERTS"

    # severity enum
    if merged.get("severity") not in ("SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"):
        merged["severity"] = "SEV_020_LOW"

    # alert fields
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

    # investigation link: safest default is reuse xql_query
    if not merged.get("investigation_query_link"):
        merged["investigation_query_link"] = merged["xql_query"]

    # normalize user_defined_* "" -> None
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
