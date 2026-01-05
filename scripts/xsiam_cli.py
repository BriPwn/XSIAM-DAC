#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
import yaml


def slugify(s: str) -> str:
    return "".join(c.lower() if c.isalnum() else "-" for c in s).strip("-")


def load_yaml(p: Path) -> Dict[str, Any]:
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def load_json(p: Path) -> Dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8"))


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
        r = self.s.post(self.base_url + path, json=payload, timeout=self.timeout_s)
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text}")
        return r.json()

    # IOCs
    def ioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/indicators/get", {"request_data": req})

    def ioc_insert(self, iocs: List[dict]):
        return self.post("/public_api/v1/indicators/insert", {"request_data": iocs})

    # BIOCs
    def bioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/bioc/get", {"request_data": req})

    def bioc_insert(self, biocs: List[dict]):
        return self.post("/public_api/v1/bioc/insert", {"request_data": biocs})

    # Correlations
    def corr_get(self, filters: Optional[List[dict]] = None, extended_view: bool = False, search_from: int = 0, search_to: int = 200):
        req = {"extended_view": extended_view, "search_from": search_from, "search_to": search_to}
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/correlations/get", {"request_data": req})

    def corr_insert(self, rules: List[dict]):
        return self.post("/public_api/v1/correlations/insert", {"request_data": rules})


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


def cmd_sync(args: argparse.Namespace) -> None:
    base_url = args.base_url
    api_key = os.environ["XSIAM_API_KEY"]
    api_key_id = os.environ["XSIAM_API_KEY_ID"]

    client = XsiamClient(base_url=base_url, api_key=api_key, api_key_id=api_key_id)

    repo = Path(args.repo).resolve()

    # Load desired-state JSON
    corr_files = sorted((repo / "xsiam/correlation").glob("*.json"))
    bioc_files = sorted((repo / "xsiam/bioc").glob("*.json"))
    ioc_files = sorted((repo / "xsiam/ioc").glob("*.json")) if (repo / "xsiam/ioc").exists() else []

    corr_objs = [load_json(p) for p in corr_files]
    bioc_objs = [load_json(p) for p in bioc_files]
    ioc_objs = [load_json(p) for p in ioc_files]

    # Upsert Correlations (de-dupe by name)
    if corr_objs:
        upserts = []
        for obj in corr_objs:
            name = obj["name"]
            existing_id = find_existing_id_by_name(client, "correlation", name)
            o = dict(obj)
            # correlation "get" returns "id"
            o["rule_id"] = existing_id or 0
            upserts.append(o)
        client.corr_insert(upserts)
        print(f"Synced correlations: {len(upserts)}")

    # Upsert BIOCs (de-dupe by name)
    if bioc_objs:
        upserts = []
        for obj in bioc_objs:
            name = obj["name"]
            existing_id = find_existing_id_by_name(client, "bioc", name)
            o = dict(obj)
            o["rule_id"] = existing_id or 0
            upserts.append(o)
        client.bioc_insert(upserts)
        print(f"Synced BIOCs: {len(upserts)}")

    # Upsert IOCs (optional folder)
    if ioc_objs:
        # de-dupe by (indicator,type) using ioc_get then set rule_id
        upserts = []
        for ioc in ioc_objs:
            indicator = ioc["indicator"]
            ioc_type = ioc["type"]
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

    s = sub.add_parser("sync")
    s.add_argument("--repo", default=".")
    s.add_argument("--base-url", required=True)
    s.set_defaults(func=cmd_sync)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
