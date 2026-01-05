#!/usr/bin/env python3
"""
Initial export ("bootstrap") from Cortex XSIAM into this repo.

Exports:
- Correlation rules -> xsiam/correlation/
- BIOCs            -> xsiam/bioc/
- IOCs             -> xsiam/ioc/

Env vars required:
- XSIAM_API_KEY
- XSIAM_API_KEY_ID

Usage:
  python scripts/xsiam_initial_sync.py export --repo . --base-url "$XSIAM_BASE_URL"
  python scripts/xsiam_initial_sync.py export --repo . --base-url "$XSIAM_BASE_URL" --verbose

Tenant constraint learned from your error:
- correlations/get requires 0 < search_size <= 100
So we page at 100.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

import requests

PAGE_SIZE_MAX = 100  # Tenant hard limit from error


# -----------------------------
# Helpers
# -----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_filename(s: str, max_len: int = 140) -> str:
    s = s.strip()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", s)
    s = s.strip("._-")
    if not s:
        s = "unnamed"
    if len(s) > max_len:
        s = s[:max_len].rstrip("._-")
    return s


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def sha1_short(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]


# -----------------------------
# Client
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

        # XSIAM sometimes returns 599 for "application-level" errors
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code} {path}: {r.text}\nParsed JSON: {body}")

        if self.verbose:
            print(f"<== {path} HTTP {r.status_code}")
            print(json.dumps(body, indent=2)[:4000])

        return body if isinstance(body, dict) else {}

    # Correlations
    def corr_get(self, filters: Optional[List[dict]] = None, extended_view: bool = True, search_from: int = 0, search_to: int = 100):
        req: Dict[str, Any] = {
            "extended_view": extended_view,
            "search_from": search_from,
            "search_to": search_to,
        }
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/correlations/get", {"request_data": req})

    # BIOCs
    def bioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = True, search_from: int = 0, search_to: int = 100):
        req: Dict[str, Any] = {
            "extended_view": extended_view,
            "search_from": search_from,
            "search_to": search_to,
        }
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/bioc/get", {"request_data": req})

    # IOCs
    def ioc_get(self, filters: Optional[List[dict]] = None, extended_view: bool = True, search_from: int = 0, search_to: int = 100):
        req: Dict[str, Any] = {
            "extended_view": extended_view,
            "search_from": search_from,
            "search_to": search_to,
        }
        if filters:
            req["filters"] = filters
        return self.post("/public_api/v1/indicators/get", {"request_data": req})


# -----------------------------
# Pagination
# -----------------------------

def fetch_all(
    fetch_page_fn: Callable[..., Dict[str, Any]],
    page_size: int = PAGE_SIZE_MAX,
    hard_limit: int = 100000,
    verbose: bool = False,
) -> List[dict]:
    """
    Pages using search_from/search_to.
    Tenant requires 0 < (search_to - search_from) <= 100.
    """
    all_objs: List[dict] = []
    search_from = 0
    page_size = min(max(1, page_size), PAGE_SIZE_MAX)

    while True:
        search_to = search_from + page_size
        # Clamp to max size (defensive)
        if (search_to - search_from) > PAGE_SIZE_MAX:
            search_to = search_from + PAGE_SIZE_MAX

        data = fetch_page_fn(search_from=search_from, search_to=search_to)
        objs = data.get("objects") or []
        all_objs.extend(objs)

        if verbose:
            print(f"Fetched {len(objs)} objects (range {search_from}-{search_to}), total so far {len(all_objs)}")

        # Stop when last page is short
        if len(objs) < page_size:
            break

        search_from += page_size
        if search_from >= hard_limit:
            break

    return all_objs


# -----------------------------
# Exporters
# -----------------------------

def export_correlations(client: XsiamClient, out_dir: Path, verbose: bool) -> List[Path]:
    objs = fetch_all(
        lambda search_from, search_to: client.corr_get(search_from=search_from, search_to=search_to, extended_view=True),
        page_size=PAGE_SIZE_MAX,
        verbose=verbose,
    )
    written: List[Path] = []
    for o in objs:
        rid = o.get("id")
        name = o.get("name") or "unnamed"
        fname = f"{safe_filename(name)}__{rid}.json"
        p = out_dir / fname
        write_json(p, o)
        written.append(p)
    return written


def export_biocs(client: XsiamClient, out_dir: Path, verbose: bool) -> List[Path]:
    objs = fetch_all(
        lambda search_from, search_to: client.bioc_get(search_from=search_from, search_to=search_to, extended_view=True),
        page_size=PAGE_SIZE_MAX,
        verbose=verbose,
    )
    written: List[Path] = []
    for o in objs:
        rid = o.get("rule_id")
        name = o.get("name") or "unnamed"
        fname = f"{safe_filename(name)}__{rid}.json"
        p = out_dir / fname
        write_json(p, o)
        written.append(p)
    return written


def export_iocs(client: XsiamClient, out_dir: Path, verbose: bool) -> List[Path]:
    objs = fetch_all(
        lambda search_from, search_to: client.ioc_get(search_from=search_from, search_to=search_to, extended_view=True),
        page_size=PAGE_SIZE_MAX,
        verbose=verbose,
    )
    written: List[Path] = []
    for o in objs:
        rid = o.get("rule_id")
        ioc_type = o.get("type") or "unknown_type"
        indicator = o.get("indicator") or ""
        h = sha1_short(f"{ioc_type}:{indicator}")
        fname = f"{safe_filename(ioc_type)}__{h}__{rid}.json"
        p = out_dir / fname
        write_json(p, o)
        written.append(p)
    return written


# -----------------------------
# Command
# -----------------------------

def cmd_export(args: argparse.Namespace) -> None:
    base_url = args.base_url
    api_key = os.environ["XSIAM_API_KEY"]
    api_key_id = os.environ["XSIAM_API_KEY_ID"]

    repo = Path(args.repo).resolve()
    corr_dir = repo / "xsiam" / "correlation"
    bioc_dir = repo / "xsiam" / "bioc"
    ioc_dir = repo / "xsiam" / "ioc"

    client = XsiamClient(base_url=base_url, api_key=api_key, api_key_id=api_key_id, verbose=args.verbose)

    manifest: Dict[str, Any] = {
        "exported_at": now_iso(),
        "base_url": base_url,
        "counts": {},
        "paths": {},
        "page_size": PAGE_SIZE_MAX,
    }

    print("Exporting Correlation rules...")
    corr_written = export_correlations(client, corr_dir, verbose=args.verbose)
    manifest["counts"]["correlation"] = len(corr_written)
    manifest["paths"]["correlation"] = str(corr_dir)

    print("Exporting BIOCs...")
    bioc_written = export_biocs(client, bioc_dir, verbose=args.verbose)
    manifest["counts"]["bioc"] = len(bioc_written)
    manifest["paths"]["bioc"] = str(bioc_dir)

    print("Exporting IOCs...")
    ioc_written = export_iocs(client, ioc_dir, verbose=args.verbose)
    manifest["counts"]["ioc"] = len(ioc_written)
    manifest["paths"]["ioc"] = str(ioc_dir)

    write_json(repo / "xsiam" / ".export_manifest.json", manifest)

    print("\n=== Export complete ===")
    print(json.dumps(manifest["counts"], indent=2))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("export", help="Export all XSIAM rules into this repo")
    e.add_argument("--repo", default=".")
    e.add_argument("--base-url", required=True)
    e.add_argument("--verbose", action="store_true")
    e.set_defaults(func=cmd_export)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
