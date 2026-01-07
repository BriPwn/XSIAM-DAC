#!/usr/bin/env python3
# scripts/sigma_to_xql.py

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import yaml

SEVERITY_MAP = {
    "informational": "SEV_010_INFO",
    "info": "SEV_010_INFO",
    "low": "SEV_020_LOW",
    "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH",
    "critical": "SEV_040_HIGH",
}

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")

SIGMA2XSIAM_DIR = Path(os.getenv("SIGMA2XSIAM_DIR", "vendor/Sigma2XSIAM"))
CONVERTER = SIGMA2XSIAM_DIR / "convert_rule.py"
PIPELINE_PATH = SIGMA2XSIAM_DIR / "pipelines" / "cortex_xdm.yml"


def sigma_level_to_xsiam(level: str | None) -> str:
    if not level:
        return "SEV_030_MEDIUM"
    return SEVERITY_MAP.get(level.strip().lower(), "SEV_030_MEDIUM")


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def ensure_vendor_present() -> None:
    if not SIGMA2XSIAM_DIR.exists():
        raise SystemExit(f"Sigma2XSIAM directory not found: {SIGMA2XSIAM_DIR.resolve()}")
    if not CONVERTER.exists():
        raise SystemExit(f"Missing converter: {CONVERTER.resolve()}")
    if not PIPELINE_PATH.exists():
        raise SystemExit(f"Missing pipeline file: {PIPELINE_PATH.resolve()}")


def load_yaml_documents(raw: str, src: Path) -> List[Dict[str, Any]]:
    docs = list(yaml.safe_load_all(raw))
    out: List[Dict[str, Any]] = []
    for i, d in enumerate(docs, start=1):
        if d is None:
            continue
        if not isinstance(d, dict):
            print(f"[WARN] Skipping non-dict YAML doc in {src} (doc #{i})")
            continue
        out.append(d)
    return out


def validate_sigma_minimum(rule_dict: Dict[str, Any], src: Path, doc_idx: int) -> None:
    logsource = rule_dict.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        raise SystemExit(
            "Sigma rule must have a logsource.\n"
            f"File: {src} (doc {doc_idx})\n\n"
            "Example:\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
        )


def derive_rule_name(rule_dict: Dict[str, Any], fallback: str) -> str:
    raw = rule_dict.get("title") or rule_dict.get("id") or fallback
    raw = str(raw).strip()
    return raw if raw else fallback


def apply_managed_scoping(name: str, description: str) -> tuple[str, str]:
    if not name.startswith(DAC_PREFIX):
        name = f"{DAC_PREFIX}{name}"
    description = (description or "").strip()
    if DAC_MARKER not in description:
        description = (description + "\n\n" + DAC_MARKER).strip()
    return name, description


def convert_one_sigma_to_xql(single_rule_path: Path) -> str:
    tmp_out = single_rule_path.with_suffix(".xql.out")
    cmd = ["python", "convert_rule.py", "-r", str(single_rule_path.resolve()), "-o", str(tmp_out.resolve())]
    proc = subprocess.run(cmd, cwd=str(SIGMA2XSIAM_DIR), capture_output=True, text=True)

    if proc.returncode != 0:
        raise SystemExit(
            f"Conversion failed for {single_rule_path}\n"
            f"STDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}\n"
        )

    if not tmp_out.exists():
        stdout = (proc.stdout or "").strip()
        if stdout:
            return stdout
        raise SystemExit(f"Converter did not create output file and stdout was empty: {tmp_out}")

    xql = tmp_out.read_text(encoding="utf-8").strip()
    if not xql:
        raise SystemExit(f"Converter produced empty XQL for: {single_rule_path}")
    return xql


def stable_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def dataset_for_query(xql: str) -> str:
    if "datamodel dataset = *" in xql:
        return "*"
    return "xdr_data"


# --- XQL FIXUPS ---
# Tenant expects string values for these XDM fields, but converter emits numbers.
# Convert: field = 123 -> field = "123"
_STRING_TYPED_INT_FIELDS = [
    r"xdm\.event\.id",
    r"xdm\.auth\.kerberos_tgs\.encryption_type",
]

_FIXUPS = [
    re.compile(rf"(\b{field}\s*=\s*)(\d+)(\b)") for field in _STRING_TYPED_INT_FIELDS
]


def fixup_xql_types(xql: str) -> str:
    if not xql:
        return xql

    out = xql
    for rx in _FIXUPS:
        out = rx.sub(r'\1"\2"\3', out)

    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-dir", default="rules/sigma")
    ap.add_argument("--out-xql-dir", default="generated/xql")
    ap.add_argument("--out-corr-dir", default="generated/correlations")
    ap.add_argument("--tmp-dir", default=".tmp_sigma2xsiam")
    args = ap.parse_args()

    ensure_vendor_present()

    sigma_dir = Path(args.sigma_dir)
    out_xql_dir = Path(args.out_xql_dir)
    out_corr_dir = Path(args.out_corr_dir)
    tmp_dir = Path(args.tmp_dir)

    out_xql_dir.mkdir(parents=True, exist_ok=True)
    out_corr_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    sigma_files = sorted(list(sigma_dir.rglob("*.yml")) + list(sigma_dir.rglob("*.yaml")))
    print(f"[GEN] sigma_dir={sigma_dir.resolve()} files={len(sigma_files)}")

    if not sigma_files:
        raise SystemExit(f"[GEN] No Sigma files found under: {sigma_dir.resolve()}")

    written_corr = 0
    written_xql = 0

    for rule_path in sigma_files:
        raw = rule_path.read_text(encoding="utf-8")
        docs = load_yaml_documents(raw, rule_path)
        if not docs:
            print(f"[WARN] Skipping empty/invalid Sigma YAML: {rule_path}")
            continue

        for doc_idx, rule_dict in enumerate(docs, start=1):
            validate_sigma_minimum(rule_dict, rule_path, doc_idx)

            fallback = f"{rule_path.stem}-{doc_idx}" if len(docs) > 1 else rule_path.stem
            base_name = derive_rule_name(rule_dict, fallback)

            desc_raw = str(rule_dict.get("description") or "")
            name, desc = apply_managed_scoping(base_name, desc_raw)

            uniq = stable_hash(f"{rule_path.as_posix()}::{doc_idx}::{name}")
            safe_name = sanitize_filename(name)
            safe = f"{safe_name}__{uniq}"

            tmp_rule = tmp_dir / f"{safe}.yml"
            tmp_rule.write_text(yaml.safe_dump(rule_dict, sort_keys=False), encoding="utf-8")

            xql_raw = convert_one_sigma_to_xql(tmp_rule)
            xql_query = fixup_xql_types(xql_raw)

            if xql_query != xql_raw:
                print(f"[GEN] XQL fixups applied for {rule_path.name} doc={doc_idx}")

            xql_path = out_xql_dir / f"{safe}.xql"
            xql_path.write_text(xql_query + "\n", encoding="utf-8")
            written_xql += 1

            corr_payload = {
                # Create: keep key present but NOT 0 (0 is treated as update in your tenant)
                "rule_id": None,

                "name": name,
                "description": desc,

                "xql_query": xql_query,
                "dataset": dataset_for_query(xql_query),

                "is_enabled": True,
                "execution_mode": "SCHEDULED",
                "search_window": "2 hours",
                "simple_schedule": "5 minutes",
                "timezone": "Etc/UTC",
                "crontab": "*/5 * * * *",

                "action": "ALERTS",

                "severity": sigma_level_to_xsiam(str(rule_dict.get("level") or "")),
                "user_defined_severity": None,

                "alert_name": name,
                "alert_description": desc,
                "alert_category": "OTHER",
                "user_defined_category": None,

                "alert_domain": "DOMAIN_SECURITY",
                "alert_type": "OTHER",

                "alert_fields": {},
                "mitre_defs": {},

                "suppression_enabled": True,
                "suppression_duration": "1 hours",
                "suppression_fields": ["event_type"],

                "mapping_strategy": "AUTO",
                "lookup_mapping": [],

                "investigation_query_link": xql_query,
                "drilldown_query_timeframe": "QUERY",
            }

            corr_path = out_corr_dir / f"{safe}.json"
            corr_path.write_text(json.dumps(corr_payload, indent=2) + "\n", encoding="utf-8")
            written_corr += 1

            print(f"[GEN] OK {rule_path} doc={doc_idx}/{len(docs)} -> {corr_path.name}")

    corr_files = sorted([p for p in out_corr_dir.glob("*.json") if p.name != ".gitkeep"])
    print(f"[GEN] wrote_xql={written_xql} wrote_corr={written_corr}")
    print(f"[GEN] disk_corr_files={len(corr_files)}")
    if len(corr_files) == 0:
        raise SystemExit("[GEN] ERROR: No correlation JSON files produced.")


if __name__ == "__main__":
    main()
