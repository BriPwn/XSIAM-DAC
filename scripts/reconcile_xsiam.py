#!/usr/bin/env python3
# scripts/sigma_to_xql.py
"""
Sigma -> XQL + XSIAM Correlation payload generator (robust, CI-safe)

What this does:
- Reads Sigma YAML from rules/sigma/**/*.yml|yaml
- Supports MULTI-DOC YAML files separated by '---'
- Writes each doc to a temp single-rule YAML, converts via Sigma2XSIAM's convert_rule.py
- Outputs:
  - generated/xql/<safe_name>.xql
  - generated/correlations/<safe_name>.json  (payload for /public_api/v1/correlations/insert)

Why this approach:
- Avoids Python packaging collisions around sigma.backends.* by invoking convert_rule.py via subprocess.
- Ensures converter finds its pipeline file by running with cwd=SIGMA2XSIAM_DIR.

Safety/ownership:
- Adds DAC_PREFIX to names
- Adds DAC_MARKER to description (for safe reconciliation deletes)

Env vars:
- DAC_PREFIX (default: "DAC: ")
- DAC_MARKER (default: "Managed by detections-as-code")
- SIGMA2XSIAM_DIR (default: "vendor/Sigma2XSIAM")
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List

import yaml

SEVERITY_MAP = {
    "informational": "SEV_010_INFO",
    "low": "SEV_020_LOW",
    "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH",
    "critical": "SEV_050_CRITICAL",
}

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")

SIGMA2XSIAM_DIR = Path(os.getenv("SIGMA2XSIAM_DIR", "vendor/Sigma2XSIAM"))
CONVERTER = SIGMA2XSIAM_DIR / "convert_rule.py"
PIPELINE_REL = Path("pipelines") / "cortex_xdm.yml"  # converter expects this relative to its CWD


def sigma_level_to_xsiam(level: str | None) -> str:
    if not level:
        return "SEV_030_MEDIUM"
    return SEVERITY_MAP.get(level.strip().lower(), "SEV_030_MEDIUM")


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def ensure_vendor_present() -> None:
    if not SIGMA2XSIAM_DIR.exists():
        raise SystemExit(f"Sigma2XSIAM directory not found: {SIGMA2XSIAM_DIR}")
    if not CONVERTER.exists():
        raise SystemExit(f"Missing Sigma2XSIAM converter at: {CONVERTER}")
    pipeline_path = SIGMA2XSIAM_DIR / PIPELINE_REL
    if not pipeline_path.exists():
        raise SystemExit(
            f"Pipeline file not found: {pipeline_path}. "
            f"The converter expects {PIPELINE_REL} relative to its working directory."
        )


def validate_sigma_minimum(rule_dict: Dict[str, Any], src: Path, doc_idx: int) -> None:
    """
    Sigma2XSIAM requires logsource to map the rule.
    Fail fast with a helpful error.
    """
    logsource = rule_dict.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        raise SystemExit(
            "Sigma rule must have a logsource.\n"
            f"File: {src} (doc {doc_idx})\n\n"
            "Add something like:\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
        )


def convert_one_sigma(single_rule_path: Path, out_path: Path) -> str:
    """
    Invoke Sigma2XSIAM converter for a single Sigma rule YAML file.

    We run with cwd=SIGMA2XSIAM_DIR so the converter finds pipelines/cortex_xdm.yml.
    We pass absolute paths to rule/output so it can read/write outside the cwd.
    """
    rule_abs = single_rule_path.resolve()
    out_abs = out_path.resolve()

    cmd = ["python", "convert_rule.py", "-r", str(rule_abs), "-o", str(out_abs)]
    proc = subprocess.run(
        cmd,
        cwd=str(SIGMA2XSIAM_DIR),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"Conversion failed for {single_rule_path}\n"
            f"STDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}\n"
        )

    if not out_abs.exists():
        raise SystemExit(f"Converter did not produce output file: {out_abs}")

    return out_abs.read_text(encoding="utf-8").strip()


def load_yaml_documents(raw: str, src: Path) -> List[Dict[str, Any]]:
    docs = list(yaml.safe_load_all(raw))
    out: List[Dict[str, Any]] = []
    for i, d in enumerate(docs, start=1):
        if d is None:
            continue
        if not isinstance(d, dict):
            print(f"Skipping non-dict YAML document in {src} (doc #{i})")
            continue
        out.append(d)
    return out


def derive_rule_name(rule_dict: Dict[str, Any], fallback: str) -> str:
    raw_name = rule_dict.get("title") or rule_dict.get("id") or fallback
    raw_name = str(raw_name).strip()
    return raw_name if raw_name else fallback


def apply_managed_scoping(name: str, description: str) -> tuple[str, str]:
    if not name.startswith(DAC_PREFIX):
        name = f"{DAC_PREFIX}{name}"

    description = (description or "").strip()
    if DAC_MARKER not in description:
        description = (description + "\n\n" + DAC_MARKER).strip()

    return name, description


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
    if not sigma_files:
        print(f"No Sigma files found in {sigma_dir}")
        return

    for rule_path in sigma_files:
        raw = rule_path.read_text(encoding="utf-8")
        docs = load_yaml_documents(raw, rule_path)

        if not docs:
            print(f"Skipping empty/invalid Sigma YAML: {rule_path}")
            continue

        for idx, rule_dict in enumerate(docs, start=1):
            validate_sigma_minimum(rule_dict, rule_path, idx)

            fallback = f"{rule_path.stem}-{idx}" if len(docs) > 1 else rule_path.stem
            base_name = derive_rule_name(rule_dict, fallback)

            desc = str(rule_dict.get("description") or "")
            name, desc = apply_managed_scoping(base_name, desc)

            safe = sanitize_filename(name)
            if len(docs) > 1:
                safe = f"{safe}__doc{idx}"

            # Write a single-doc Sigma YAML so the converter doesn't choke on multi-doc input
            tmp_rule = tmp_dir / f"{safe}.yml"
            tmp_rule.write_text(yaml.safe_dump(rule_dict, sort_keys=False), encoding="utf-8")

            tmp_out = tmp_dir / f"{safe}.xql"
            xql_query = convert_one_sigma(tmp_rule, tmp_out)

            (out_xql_dir / f"{safe}.xql").write_text(xql_query + "\n", encoding="utf-8")

            # Correlation payload for /public_api/v1/correlations/insert
            # These fields align with the API-required set your tenant returned.
            corr_payload = {
                # required identifier for upsert. 0 means "create" in insert endpoint.
                "rule_id": 0,
                # identity
                "name": name,
                "description": desc,
                # execution
                "execution_mode": "SCHEDULED",
                "search_window": "\"2 hours\"",
                "simple_schedule": "\"5 minutes\"",
                "timezone": "UTC",
                "crontab": "",
                # query / mapping
                "xql_query": xql_query,
                "dataset": "",
                "lookup_mapping": {},
                "mapping_strategy": "AUTO",
                # enablement & suppression
                "is_enabled": True,
                "suppression_enabled": True,
                "suppression_duration": "\"1 hours\"",
                "suppression_fields": ["\"event_type\""],
                # alert properties
                "severity": sigma_level_to_xsiam(str(rule_dict.get("level") or "")),
                "user_defined_severity": "MEDIUM",
                "alert_name": name,
                "alert_description": desc,
                "alert_category": "OTHER",
                "user_defined_category": "OTHER",
                "alert_domain": "OTHER",
                "alert_type": "OTHER",
                # required collections (can be empty)
                "alert_fields": [],
                "mitre_defs": [],
                # required but can be empty/default
                "investigation_query_link": "",
                "drilldown_query_timeframe": "\"24 hours\"",
                # required action field
                "action": "ALERT",
            }

            (out_corr_dir / f"{safe}.json").write_text(
                json.dumps(corr_payload, indent=2) + "\n",
                encoding="utf-8",
            )

            print(f"Converted: {rule_path} (doc {idx}/{len(docs)}) -> {safe}.xql + {safe}.json")


if __name__ == "__main__":
    main()
