#!/usr/bin/env python3
"""
Sigma -> XQL + XSIAM Correlation payload generator (robust, CI-safe)

This version:
- Supports Sigma YAML files containing MULTIPLE documents separated by '---'
- Converts each document independently by writing it to a temp single-rule YAML
- Uses Sigma2XSIAM's converter script via subprocess to avoid Python package collisions
- Runs converter with cwd=SIGMA2XSIAM_DIR so it can find pipelines/cortex_xdm.yml
- Outputs:
  - generated/xql/<safe_name>.xql
  - generated/correlations/<safe_name>.json
- Applies managed scoping:
  - Name prefix (DAC_PREFIX)
  - Marker in description (DAC_MARKER)

Environment variables:
- DAC_PREFIX: default "DAC: "
- DAC_MARKER: default "Managed by detections-as-code"
- SIGMA2XSIAM_DIR: default "vendor/Sigma2XSIAM" (where workflow clones Sigma2XSIAM)
"""

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
PIPELINE_REL = Path("pipelines") / "cortex_xdm.yml"


def sigma_level_to_xsiam(level: str | None) -> str:
    if not level:
        return "SEV_030_MEDIUM"
    return SEVERITY_MAP.get(level.strip().lower(), "SEV_030_MEDIUM")


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def ensure_vendor_present() -> None:
    if not SIGMA2XSIAM_DIR.exists():
        raise SystemExit(
            f"Sigma2XSIAM directory not found: {SIGMA2XSIAM_DIR}. "
            f"Workflow must clone Sigma2XSIAM into this path."
        )
    if not CONVERTER.exists():
        raise SystemExit(
            f"Missing Sigma2XSIAM converter at {CONVERTER}. "
            f"Workflow must clone Sigma2XSIAM into {SIGMA2XSIAM_DIR}."
        )
    pipeline_path = SIGMA2XSIAM_DIR / PIPELINE_REL
    if not pipeline_path.exists():
        raise SystemExit(
            f"Missing pipeline file at {pipeline_path}. "
            f"Sigma2XSIAM converter expects {PIPELINE_REL} relative to its working directory."
        )


def convert_one_sigma(single_rule_path: Path, out_path: Path) -> str:
    """
    Invoke Sigma2XSIAM converter for a single Sigma rule YAML file.

    The converter expects pipelines/cortex_xdm.yml relative to its CWD,
    so we run it with cwd=SIGMA2XSIAM_DIR and pass absolute file paths.
    """
    rule_abs = single_rule_path.resolve()
    out_abs = out_path.resolve()

    cmd = [
        "python",
        "convert_rule.py",
        "-r",
        str(rule_abs),
        "-o",
        str(out_abs),
    ]
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
    """
    Loads one or more YAML docs from a Sigma file.
    Returns only dict documents.
    """
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
    """
    Prefer Sigma 'title', fallback to 'id', then fallback string.
    """
    raw_name = rule_dict.get("title") or rule_dict.get("id") or fallback
    raw_name = str(raw_name).strip()
    if not raw_name:
        raw_name = fallback
    return raw_name


def apply_managed_scoping(name: str, description: str) -> tuple[str, str]:
    """
    Apply prefix + marker to ensure safe reconciliation scoping.
    """
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
            # Stable fallback name: include filename stem + doc idx for multi-doc files
            fallback = f"{rule_path.stem}-{idx}" if len(docs) > 1 else rule_path.stem
            base_name = derive_rule_name(rule_dict, fallback)

            desc = str(rule_dict.get("description") or "")
            name, desc = apply_managed_scoping(base_name, desc)

            safe = sanitize_filename(name)
            if len(docs) > 1:
                safe = f"{safe}__doc{idx}"

            # Write single-doc Sigma YAML to temp so converter sees one rule
            tmp_rule = tmp_dir / f"{safe}.yml"
            tmp_rule.write_text(yaml.safe_dump(rule_dict, sort_keys=False), encoding="utf-8")

            tmp_out = tmp_dir / f"{safe}.xql"
            xql_query = convert_one_sigma(tmp_rule, tmp_out)

            # Write generated XQL
            (out_xql_dir / f"{safe}.xql").write_text(xql_query + "\n", encoding="utf-8")

            # Build correlation payload JSON (for XSIAM /correlations/insert)
            corr_payload = {
                "rule_id": 0,
                "name": name,
                "severity": sigma_level_to_xsiam(str(rule_dict.get("level") or "")),
                "xql_query": xql_query,
                "is_enabled": True,
                "description": desc,
                "alert_name": name,
                "alert_category": "other",
                "execution_mode": "scheduled",
                "search_window": "2 hours",
                "simple_schedule": "5 minutes",
                "suppression_enabled": True,
                "suppression_duration": "1 hours",
                "suppression_fields": ["event_type"],
                "mapping_strategy": "auto",
            }

            (out_corr_dir / f"{safe}.json").write_text(
                json.dumps(corr_payload, indent=2) + "\n",
                encoding="utf-8",
            )

            print(f"Converted: {rule_path} (doc {idx}/{len(docs)}) -> {safe}.xql + {safe}.json")


if __name__ == "__main__":
    main()

