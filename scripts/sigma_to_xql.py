#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
from pathlib import Path

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

# Where the workflow clones Sigma2XSIAM
SIGMA2XSIAM_DIR = Path(os.getenv("SIGMA2XSIAM_DIR", "vendor/sigma2xsiam"))
CONVERTER = SIGMA2XSIAM_DIR / "convert_rule.py"
PIPELINE_YML = SIGMA2XSIAM_DIR / "pipelines" / "cortex_xdm.yml"  # referenced by the project README 


def sigma_level_to_xsiam(level: str | None) -> str:
    if not level:
        return "SEV_030_MEDIUM"
    return SEVERITY_MAP.get(level.strip().lower(), "SEV_030_MEDIUM")


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def ensure_vendor_present() -> None:
    if not CONVERTER.exists():
        raise SystemExit(
            f"Missing Sigma2XSIAM converter at {CONVERTER}. "
            f"Workflow must clone Sigma2XSIAM into {SIGMA2XSIAM_DIR}."
        )
    if not PIPELINE_YML.exists():
        raise SystemExit(
            f"Missing pipeline file at {PIPELINE_YML}. "
            f"Ensure the Sigma2XSIAM repo includes pipelines/cortex_xdm.yml."
        )


def convert_one_sigma(rule_path: Path, tmp_out: Path) -> str:
    """
    Uses Sigma2XSIAM's CLI converter script to generate XQL to a file and returns it.
    The project documents running convert_rule.py for single and batch conversions. 
    """
    cmd = [
        "python",
        str(CONVERTER),
        "-r",
        str(rule_path),
        "-o",
        str(tmp_out),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"Conversion failed for {rule_path}\n"
            f"STDOUT:\n{proc.stdout}\n"
            f"STDERR:\n{proc.stderr}\n"
        )

    if not tmp_out.exists():
        # Some converters may only print output; but Sigma2XSIAM supports -o output. 
        raise SystemExit(f"Converter did not produce output file: {tmp_out}")

    return tmp_out.read_text(encoding="utf-8").strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-dir", default="rules/sigma")
    ap.add_argument("--out-xql-dir", default="generated/xql")
    ap.add_argument("--out-corr-dir", default="generated/correlations")
    args = ap.parse_args()

    ensure_vendor_present()

    sigma_dir = Path(args.sigma_dir)
    out_xql_dir = Path(args.out_xql_dir)
    out_corr_dir = Path(args.out_corr_dir)
    out_xql_dir.mkdir(parents=True, exist_ok=True)
    out_corr_dir.mkdir(parents=True, exist_ok=True)

    sigma_files = sorted(list(sigma_dir.rglob("*.yml")) + list(sigma_dir.rglob("*.yaml")))
    if not sigma_files:
        print(f"No Sigma files found in {sigma_dir}")
        return

    tmp_dir = Path(".tmp_sigma2xsiam")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    for rule_path in sigma_files:
        raw = rule_path.read_text(encoding="utf-8")
        rule_dict = yaml.safe_load(raw) or {}

        raw_name = (rule_dict.get("title") or rule_dict.get("id") or rule_path.stem).strip()
        name = raw_name if raw_name.startswith(DAC_PREFIX) else f"{DAC_PREFIX}{raw_name}"

        desc = (rule_dict.get("description") or "").strip()
        if DAC_MARKER not in desc:
            desc = (desc + "\n\n" + DAC_MARKER).strip()

        safe = sanitize_filename(name)

        tmp_out = tmp_dir / f"{safe}.xql"
        xql_query = convert_one_sigma(rule_path, tmp_out)

        # Write generated XQL
        (out_xql_dir / f"{safe}.xql").write_text(xql_query + "\n", encoding="utf-8")

        # Build correlation payload JSON (used by reconciliation)
        corr_payload = {
            "rule_id": 0,
            "name": name,
            "severity": sigma_level_to_xsiam(rule_dict.get("level")),
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

        (out_corr_dir / f"{safe}.json").write_text(json.dumps(corr_payload, indent=2) + "\n", encoding="utf-8")

        print(f"Converted: {rule_path} -> {safe}.xql + {safe}.json")


if __name__ == "__main__":
    main()
