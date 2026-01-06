#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path

import yaml
from sigma.rule import SigmaRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.backends.cortexxsiam import CortexXSIAMBackend

SEVERITY_MAP = {
    "informational": "SEV_010_INFO",
    "low": "SEV_020_LOW",
    "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH",
    "critical": "SEV_050_CRITICAL",
}

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")


def sigma_level_to_xsiam(level: str | None) -> str:
    if not level:
        return "SEV_030_MEDIUM"
    return SEVERITY_MAP.get(level.strip().lower(), "SEV_030_MEDIUM")


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-dir", default="rules/sigma")
    ap.add_argument("--out-xql-dir", default="generated/xql")
    ap.add_argument("--out-corr-dir", default="generated/correlations")
    ap.add_argument(
        "--pipeline-yml",
        default="pipelines/cortex_xdm.yml",
        help="Processing pipeline YAML (from sigma2xsiam repo)",
    )
    args = ap.parse_args()

    sigma_dir = Path(args.sigma_dir)
    out_xql_dir = Path(args.out_xql_dir)
    out_corr_dir = Path(args.out_corr_dir)
    out_xql_dir.mkdir(parents=True, exist_ok=True)
    out_corr_dir.mkdir(parents=True, exist_ok=True)

    # Load processing pipeline (required for good XDM field mapping) :contentReference[oaicite:2]{index=2}
    pipeline_path = Path(args.pipeline_yml)
    if not pipeline_path.exists():
        raise SystemExit(
            f"Missing pipeline file: {pipeline_path}. "
            f"Ensure the sigma2xsiam repo files are present in your repo at /pipelines."
        )

    pipeline = ProcessingPipeline.from_yaml(pipeline_path.read_text(encoding="utf-8"))
    backend = CortexXSIAMBackend(processing_pipeline=pipeline)

    sigma_files = sorted(list(sigma_dir.rglob("*.yml")) + list(sigma_dir.rglob("*.yaml")))
    if not sigma_files:
        print(f"No Sigma files found in {sigma_dir}")
        return

    for rule_path in sigma_files:
        raw = rule_path.read_text(encoding="utf-8")
        rule_dict = yaml.safe_load(raw) or {}

        raw_name = (rule_dict.get("title") or rule_dict.get("id") or rule_path.stem).strip()
        name = raw_name if raw_name.startswith(DAC_PREFIX) else f"{DAC_PREFIX}{raw_name}"

        desc = (rule_dict.get("description") or "").strip()
        if DAC_MARKER not in desc:
            desc = (desc + "\n\n" + DAC_MARKER).strip()

        sigma_rule = SigmaRule.from_yaml(raw)

        # Convert: returns list of queries; most rules -> 1
        xql_query = backend.convert_rule(sigma_rule)[0].strip()

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

        safe = sanitize_filename(name)
        (out_xql_dir / f"{safe}.xql").write_text(xql_query + "\n", encoding="utf-8")
        (out_corr_dir / f"{safe}.json").write_text(json.dumps(corr_payload, indent=2) + "\n", encoding="utf-8")

        print(f"Converted: {rule_path} -> {safe}.xql + {safe}.json")


if __name__ == "__main__":
    main()
