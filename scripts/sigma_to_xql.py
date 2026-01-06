#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import yaml
from sigma.collection import SigmaCollection
from sigma2xsiam.backend import CortexXsiamBackend

SEVERITY_MAP = {
    "informational": "SEV_010_INFO",
    "low": "SEV_020_LOW",
    "medium": "SEV_030_MEDIUM",
    "high": "SEV_040_HIGH",
    "critical": "SEV_050_CRITICAL",
}

DAC_PREFIX = os.getenv("DAC_PREFIX", "DAC: ")
DAC_MARKER = os.getenv("DAC_MARKER", "Managed by detections-as-code")

def sigma_level_to_xsiam(level):
    if not level:
        return "SEV_030_MEDIUM"
    return SEVERITY_MAP.get(level.lower(), "SEV_030_MEDIUM")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sigma-dir", default="rules/sigma")
    ap.add_argument("--out-xql-dir", default="generated/xql")
    ap.add_argument("--out-corr-dir", default="generated/correlations")
    args = ap.parse_args()

    Path(args.out-xql-dir).mkdir(parents=True, exist_ok=True)
    Path(args.out-corr-dir).mkdir(parents=True, exist_ok=True)

    backend = CortexXsiamBackend()

    for p in Path(args.sigma-dir).glob("*.yml"):
        rule = yaml.safe_load(p.read_text())
        raw_name = rule.get("title") or rule.get("id") or p.stem
        name = raw_name if raw_name.startswith(DAC_PREFIX) else f"{DAC_PREFIX}{raw_name}"

        desc = (rule.get("description") or "").strip()
        if DAC_MARKER not in desc:
            desc = (desc + "\n\n" + DAC_MARKER).strip()

        collection = SigmaCollection.from_yaml(p.read_text())
        xql = "\n".join(backend.convert(collection))

        payload = {
            "rule_id": 0,
            "name": name,
            "severity": sigma_level_to_xsiam(rule.get("level")),
            "xql_query": xql,
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

        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        Path(args.out_xql_dir, f"{safe}.xql").write_text(xql)
        Path(args.out_corr_dir, f"{safe}.json").write_text(json.dumps(payload, indent=2))

if __name__ == "__main__":
    main()
