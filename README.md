# Cortex XSIAM – Detections as Code (Full Reconciliation)

This repository implements a **detections-as-code** pipeline for **Cortex XSIAM** with **Git as the source of truth**.

It supports **IOCs**, **BIOCs**, and **Correlation Rules**, including:
- Sigma → XQL conversion
- Idempotent upsert-by-name
- **Full reconciliation** (create / update / delete)
- Safe scoping to prevent accidental deletion
- GitHub Actions automation

---

## High-level goals

- Treat detections like application code
- Make deployments **repeatable and idempotent**
- Ensure **no configuration drift** between Git and XSIAM
- Allow safe automation without risking manually created rules

---

## What this pipeline manages

| Detection Type | Source of Truth | Managed |
|---------------|----------------|---------|
| Correlation Rules | Sigma (`rules/sigma/`) | ✅ |
| BIOCs | YAML (`rules/biocs/`) | ✅ |
| IOCs | YAML (`rules/iocs/`) | ✅ |

---

## Key design principles

### 1. Git is the source of truth
Anything **present in Git** will exist in XSIAM.  
Anything **removed from Git** will be removed from XSIAM (if managed).

### 2. Idempotency
Running the pipeline repeatedly will result in:
- No API calls if nothing changed
- Only changed rules being updated
- No duplicate rules created

### 3. Safe full reconciliation
To avoid deleting rules you don’t own, the pipeline **only deletes rules it manages**.

A rule is considered **managed** if **both** conditions are true:
- Name starts with a prefix (default: `DAC:`)
- Description/comment contains a marker string  
  (`Managed by detections-as-code`)

This applies to:
- Correlation rules
- BIOCs
- IOCs (via comment field)

---

## Repository structure

```text
detections-as-code/
├── rules/
│   ├── sigma/                # Sigma rules (source for correlations)
│   ├── biocs/                # BIOCs in YAML
│   └── iocs/                 # IOCs in YAML
│
├── generated/
│   ├── xql/                  # Generated XQL queries
│   └── correlations/         # Generated correlation rule payloads
│
├── scripts/
│   ├── sigma_to_xql.py       # Sigma → XQL + correlation payloads
│   └── reconcile_xsiam.py    # Full reconciliation engine
│
├── .github/workflows/
│   └── xsiam_detections_pipeline.yml
│
└── requirements.txt
