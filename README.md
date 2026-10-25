# Ghost Data Audit Agent

A Python-based, evidence-grounded baseline for the HackerRank Orchestrate “Ghost Data Still Exists” challenge.

> **Honest status:** this is a runnable research/PR package, not a claim of perfect canonical accuracy. The latest public-sample run recorded 24/32 status matches (75.00%) and 1/32 exact step-array matches (3.13%). The largest known limitation is interpreting conflicting/historical evidence at `audit_at`; review the evaluation report before relying on predictions.

## What it does

- Reads the challenge CSV files and evidence manifest.
- Resolves exact current and historical identifiers using identity records and audit logs.
- Parses JSON and SQLite-compatible SQL snapshots, text/log files, and optionally PDFs/images when OCR libraries are installed.
- Applies deterministic policy heuristics to produce `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- Writes ordered JSON steps to a CSV file.
- Includes schema/order tests and a public-sample evaluation script.

The program does not call an external LLM/VLM API. The “AI agent” task is implemented here as a deterministic evidence-processing baseline. This avoids API credentials and unreported model cost, but also means nuanced evidence interpretation remains a limitation.

## Requirements

- Python 3.10+
- Core pipeline uses the Python standard library.
- Optional evidence parsing:
  - `pypdf` for PDF text extraction.
  - `Pillow` and `pytesseract` plus a system Tesseract installation for OCR of images.

Install optional dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run

Place the supplied `dataset/` directory at the repository root (it is intentionally not bundled in this source ZIP), then run:

```bash
python code/main.py
```

Defaults:
- input: `dataset/deletion_requests.csv`
- output: `output.csv`

Custom paths:

```bash
python code/main.py --dataset ./dataset --requests deletion_requests.csv --output ./output.csv
```

To run the public sample through the same pipeline:

```bash
python code/main.py --dataset ./dataset --requests sample_deletion_requests.csv --output ./sample_generated.csv
python code/evaluation/evaluate.py --dataset ./dataset --predictions ./sample_generated.csv
```

## Tests

```bash
python -m unittest discover -s code/tests -v
```

## Output contract

The CSV header is exactly `case_id,deletion_status,steps_json`. Each `steps_json` value is a JSON array. Steps use the required fields, consecutive numbering, and phase order `FINDING`, `REMEDIATION`, `VERIFICATION`. Findings use evidence IDs; proposed remediation/future verification steps use an empty evidence ID.

## Important engineering limitations

1. Evidence extraction is heuristic and may not correctly interpret every schema, PDF, screenshot, or log format.
2. Resource matching is identifier/string based and can miss indirect links or create false positives.
3. Conflicting evidence and snapshot lineage are not yet modeled with a complete event-sourcing/temporal database approach.
4. OCR is optional and only runs if the optional Python packages and Tesseract binary are installed.
5. The public-sample evaluation is the available validation; it does not establish hidden-test accuracy.

## PR guidance

Create a branch in your own repository, review the code and evaluation report, run tests, and commit the source. A GitHub PR does not update a HackerRank submission or guarantee a challenge-score change. Do not commit the dataset, private information, API keys, or generated customer-level predictions unless the repository owner explicitly permits them.
