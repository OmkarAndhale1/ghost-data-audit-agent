#!/usr/bin/env python3
"""Compare a generated prediction CSV with the public sample answer file."""
import argparse, csv, json
from pathlib import Path

FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")

def read(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return {r["case_id"]: r for r in csv.DictReader(f)}

def evaluate(dataset: Path, predictions: Path):
    expected = read(dataset / "sample_output.csv")
    actual = read(predictions)
    common = sorted(set(expected) & set(actual))
    status_ok = sum(expected[k]["deletion_status"] == actual[k]["deletion_status"] for k in common)
    sequence_ok = 0
    field_ok = field_total = 0
    for case in common:
        exp_steps = json.loads(expected[case]["steps_json"])
        got_steps = json.loads(actual[case]["steps_json"])
        sequence_ok += exp_steps == got_steps
        for i in range(max(len(exp_steps), len(got_steps))):
            for field in FIELDS:
                field_total += 1
                if i < len(exp_steps) and i < len(got_steps) and exp_steps[i].get(field) == got_steps[i].get(field):
                    field_ok += 1
    n = len(common)
    print(f"Cases matched by ID: {n}/{len(expected)} expected, {len(actual)} predicted")
    print(f"Status accuracy: {status_ok}/{n} ({status_ok/n:.2%})" if n else "Status accuracy: n/a")
    print(f"Exact step-array accuracy: {sequence_ok}/{n} ({sequence_ok/n:.2%})" if n else "Sequence accuracy: n/a")
    print(f"Aligned step-field accuracy: {field_ok}/{field_total} ({field_ok/field_total:.2%})" if field_total else "Field accuracy: n/a")
    missing = sorted(set(expected)-set(actual)); extra = sorted(set(actual)-set(expected))
    if missing: print("Missing cases:", ", ".join(missing))
    if extra: print("Unexpected cases:", ", ".join(extra))
    return 0 if not missing and not extra else 1

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--dataset", type=Path, default=Path("dataset"))
    p.add_argument("--predictions", type=Path, required=True)
    a=p.parse_args()
    raise SystemExit(evaluate(a.dataset, a.predictions))
