# Evaluation Report

## Evaluation setup

The generated predictions were compared with `dataset/sample_output.csv` using `code/evaluation/evaluate.py`. The sample contains 32 labeled cases. The full 518-case output is not ground truth, so its status distribution is descriptive only and is not an accuracy metric.

## Public-sample metrics (latest packaged code)

- Sample cases: 32
- Status matches: 24 / 32 (**75.00%**)
- Exact step-array matches: 1 / 32 (**3.13%**)
- Aligned step-field matches: 484 / 3,546 (**13.65%**)

Reproduce by placing the provided dataset at the repository root and running:

```bash
python code/main.py --dataset ./dataset --requests sample_deletion_requests.csv --output ./sample_generated.csv
python code/evaluation/evaluate.py --dataset ./dataset --predictions ./sample_generated.csv
```

These are the metrics from the current packaged source after removing a case-specific fallback that inferred `account_001`-style resource IDs and `evidence_54` for low-numbered users. Removing that shortcut makes the code more general and avoids hardcoded case labels, but it lowers sample accuracy. Do not represent this implementation as a high-scoring or production-ready solution.

## What the metrics mean

- Status accuracy is only a partial signal: the agent can choose the right status while listing the wrong records or operations.
- Exact sequence accuracy is low, indicating the remediation planner and evidence-to-resource matching need substantial work.
- Field accuracy is calculated over aligned step positions and required step fields; different sequence lengths count as mismatches. It is a strict diagnostic, not a standalone official score.

## Three additional evaluation cases designed for this project

1. **Active sync after deletion:** an account is absent, but a current connector is enabled and can recreate it. Expected: `INCOMPLETE`; report the active flow, propose disabling it, and verify the flow is disabled.
2. **Retained shared support conversation:** a support conversation is policy-required to remain because it contains shared context, but direct customer identifiers remain. Expected: `INCOMPLETE`; redact the conversation and verify the redaction while preserving the record.
3. **Safe tombstone:** an account is deleted and the tombstone contains only a policy-permitted stable `user_id`, with no direct identifiers. Expected: tombstone alone does not make deletion incomplete; verify redaction and verify other applicable requirements.

These are designed scenarios, not measured dataset cases. Add fixtures for each scenario before treating them as automated regression tests.

## Failures found and improvements made

- **Found:** earlier version used a special-case convention to infer account IDs for a small range of user IDs and cite a specific evidence ID. **Improvement:** removed the special-case fallback; account absence is now only added when concrete evidence matches.
- **Found:** PDFs and screenshots were not handled by the initial evidence reader. **Improvement:** added optional PDF text extraction (`pypdf`) and image OCR (`Pillow` + `pytesseract` and the Tesseract system binary). If dependencies are unavailable, those files are skipped safely.
- **Found:** evidence manifest timestamps were repeatedly looked up while processing each record. **Improvement:** index manifest rows once per run.
- **Still unresolved:** event-time reconstruction across multiple snapshots is heuristic; identifier matching is not a full graph; category classification can be wrong for ambiguous schemas; optional OCR can miss text. These issues explain the low step-level metrics and should be addressed next.

## Next improvements

1. Build a temporal evidence ledger keyed by `(system_id, resource_id)` with both capture time and event time.
2. Parse each evidence schema explicitly rather than relying primarily on generic field-name heuristics.
3. Model identity relationships as a graph and avoid unbounded substring matches.
4. Resolve data-flow and backup scope to a subject through explicit source/target/resource links.
5. Add fixture-based regression tests for every policy category and each allowed operation.
6. Only classify `COMPLETE` when each required category has sufficient current-state evidence and no unresolved recreation path remains.
