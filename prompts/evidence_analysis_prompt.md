# Evidence-analysis contract (documentation)

The current implementation does not invoke an LLM. If an LLM is introduced in a future branch, require it to:

1. Cite only supplied `file_id`, `activity_id`, or `audit_id` values.
2. Distinguish observation time from evidence capture time and evaluate state at `audit_at`.
3. Never infer that an operation succeeded merely because `reported_status` says COMPLETE.
4. Apply `deletion_rules.csv` exactly, including retention, redaction, anonymization, and tombstone exceptions.
5. Return only the allowed operations and states from `problem_statement.md`.
6. Return a structured intermediate representation; deterministic Python must validate IDs, status, and step ordering before output.
7. Treat missing/ambiguous evidence as uncertainty rather than inventing a resource, identifier, or citation.
8. Never include raw personal data in logs or reports unnecessarily.
