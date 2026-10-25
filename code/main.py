#!/usr/bin/env python3
"""Evidence-grounded deletion audit pipeline for Ghost Data Still Exists.

Uses only participant-facing dataset files. Structured evidence is parsed first;
text/log evidence is also searched. Policy decisions and step ordering are
implemented deterministically so model output is not required for correctness.
"""
from __future__ import annotations
import csv, json, re, sqlite3, sys, hashlib, argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "FINDING": {"REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3},
    "REMEDIATION": {"DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4},
    "VERIFICATION": {"VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5},
}


def read_csv(name):
    with (DATA / name).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def dt(value):
    if not value: return None
    try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception: return None


def norm(v):
    return str(v or "").strip().casefold()


def add_id(mapping, user_id, value):
    value = norm(value)
    if value and value not in {"none", "null", "nan", "n/a"}:
        mapping[value].add(user_id)


def identity_index():
    identities = read_csv("user_identities.csv")
    audits = read_csv("user_audit_log.csv")
    idx = defaultdict(set)
    users = {}
    for r in identities:
        uid = r["user_id"]
        users[uid] = dict(r)
        for k in ("name", "email", "phone", "email_hash"):
            add_id(idx, uid, r.get(k))
    for r in audits:
        uid = r.get("user_id", "")
        for k in ("old_value", "new_value"):
            add_id(idx, uid, r.get(k))
    return idx, users, audits


def resolve_user(email, idx, users, audits):
    hits = idx.get(norm(email), set())
    if hits:
        # Exact email is expected to map to one user; deterministic fallback if malformed.
        return sorted(hits)[0]
    return None


def load_manifest():
    out = {}
    for r in read_csv("evidence_files.csv"):
        out[r["file_path"]] = r["file_id"]
    return out


def walk_dicts(obj, inherited_system=""):
    """Yield each dictionary with its nearest inferred system and parent context."""
    if isinstance(obj, dict):
        system = inherited_system
        for k in ("data_store", "system", "service", "source_system", "target_system"):
            if isinstance(obj.get(k), str):
                val = obj[k]
                if val.endswith("_service") or val.endswith("_platform") or val.endswith("_system") or val in {"identity_service", "security_service", "backup_service", "integration_service", "export_service", "support_platform", "search_service", "analytics_platform", "account_service", "marketing_platform", "cache_service", "email_service"}:
                    system = val
        yield obj, system
        for v in obj.values():
            yield from walk_dicts(v, system)
    elif isinstance(obj, list):
        for v in obj: yield from walk_dicts(v, inherited_system)


def read_json_records(path):
    try: obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception: return []
    result = []
    for d, system in walk_dicts(obj):
        rid = d.get("resource_id") or d.get("record_id") or d.get("id")
        if not rid: continue
        # Include only records that look like resource-level data, not arbitrary nested metadata.
        vals = " ".join(str(v) for v in d.values() if isinstance(v, (str, int, float, bool)) and v is not None)
        result.append({"resource_id": str(rid), "system": system, "data": d, "text": vals})
    return result


def read_sql_records(path):
    # SQL evidence is SQLite-compatible. Execute each snapshot in an isolated in-memory DB.
    try:
        script = path.read_text(encoding="utf-8", errors="replace")
        con = sqlite3.connect(":memory:")
        con.executescript(script)
        rows = []
        tables = [x[0] for x in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            try:
                cur = con.execute('SELECT * FROM "' + table.replace('"','""') + '"')
                cols = [x[0] for x in cur.description]
                for vals in cur.fetchall():
                    d = dict(zip(cols, vals))
                    # Some evidence databases store heterogeneous records in a JSON payload column.
                    # Decode it so category/system/state fields are not lost in a serialized string.
                    nested = None
                    for field in ("payload", "record_json", "json_record", "record_data", "document"):
                        if isinstance(d.get(field), str) and d[field].lstrip().startswith("{"):
                            try:
                                nested = json.loads(d[field]); break
                            except Exception:
                                pass
                    if isinstance(nested, dict):
                        merged = dict(d); merged.update(nested); d = merged
                    rid = d.get("resource_id") or d.get("record_id") or d.get("id")
                    if rid:
                        system = d.get("system") or d.get("data_store") or d.get("origin_system") or system_for_table(table)
                        rows.append({"resource_id": str(rid), "system": str(system), "data": d, "text": " ".join(str(v) for v in vals if v is not None) + " " + json.dumps(d, ensure_ascii=False, default=str)})
            except Exception: pass
        con.close(); return rows
    except Exception: return []


def system_for_table(table):
    t = table.casefold()
    if "profile" in t and "analytic" not in t: return "account_service"
    if "search" in t: return "search_service"
    if "analytic" in t or "telemetry" in t: return "analytics_platform"
    if "support" in t: return "support_platform"
    if "export" in t: return "export_service"
    if "connector" in t or "flow" in t: return "integration_service"
    if "backup" in t or "restore" in t: return "backup_service"
    if "security" in t or "audit" in t: return "security_service"
    if "tombstone" in t or "deleted_customer" in t: return "identity_service"
    return "unknown_system"


def read_pdf_records(path):
    """Extract text from PDF evidence when pypdf is installed; fail safely otherwise."""
    try:
        from pypdf import PdfReader
        text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
    except Exception:
        return []
    return records_from_text(text)


def read_image_records(path):
    """OCR image evidence when Pillow and pytesseract/Tesseract are available."""
    try:
        from PIL import Image
        import pytesseract
        text = pytesseract.image_to_string(Image.open(path))
    except Exception:
        return []
    return records_from_text(text)


def records_from_text(text):
    rows=[]
    for line in text.splitlines():
        ridm = re.search(r'\b(resource_id|resource|record_id|record|account_id)=([\w./:-]+)', line, re.I)
        if not ridm:
            parts = [x.strip() for x in line.split("|")]
            if len(parts) >= 5 and re.match(r'^[\w]+_\d+$', parts[2]):
                rows.append({"resource_id":parts[2],"system":parts[1],"data":{"line":line},"text":line})
            continue
        sm = re.search(r'\b(?:service|system|source_system|target_system)=([\w.-]+)', line, re.I)
        rows.append({"resource_id":ridm.group(2),"system":sm.group(1) if sm else "unknown_system","data":{"line":line},"text":line})
    return rows


def read_text_records(path):
    return records_from_text(path.read_text(encoding="utf-8", errors="replace"))


def collect_evidence(manifest):
    allrows=[]
    for rel, evid in manifest.items():
        p = DATA / rel
        if not p.exists(): continue
        suffix = p.suffix.lower()
        if suffix == ".json": rows=read_json_records(p)
        elif suffix == ".sql": rows=read_sql_records(p)
        elif suffix in {".log", ".txt", ".csv"}: rows=read_text_records(p)
        elif suffix == ".pdf": rows=read_pdf_records(p)
        elif suffix in {".png", ".jpg", ".jpeg", ".webp"}: rows=read_image_records(p)
        else: rows=[]
        for r in rows:
            r["evidence_id"] = evid; r["path"] = rel
            allrows.append(r)
    return allrows


def classify_system(row):
    s = (row.get("system") or "").casefold()
    rid = row["resource_id"].casefold()
    d = row.get("data", {})
    if "tombstone" in rid or "deleted_customer" in str(d.get("record_type", "")).casefold(): return "identity_service", "ACCOUNT_TOMBSTONE"
    if "account" in s or rid.startswith("account_"): return "account_service", "USER_PROFILE"
    if "search" in s or rid.startswith("search_"): return "search_service", "SEARCH_INDEX_ENTRY"
    if "cache" in s or rid.startswith("cache_"): return "cache_service", "CACHE_ENTRY"
    if "support" in s or rid.startswith("support_"): return "support_platform", "SUPPORT_MESSAGE"
    if "analytic" in s or rid.startswith("analytics_"): return "analytics_platform", "ANALYTICS_PROFILE"
    if "telemetry" in s: return s, "PRODUCT_TELEMETRY"
    if "export" in s or rid.startswith("export_"): return "export_service", "USER_EXPORT"
    if "market" in s or rid.startswith("marketing_"): return "marketing_platform", "MARKETING_PROFILE"
    if "security" in s or rid.startswith("audit_record_"): return "security_service", "SECURITY_AUDIT_LOG"
    if "backup" in s or rid.startswith("backup_"): return "backup_service", "BACKUP_ARCHIVE"
    if "integration" in s or "connector" in rid or rid.startswith("data_flow_"): return "integration_service", "DATA_FLOW"
    if "email" in s or "delivery" in s: return s, "EMAIL_DELIVERY_LOG"
    return s or "unknown_system", "UNKNOWN"


def status_of(row):
    d=row.get("data",{}); text=(row.get("text","")+" "+json.dumps(d,ensure_ascii=False,default=str)).casefold()
    # Evidence record's explicit state/status dominates inferred identifiers.
    for key in ("result","status","state","account_status","last_delivery_status","event_name","event_code"):
        v=norm(d.get(key))
        if v in {"not_found","absent","deleted","deleted_successfully","404","anonymized","redacted","disabled","blocked","retained","found","active","identifiable","present"}:
            return v.upper()
    if any(x in text for x in ("status_code': 404", '"status_code": 404', "rows=0", "result=miss", "result=not_found", "not_found")): return "ABSENT"
    if "restore_allowed': false" in text or '"restore_allowed": false' in text or "restore_allowed=false" in text: return "BLOCKED"
    if "enabled': 0" in text or '"enabled": 0' in text or "enabled=false" in text or "disabled" in text: return "DISABLED"
    if any(x in text for x in ("anonymized", "identifiable")): return "ANONYMIZED" if "anonymized" in text else "PRESENT"
    if "redacted" in text: return "REDACTED"
    if "active" in text or "found" in text or "result=hit" in text or "http_status=200" in text: return "PRESENT"
    return "PRESENT"


def is_deletion_request(req):
    text = norm(req.get("request_text"))
    # A verification-only question still authorizes auditing the existing deletion; only explicit non-request language is N/A.
    # Clearly non-deletion requests should not authorize an audit/remediation plan.
    non_delete = re.search(r"\b(leave the account active|keep the account as it is|without removing any|leave my profile .* in place|want to continue using the service|change the email address|correct it without removing|copy of .* invoices|download my account information)\b", text)
    explicit_no = re.search(r"\b(not requesting|not ask(?:ing)? for deletion|do not delete|don't delete|no deletion request|did not request deletion|not a deletion request)\b", text)
    if non_delete or explicit_no: return False
    # Requests are multilingual; several localized templates do not contain English verbs.
    if re.search(r"\b(verify|check|audit|confirm|already deleted|deletion|delete|deleted|deleting|erase|erased|erasure|remove|removed|removal|close|closed|eliminat|forget|supress|suppression|exclus[aã]o|eliminaci[oó]n|borrar|eliminar|lösch|löschung)\b", text): return True
    if any(token in text for token in ("영구 삭제", "完全な削除", "削除を依頼", "永久删除", "删除请求")): return True
    return False


def make_step(phase, system, resource, operation, state, evidence=""):
    return {"step_no":0,"phase":phase,"system_id":system,"resource_id":resource,"operation":operation,"state":state,"evidence_id":evidence}


def run_pipeline(data_dir: Path, output_path: Path, request_filename: str = "deletion_requests.csv"):
    global DATA, OUT
    DATA = data_dir.resolve()
    OUT = output_path.resolve()
    requests=read_csv(request_filename)
    ids, users, audits=identity_index()
    manifest=load_manifest()
    evidence=collect_evidence(manifest)
    manifest_rows = {r["file_path"]: r for r in read_csv("evidence_files.csv")}
    activity=read_csv("system_activity.csv")
    # Identity-associated historical identifiers, including old values and current identity fields.
    idvals=defaultdict(set)
    for value,uids in ids.items():
        for uid in uids: idvals[uid].add(value)
    # Stable internal IDs are identifiers too and connect snapshots that no longer contain PII.
    for uid in users:
        idvals[uid].add(norm(uid))
    for req in requests:
        req["_user_id"] = resolve_user(req.get("email"), ids, users, audits)
    # Evidence records are selected by exact identifiers or resolved user_id; no fuzzy name-only matching.
    output=[]
    for req in requests:
        case=req["case_id"]; email=norm(req.get("email")); audit=dt(req.get("audit_at")); uid=req.get("_user_id")
        if not is_deletion_request(req):
            output.append({"case_id":case,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"}); continue
        identifiers={email}
        if uid:
            identifiers |= idvals.get(uid,set())
        # Build relevant records with evidence timestamp not after the audit point when the timestamp is explicit.
        relevant=[]
        for row in evidence:
            d=row.get("data",{})
            searchable=norm(row.get("text"))+" "+norm(json.dumps(d,ensure_ascii=False,default=str))
            if not any(x and x in searchable for x in identifiers): continue
            # Avoid evidence captured after audit_at, unless the file is a direct readback dated later than audit
            # (later readbacks are not used to prove the historical state).
            captured=None
            # capture timestamp from manifest entry
            rel=row.get("path")
            mr=manifest_rows.get(rel)
            if mr: captured=dt(mr.get("captured_at"))
            if audit and captured and captured > audit: continue
            system,cat=classify_system(row)
            relevant.append((row,system,cat,status_of(row)))
        # Include activity only where an identifier/resource maps to this subject; activity is supporting context,
        # not sufficient by itself to prove deletion unless it contains a concrete resource and final operation.
        act_relevant=[]
        resource_ids={x[0]["resource_id"] for x in relevant}
        for a in activity:
            if audit and dt(a.get("event_time")) and dt(a["event_time"])>audit: continue
            if a.get("resource_id") in resource_ids or any(v and v in norm(a.get("details")) for v in identifiers):
                act_relevant.append(a)
        # Temporal reconciliation: within each system+category the most recently
        # captured evidence at or before audit_at supersedes older snapshots. Keep
        # every matched record from that decisive capture so stale snapshot copies
        # (replicas, historical bundles, old readback traces) do not add phantom
        # steps for resources that have since been superseded.
        by_group=defaultdict(list)
        for row,system,cat,state in relevant:
            by_group[(system,cat)].append((row,system,cat,state))

        def capture_rank(item):
            rel=item[0].get("path")
            mr=manifest_rows.get(rel)
            cap=dt(mr.get("captured_at")) if mr else None
            # Later capture wins; the evidence id breaks ties deterministically.
            return (cap.timestamp() if cap else 0.0, int(item[0]["evidence_id"].split("_")[-1]))

        chosen=[]
        for items in by_group.values():
            decisive=max(items,key=capture_rank)[0]["evidence_id"]
            chosen.extend(item for item in items if item[0]["evidence_id"]==decisive)
        # Resource states/rules: expose PII records, active flows, restore risks, and records explicitly required retained.
        findings=[]; remediation=[]; verification=[]
        found_account=False
        for row,system,cat,state in chosen:
            rid=row["resource_id"]; d=row.get("data",{}); evid=row["evidence_id"]
            if cat=="SECURITY_AUDIT_LOG":
                if state not in {"ABSENT"}: verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_PRESENT","PRESENT",evid))
                continue
            if cat=="BACKUP_ARCHIVE":
                restore_allowed = d.get("restore_allowed") is True or str(d.get("restore_allowed","")).lower() in {"1","true"}
                if state=="ACTIVE" or restore_allowed or (state=="PRESENT" and "restore_allowed" in d and restore_allowed):
                    findings.append(make_step("FINDING",system,rid,"REPORT_RESTORE_RISK","ACTIVE",evid))
                    remediation.append(make_step("REMEDIATION",system,rid,"BLOCK_RESTORE","BLOCKED"))
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RESTORE_BLOCKED","BLOCKED"))
                else:
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RESTORE_BLOCKED","BLOCKED",evid))
                continue
            if cat=="DATA_FLOW":
                enabled=d.get("enabled") is True or str(d.get("enabled","")).lower() in {"1","true"} or state=="ACTIVE"
                if enabled:
                    findings.append(make_step("FINDING",system,rid,"REPORT_ACTIVE_DATA_FLOW","ACTIVE",evid))
                    remediation.append(make_step("REMEDIATION",system,rid,"DISABLE_DATA_FLOW","DISABLED"))
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_DATA_FLOW_DISABLED","DISABLED"))
                else: verification.append(make_step("VERIFICATION",system,rid,"VERIFY_DATA_FLOW_DISABLED","DISABLED",evid))
                continue
            if cat=="ACCOUNT_TOMBSTONE":
                pii=any(d.get(k) not in (None,"") for k in ("name","full_name","email","phone","email_hash"))
                if pii:
                    findings.append(make_step("FINDING",system,rid,"REPORT_EXPOSED_PII","PRESENT",evid))
                    remediation.append(make_step("REMEDIATION",system,rid,"REDACT_RECORD","REDACTED"))
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED","REDACTED"))
                else: verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED","REDACTED",evid))
                continue
            if cat=="ANALYTICS_PROFILE" or cat=="PRODUCT_TELEMETRY":
                pii=any(d.get(k) not in (None,"") for k in ("email","phone","email_hash","customer_reference","user_id","user_id_ref"))
                if pii:
                    findings.append(make_step("FINDING",system,rid,"REPORT_EXPOSED_PII","PRESENT",evid))
                    remediation.append(make_step("REMEDIATION",system,rid,"ANONYMIZE_RECORD","ANONYMIZED"))
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED"))
                else: verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_ANONYMIZED","ANONYMIZED",evid))
                continue
            if cat=="SUPPORT_MESSAGE":
                pii=any(d.get(k) not in (None,"") for k in ("requester_name","requester_email","requester_phone","email","phone"))
                # Only retained shared-context support messages should be redacted; attachments are handled by category.
                if pii:
                    findings.append(make_step("FINDING",system,rid,"REPORT_EXPOSED_PII","PRESENT",evid))
                    remediation.append(make_step("REMEDIATION",system,rid,"REDACT_RECORD","REDACTED"))
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED","REDACTED"))
                else: verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED","REDACTED",evid))
                continue
            # Any direct-identifier record in a delete category is remaining data unless explicit absent/deleted.
            if cat in {"USER_PROFILE","SECONDARY_IDENTIFIER","SEARCH_INDEX_ENTRY","CACHE_ENTRY","SUPPORT_ATTACHMENT","USER_EXPORT","MARKETING_PROFILE","EMAIL_DELIVERY_LOG"}:
                if state not in {"ABSENT","NOT_FOUND","DELETED"}:
                    findings.append(make_step("FINDING",system,rid,"REPORT_REMAINING_RECORD","PRESENT",evid))
                    op="REDACT_RECORD" if cat=="EMAIL_DELIVERY_LOG" else "DELETE_RECORD"
                    remediation.append(make_step("REMEDIATION",system,rid,op,"REDACTED" if op=="REDACT_RECORD" else "ABSENT"))
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_REDACTED" if op=="REDACT_RECORD" else "VERIFY_RECORD_ABSENT","REDACTED" if op=="REDACT_RECORD" else "ABSENT"))
                else:
                    verification.append(make_step("VERIFICATION",system,rid,"VERIFY_RECORD_ABSENT","ABSENT",evid))
                if cat=="USER_PROFILE": found_account=True
        # Account verification is required for every authorized deletion; use most relevant account lookup if available.
        account_steps=[s for s in verification if s["system_id"]=="account_service" and s["operation"]=="VERIFY_RECORD_ABSENT"]
        if not account_steps:
            # Only add account absence verification when concrete evidence records an
            # account lookup/readback for this identity. Never infer resource IDs or evidence IDs.
            candidates=[]
            for row in evidence:
                if "account_" not in row["resource_id"]: continue
                text=norm(row.get("text"))+" "+norm(json.dumps(row.get("data",{}),default=str))
                if any(v and v in text for v in identifiers) and ("not_found" in text or "404" in text or "rows=0" in text):
                    candidates.append(row)
            if candidates:
                row=sorted(candidates,key=lambda x:int(x["evidence_id"].split("_")[-1]))[-1]
                verification.append(make_step("VERIFICATION","account_service",row["resource_id"],"VERIFY_RECORD_ABSENT","ABSENT",row["evidence_id"]))
        # Add retained security record verification associated by user id, even if only user_id in row.
        # If no relevant concrete state is found, conservatively mark incomplete and provide an evidence gap finding.
        if not findings:
            # If any relevant resource remains in delete category, status is incomplete; otherwise complete only with a proof.
            status="COMPLETE" if verification else "INCOMPLETE"
        else: status="INCOMPLETE"
        if status=="COMPLETE":
            steps=[s for s in verification if s.get("evidence_id")]
        else:
            # Do not claim unobserved future operations as completed. Sort and number by contract.
            steps=findings+remediation+verification
            # Verification after remediation should cover each proposed action; account absence remains a current-state check.
        # Collapse repeated (phase, system, resource, operation, state) observations so the
        # same logical step is not emitted once per historical snapshot.
        seen=set(); unique_steps=[]
        for s in steps:
            key=(s["phase"],s["system_id"],s["resource_id"],s["operation"],s["state"])
            if key in seen: continue
            seen.add(key); unique_steps.append(s)
        steps=unique_steps
        if not steps:
            # An empty step array is only valid for NOT_APPLICABLE. When no concrete evidence
            # is matched we cannot assert completion, so record the outstanding account lookup
            # as a planned verification step rather than emitting an INCOMPLETE row with no steps.
            status="INCOMPLETE"
            steps=[make_step("VERIFICATION","account_service","","VERIFY_RECORD_ABSENT","ABSENT")]
        steps.sort(key=lambda s:(PHASE_ORDER[s["phase"]],OP_ORDER[s["phase"]].get(s["operation"],99),s["system_id"],s["resource_id"]))
        # Ensure complete cases only have verification and all incomplete future steps have empty evidence ids.
        if status=="INCOMPLETE":
            for s in steps:
                if s["phase"] in {"REMEDIATION"} or (s["phase"]=="VERIFICATION" and not s.get("evidence_id")):
                    s["evidence_id"]=""
        for i,s in enumerate(steps,1): s["step_no"]=i
        output.append({"case_id":case,"deletion_status":status,"steps_json":json.dumps(steps,separators=(",",":"),ensure_ascii=False)})
    output.sort(key=lambda r:r["case_id"])
    with OUT.open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"],lineterminator="\n")
        w.writeheader(); w.writerows(output)
    print(f"Wrote {len(output)} rows to {OUT}")
    from collections import Counter
    print("Status counts:",dict(Counter(r["deletion_status"] for r in output)))

def main():
    parser = argparse.ArgumentParser(description="Audit customer deletion requests using supplied evidence.")
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset", help="Directory containing challenge CSVs and evidence/")
    parser.add_argument("--requests", default="deletion_requests.csv", help="Request CSV filename within --dataset")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv", help="Output CSV path")
    args = parser.parse_args()
    run_pipeline(args.dataset, args.output, args.requests)

if __name__ == "__main__": main()
