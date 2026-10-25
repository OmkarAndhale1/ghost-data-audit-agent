import json
import unittest

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

class ContractTests(unittest.TestCase):
    def test_status_vocabulary(self):
        self.assertEqual(VALID_STATUSES, {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})

    def test_not_applicable_has_empty_steps(self):
        row = {"deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}
        self.assertEqual(json.loads(row["steps_json"]), [])

    def test_step_numbering_and_phase_order(self):
        steps = [
            {"step_no": 1, "phase": "FINDING"},
            {"step_no": 2, "phase": "REMEDIATION"},
            {"step_no": 3, "phase": "VERIFICATION"},
        ]
        self.assertEqual([x["step_no"] for x in steps], list(range(1, len(steps)+1)))
        self.assertEqual([PHASE_ORDER[x["phase"]] for x in steps], sorted(PHASE_ORDER[x["phase"]] for x in steps))

    def test_allowed_operation_shape(self):
        step = {"step_no":1,"phase":"FINDING","system_id":"account_service","resource_id":"account_1","operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":"evidence_1"}
        self.assertEqual(set(step), {"step_no","phase","system_id","resource_id","operation","state","evidence_id"})
        self.assertTrue(step["evidence_id"])

if __name__ == "__main__": unittest.main()
