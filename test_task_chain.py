import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import inventory_demo as demo
from task_chain import Denied, digest, load_policy, run, wire


def events(path):
    connection = sqlite3.connect(path / "run.sqlite")
    try:
        return [(kind, task, json.loads(details), artifact) for kind, task, details, artifact
                in connection.execute("SELECT kind, task_id, details, artifact FROM events ORDER BY sequence")]
    finally:
        connection.close()


class TaskChainTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.evidence = Path(temp.name) / "run"
        self.policy_path = demo.ROOT / "workflow_policy.toml"
        self.policy = load_policy(self.policy_path)
        self.request = (demo.ROOT / "inventory_request.json").read_bytes()
        self.called = []

    def execute(self, packet):
        self.called.append(json.loads(packet)["task_id"])
        return demo.execute(packet)

    def run_chain(self, *, plan=demo.decompose, execute=None, checks=demo.CHECKS):
        return run(self.policy, self.request, plan, execute or self.execute, checks, self.evidence)

    def changed_plan(self, change):
        def plan(packet):
            proposal = json.loads(demo.decompose(packet))
            change(proposal["tasks"])
            return wire(proposal)
        return plan

    def test_scopes_packets_and_commits_artifacts_before_dispatch(self):
        packets = []

        def execute(packet):
            data = json.loads(packet)
            previous = {task: details for kind, task, details, _ in events(self.evidence)
                        if kind == "task_admitted"}
            dispatch = events(self.evidence)[-1]
            self.assertEqual(dispatch[:2], ("task_dispatched", data["task_id"]))
            self.assertEqual(dispatch[2]["prompt_sha256"], digest(packet))
            self.assertTrue(set(dispatch[2]["artifact_inputs"].values())
                            <= {item["artifact_sha256"] for item in previous.values()})
            packets.append(data)
            return self.execute(packet)

        result = self.run_chain(execute=execute)
        self.assertEqual(json.loads(result), {"location_totals": {"NORTH": 6, "SOUTH": 3},
                                              "zero_quantity_rows": ["r2"]})
        self.assertEqual(self.called, ["task_01_normalize", "task_02_count", "task_03_flag", "task_04_report"])
        self.assertEqual([set(packet["inputs"]) for packet in packets],
                         [{"records"}, {"receipt"}, {"receipt"}, {"counts", "exceptions"}])
        self.assertEqual([set(packet["requirements"]) for packet in packets],
                         [{"normalize_locations"}, {"count_inventory"}, {"report_exceptions"}, set()])
        for packet in packets:
            self.assertNotIn("operator_note", wire(packet).decode())
        history = events(self.evidence)
        self.assertEqual(history[0][2]["policy_sha256"], digest(self.policy_path.read_bytes()))
        self.assertEqual(history[-1], ("run_admitted", "task_04_report",
                                       {"artifact_sha256": digest(result)}, None))
        self.assertEqual(history[-2][2]["checks"], ["report_assembly", "original_request_reconciliation"])

    def test_denial_blocks_successors(self):
        def invalid(packet):
            self.called.append(json.loads(packet)["task_id"])
            return b'{"rows":[]}'
        with self.assertRaisesRegex(Denied, "normalized_receipt"):
            self.run_chain(execute=invalid)
        self.assertEqual(self.called, ["task_01_normalize"])
        self.assertEqual(events(self.evidence)[-1][:2], ("run_denied", "task_01_normalize"))
        self.assertFalse(any(item[0] == "task_admitted" for item in events(self.evidence)))

    def test_wrong_intermediate_that_passes_local_check_fails_final_check(self):
        def undercount(packet):
            if json.loads(packet)["profile"] == "count":
                return b'{"location_totals":{"NORTH":5,"SOUTH":3}}'
            return self.execute(packet)
        checks = demo.CHECKS | {"location_totals": lambda context: True}
        with self.assertRaisesRegex(Denied, "final check denied: original_request_reconciliation"):
            self.run_chain(execute=undercount, checks=checks)
        self.assertEqual(events(self.evidence)[-1][:2], ("run_denied", "task_04_report"))

    def test_callbacks_are_given_their_declared_scope(self):
        def local_check(context):
            return context.request is None and demo.normalized_receipt(context)
        def final_check(context):
            return (context.request == self.request and
                    demo.original_request_reconciliation(context))
        self.run_chain(checks=demo.CHECKS | {"normalized_receipt": local_check,
                                           "original_request_reconciliation": final_check})

    def test_validation_rejects_cyclic_unknown_leaking_and_disconnected_tasks(self):
        def detach(tasks):
            tasks["task_detached"] = tasks["task_01_normalize"]
        cases = [
            (lambda t: t["task_01_normalize"]["after"].append("task_04_report"), "cyclic"),
            (lambda t: t["task_01_normalize"]["after"].append("missing"), "undeclared predecessor"),
            (lambda t: t["task_02_count"]["requirements"].clear(), "requirement scope"),
            (lambda t: t["task_02_count"]["requirements"].append("report_exceptions"), "requirement scope"),
            (lambda t: t["task_01_normalize"]["inputs"].update(records="operator_note"), "request input binding"),
            (lambda t: t["task_04_report"]["inputs"].update(counts="task_03_flag"), "artifact input binding"),
            (detach, "outside final dependency graph"),
        ]
        parent = self.evidence.parent
        for index, (mutate, error) in enumerate(cases):
            with self.subTest(error=error):
                self.evidence = parent / f"case-{index}"
                with self.assertRaisesRegex(Denied, error):
                    self.run_chain(plan=self.changed_plan(mutate))
                self.assertEqual(self.called, [])

    def test_canonical_dispatch_and_digests_ignore_task_order_in_planner_output(self):
        self.run_chain()
        original = events(self.evidence)
        self.evidence = self.evidence.with_name("reordered")

        def reversed_plan(packet):
            plan = json.loads(demo.decompose(packet))
            plan["tasks"] = dict(reversed(list(plan["tasks"].items())))
            for task in plan["tasks"].values():
                task["after"].reverse()
            return json.dumps(plan).encode()

        self.run_chain(plan=reversed_plan)
        # The plan digest preserves declared list order. Execution and prompt digests are stable.
        kinds = {"task_dispatched", "task_admitted", "run_admitted"}
        self.assertEqual([row for row in original if row[0] in kinds],
                         [row for row in events(self.evidence) if row[0] in kinds])

    def test_prompt_limit_prevents_dispatch(self):
        self.change_policy("prompt_bytes = 4096", "prompt_bytes = 20")
        with self.assertRaisesRegex(Denied, "task prompt exceeds limit"):
            self.run_chain()
        self.assertEqual(self.called, [])
        self.assertFalse(any(item[0] == "task_dispatched" for item in events(self.evidence)))

    def test_output_limit_applies_before_admission(self):
        self.change_policy("output_bytes = 2048", "output_bytes = 16")
        with self.assertRaisesRegex(Denied, "output exceeds wire limit"):
            self.run_chain()
        self.assertEqual(self.called, ["task_01_normalize"])

    def test_invalid_results_are_denied(self):
        parent = self.evidence.parent
        for index, bad in enumerate((b'{"rows":[],"rows":[]}', b'{"rows":NaN}', b'[]',
                                     br'{"rows":"\udfff"}', b'\xff')):
            with self.subTest(bad=bad):
                self.evidence = parent / f"bad-{index}"
                with self.assertRaises(Denied):
                    self.run_chain(execute=lambda packet: bad)
                self.assertEqual(events(self.evidence)[-1][0], "run_denied")

    def test_existing_run_is_never_reopened(self):
        self.run_chain()
        original = events(self.evidence)
        with self.assertRaises(FileExistsError):
            self.run_chain()
        self.assertEqual(events(self.evidence), original)

    def test_policy_requires_bound_checks_before_dispatch(self):
        checks = dict(demo.CHECKS)
        del checks["original_request_reconciliation"]
        with self.assertRaisesRegex(Denied, "unbound admission check"):
            self.run_chain(checks=checks)
        self.assertFalse(self.evidence.exists())

    def test_policy_rejects_unknown_keys_and_boolean_limits(self):
        for old, new in (("version = 1", "version = 1\nunsupported = true"),
                         ("task_count = 64", "task_count = true"),
                         ('final_checks = ["original_request_reconciliation"]', "final_checks = []")):
            with self.subTest(new=new), self.assertRaises(Denied):
                self.change_policy(old, new)

    def test_example_decomposer_denies_unsupported_intent(self):
        request = json.loads(self.request)
        request["requirements"]["count_inventory"]["text"] = "Count only the SOUTH location."
        self.request = wire(request)
        with self.assertRaisesRegex(Denied, "decomposer failed"):
            self.run_chain()
        self.assertEqual(self.called, [])

    def change_policy(self, old, new):
        path = self.evidence.parent / "changed.toml"
        path.write_text(self.policy_path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
        self.policy = load_policy(path)


if __name__ == "__main__":
    unittest.main()
