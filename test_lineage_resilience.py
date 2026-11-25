from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import inventory_demo as demo
from lineage_observe import observe, postgres_ancestors
from resilience_gate import CallWindow, TransientFailure, WindowClosed
from run_ledger import RunLedger, read_verified
from task_chain import Denied, load_policy, run, wire
from workflow_contracts import Resilience


class TimingTests(unittest.TestCase):
    def test_exact_margin_denies_and_one_nanosecond_more_admits(self):
        policy = Resilience(attempts=1, window_ns=100, attempt_bound_ns=40,
                            fallback_reserve_ns=5, uncertainty_ns=5)
        for margin in (50, 51):
            window = CallWindow(policy, lambda: margin, clock=lambda: 0)
            history = []
            if margin == 50:
                with self.assertRaisesRegex(WindowClosed, "insufficient_margin"):
                    window.call(lambda packet: packet, b"value", lambda kind, **_: history.append(kind))
                self.assertEqual(history, [])
            else:
                self.assertEqual(window.call(lambda packet: packet, b"value", lambda kind, **_: history.append(kind)),
                                 b"value")
                self.assertEqual(history, ["attempt_admitted", "attempt_completed"])

    def test_tightening_after_backoff_gate_prevents_retry(self):
        policy = Resilience(attempts=2, window_ns=1_000_000, attempt_bound_ns=40,
                            fallback_reserve_ns=5, uncertainty_ns=5, backoff_ns=0)
        current_deadline = 100
        window = CallWindow(policy, lambda: current_deadline, clock=lambda: 0)
        history = []

        def fail(packet):
            raise TransientFailure()

        def record(kind, **details):
            nonlocal current_deadline
            history.append(kind)
            if kind == "retry_scheduled":
                current_deadline = 50

        with self.assertRaises(WindowClosed):
            window.call(fail, b"value", record, replay_safe=True)
        self.assertEqual(history, ["attempt_admitted", "attempt_failed", "retry_scheduled"])

    def test_callback_overrun_denies_returned_result(self):
        policy = Resilience(attempts=1, window_ns=100, attempt_bound_ns=40,
                            fallback_reserve_ns=5, uncertainty_ns=5)
        elapsed = 0
        window = CallWindow(policy, clock=lambda: elapsed)

        def late(packet):
            nonlocal elapsed
            elapsed = 41
            return b"unadmitted"

        with self.assertRaisesRegex(WindowClosed, "attempt_bound_exceeded"):
            window.call(late, b"value", lambda *_args, **_details: None)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "evidence"
        self.ledger = self.directory / "run.sqlite"
        self.policy = load_policy(demo.ROOT / "workflow_policy.toml")
        self.request = (demo.ROOT / "inventory_request.json").read_bytes()

    def run_chain(self, execute=demo.execute, **kwargs):
        return run(self.policy, self.request, demo.decompose, execute,
                   demo.CHECKS, self.directory, **kwargs)

    def test_retry_keeps_packet_identical_and_yields_observable_receipt(self):
        attempts = []

        def transient_then_success(packet):
            if json.loads(packet)["profile"] == "normalize":
                attempts.append(packet)
                if len(attempts) == 1:
                    raise TransientFailure("sensitive service details")
            return demo.execute(packet)

        self.run_chain(transient_then_success, replay_safe=True)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0], attempts[1])
        expected = read_verified(self.ledger)[-1].sha256
        graph = observe(self.ledger, expected)
        self.assertEqual(graph["integrity"], "pinned_receipt")
        self.assertEqual(graph["status"], "admitted")
        self.assertEqual(len([edge for edge in graph["edges"] if edge["relation"] == "uses_artifact"]), 4)
        self.assertTrue({"retry_scheduled", "published", "receipted"} <= {edge["relation"] for edge in graph["edges"]})
        serialized = wire(graph)
        for private in (b"sensitive service details", b"operator_note", b'"NORTH":6', b"Return the total"):
            self.assertNotIn(private, serialized)

    def test_retry_cap_and_explicit_replay_authority(self):
        for replay_safe, expected in ((False, 1), (True, 3)):
            self.directory = self.directory.with_name(f"run-{expected}")
            self.ledger = self.directory / "run.sqlite"
            calls = []

            def fail(packet):
                calls.append(packet)
                raise TransientFailure("hidden")

            with self.assertRaisesRegex(Denied, "executor failed"):
                self.run_chain(fail, replay_safe=replay_safe)
            self.assertEqual(len(calls), expected)
            graph = observe(self.ledger)
            self.assertEqual(graph["status"], "denied")
            self.assertIsNone(graph["receipt"]["details"]["effect_sha256"])
            self.assertNotIn(b"hidden", wire(graph))

    def test_plain_connection_failure_is_terminal(self):
        calls = []

        def fail(packet):
            calls.append(packet)
            raise ConnectionError("uncertain acknowledgement")

        with self.assertRaisesRegex(Denied, "executor failed"):
            self.run_chain(fail, replay_safe=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(observe(self.ledger)["status"], "denied")

    def test_worker_replay_requires_profile_permission(self):
        policy = self.directory.parent / "test_policy.toml"
        policy.write_text((demo.ROOT / "workflow_policy.toml").read_text(encoding="utf-8").replace(
            'replay_profiles = ["normalize", "count", "flag", "report"]', 'replay_profiles = ["count"]'),
            encoding="utf-8")
        self.policy = load_policy(policy)
        calls = []

        def fail(packet):
            calls.append(packet)
            raise TransientFailure()

        with self.assertRaisesRegex(Denied, "executor failed"):
            self.run_chain(fail, replay_safe=True)
        self.assertEqual(len(calls), 1)

    def test_invalid_timing_evidence_denies_before_execution(self):
        with self.assertRaisesRegex(Denied, "invalid_time_evidence"):
            self.run_chain(violation_deadline_ns=lambda: True)
        graph = observe(self.ledger)
        self.assertEqual(graph["status"], "denied")
        self.assertNotIn("attempt_admitted", [node["kind"] for node in graph["nodes"]])

    def test_modified_artifact_and_wrong_receipt_are_rejected(self):
        self.run_chain()
        with self.assertRaisesRegex(Denied, "receipt digest mismatch"):
            observe(self.ledger, "f" * 64)
        with closing(sqlite3.connect(self.ledger)) as db, db:
            db.execute("UPDATE events SET artifact = ? WHERE kind = 'effect_committed'", (b"{}",))
        with self.assertRaisesRegex(Denied, "event digest mismatch"):
            observe(self.ledger)

    def test_receipt_write_failure_rolls_back_effect(self):
        append = RunLedger._append

        def fail_receipt(instance, kind, *args):
            if kind == "run_admitted":
                raise sqlite3.OperationalError("injected failed commit")
            return append(instance, kind, *args)

        with patch.object(RunLedger, "_append", fail_receipt), self.assertRaises(sqlite3.OperationalError):
            self.run_chain()
        graph = observe(self.ledger)
        self.assertEqual(graph["status"], "incomplete")
        self.assertIsNone(graph["receipt"])
        self.assertNotIn("effect_committed", [node["kind"] for node in graph["nodes"]])

    @unittest.skipUnless(os.getenv("CHAIN_TEST_POSTGRES") == "1", "requires PostgreSQL integration fixture")
    def test_native_postgres_receipt_ancestry(self):
        self.run_chain()
        graph = observe(self.ledger)
        upstream = postgres_ancestors(graph)
        self.assertEqual(upstream, graph["nodes"])
        self.assertEqual(upstream[0]["kind"], "run_started")
        self.assertEqual(upstream[-2]["kind"], "effect_committed")
        self.assertEqual(upstream[-1]["kind"], "run_admitted")
