"""Verify a local run ledger and emit a redacted origin-to-receipt graph."""

import argparse
from pathlib import Path
import sqlite3
import sys

from run_ledger import TERMINAL, read_verified
from runtime_codec import Denied, require, wire


METADATA_FIELDS = {
    "planning_started": ("planner_packet_bytes", "planner_packet_sha256"),
    "plan_admitted": ("task_count", "final_task"),
    "task_dispatched": ("profile", "prompt_bytes", "prompt_sha256"),
    "task_admitted": ("checks",),
    "attempt_admitted": ("stage", "attempt"),
    "attempt_completed": ("stage", "attempt"),
    "attempt_failed": ("stage", "attempt", "classification"),
    "retry_scheduled": ("stage", "attempt", "delay_ns"),
    "window_closed": ("reason", "observed_ns", "deadline_ns", "required_ns"),
    "effect_committed": ("effect",),
}


def observe(path, expected_receipt=None):
    events = read_verified(path, expected_receipt)
    origin = events[0]
    nodes = []
    edges = []
    dispatches = {}
    admitted = {}
    stage_heads = {}
    planning = plan = effect = None

    def connect(source, target, relation, alias=None):
        require(source is not None and source.sequence < target.sequence, "unbound lineage reference")
        edges.append({"source": source.sequence, "target": target.sequence, "relation": relation, "alias": alias})

    for event in events:
        name, details = event.task_id, event.details
        nodes.append({
            "sequence": event.sequence, "kind": event.kind, "task_id": name,
            "event_sha256": event.sha256, "artifact_sha256": event.artifact_sha256,
            "metadata": {key: details[key] for key in
                         ("observed_at_ns", *METADATA_FIELDS.get(event.kind, ()))},
        })
        if event.kind == "planning_started":
            require(planning is None, "duplicate planning event")
            planning = event
            stage_heads[None] = event
            connect(origin, event, "planned_from")
        elif event.kind == "plan_admitted":
            require(plan is None and details.get("plan_sha256") == event.artifact_sha256,
                    "invalid plan evidence")
            plan = event
            connect(stage_heads.get(None), event, "produced_plan")
        elif event.kind == "task_dispatched":
            require(name is not None and name not in dispatches, "duplicate task dispatch")
            dispatches[name] = event
            stage_heads[name] = event
            connect(plan, event, "scheduled")
            for alias in details["request_sources"]:
                require(origin.details["request_sha256"] is not None, "request source lacks digest")
                connect(origin, event, "uses_request", alias)
            for predecessor in details["predecessors"]:
                connect(admitted.get(predecessor), event, "requires")
            sources = details["artifact_sources"]
            require(sources.keys() == details["artifact_inputs"].keys(), "artifact inputs differ from bindings")
            for alias, producer in sources.items():
                prior = admitted.get(producer)
                require(producer in details["predecessors"] and prior is not None
                        and prior.artifact_sha256 == details["artifact_inputs"][alias],
                        "artifact input digest mismatch")
                connect(prior, event, "uses_artifact", alias)
        elif event.kind in {"attempt_admitted", "attempt_failed", "attempt_completed", "retry_scheduled"}:
            connect(stage_heads.get(name), event, event.kind)
            stage_heads[name] = event
        elif event.kind == "window_closed":
            connect(stage_heads.get(name, plan or planning or origin), event, "closed_window")
            stage_heads[name] = event
        elif event.kind == "task_admitted":
            require(name not in admitted and event.artifact_sha256 is not None
                    and event.artifact_sha256 == details.get("artifact_sha256"), "invalid transform evidence")
            admitted[name] = event
            connect(stage_heads.get(name), event, "produced_artifact")
            stage_heads[name] = event
        elif event.kind == "effect_committed":
            source = admitted.get(name)
            require(effect is None and plan is not None and name == plan.details["final_task"]
                    and len(admitted) == plan.details["task_count"]
                    and source is not None and event.artifact_sha256 is not None
                    and source.artifact_sha256 == event.artifact_sha256 == details.get("artifact_sha256"),
                    "effect differs from admitted final artifact")
            connect(source, event, "published")
            effect = event
        elif event.kind in TERMINAL:
            _verify_receipt(event, origin, plan, effect)
            connect(effect or stage_heads.get(name, plan or planning or origin), event, "receipted")
            if effect is None:
                for prior in admitted.values():
                    connect(prior, event, "admitted_before_denial")
        else:
            require(event is origin, "unknown lineage event")

    terminal = events[-1]
    has_receipt = terminal.kind in TERMINAL
    require(effect is None or terminal.kind == "run_admitted", "unreceipted effect")
    return {
        "origin": {key: origin.details[key] for key in
                   ("run_id", "policy_id", "generation", "policy_sha256", "request_sha256")},
        "status": terminal.details["status"] if has_receipt else "incomplete",
        "integrity": "pinned_receipt" if expected_receipt is not None else "unanchored_chain",
        "receipt": ({"sequence": terminal.sequence, "sha256": terminal.sha256,
                     "details": terminal.details} if has_receipt else None),
        "nodes": nodes,
        "edges": edges,
    }


def _verify_receipt(event, origin, plan, effect):
    receipt = event.details
    keys = ("run_id", "policy_id", "generation", "policy_sha256", "request_sha256")
    require(receipt.get("receipt_version") == 1
            and all(receipt.get(key) == origin.details.get(key) for key in keys)
            and receipt.get("plan_sha256") == (plan.artifact_sha256 if plan else None)
            and receipt.get("effect_sha256") == (effect.sha256 if effect else None)
            and receipt.get("artifact_sha256") == (effect.artifact_sha256 if effect else None)
            and receipt.get("status") == ("admitted" if effect else "denied")
            and (event.kind == "run_admitted") == (effect is not None)
            and (effect is None or event.task_id == effect.task_id), "receipt lineage mismatch")


def postgres_ancestors(graph):
    """Traverse receipt ancestry with native PostgreSQL SQL and a read-only transaction."""
    try:
        import psycopg
        from psycopg.types.json import Jsonb
    except ImportError:
        raise Denied("PostgreSQL observer requires requirements-postgres.lock") from None
    require(graph["receipt"] is not None, "PostgreSQL traversal requires a terminal receipt")
    query = Path(__file__).with_name("postgres_lineage.sql").read_text(encoding="utf-8")
    try:
        with psycopg.connect(connect_timeout=5, options="-c search_path=pg_catalog -c statement_timeout=5000") as conn:
            conn.execute("SET TRANSACTION READ ONLY")
            return conn.execute(query, (Jsonb(graph["nodes"]), Jsonb(graph["edges"]),
                                        graph["receipt"]["sequence"])).fetchone()[0]
    except psycopg.Error:
        raise Denied("PostgreSQL lineage query failed") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--expect-receipt", help="Receipt SHA-256 from a trusted independent copy")
    parser.add_argument("--postgres", action="store_true", help="Traverse the receipt graph using libpq environment settings")
    args = parser.parse_args()
    try:
        graph = observe(args.ledger, args.expect_receipt)
        if args.postgres:
            graph["postgres_ancestors"] = postgres_ancestors(graph)
        print(wire(graph).decode())
    except (Denied, OSError, sqlite3.Error, KeyError, TypeError):
        sys.exit("Lineage observation denied")


if __name__ == "__main__":
    main()
