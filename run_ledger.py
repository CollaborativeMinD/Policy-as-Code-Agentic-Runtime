"""Durable effect and receipt transaction, with a verifiable event chain."""

from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
from time import time_ns
from uuid import uuid4

from runtime_codec import Denied, digest, require, wire


EMPTY_HASH = "0" * 64
TERMINAL = {"run_admitted", "run_denied"}


def event_digest(sequence, kind, task_id, details, previous, artifact_hash):
    return digest(wire({
        "sequence": sequence, "kind": kind, "task_id": task_id, "details": details,
        "previous_sha256": previous, "artifact_sha256": artifact_hash,
    }))


class RunLedger:
    def __init__(self, directory: Path, policy_id, generation, policy_sha256, effect):
        self.directory = directory
        self.policy_id = policy_id
        self.generation = generation
        self.policy_sha256 = policy_sha256
        self.effect = effect
        self.run_id = str(uuid4())
        self.sequence = 0
        self.previous = EMPTY_HASH

    def __enter__(self):
        self.directory.mkdir(mode=0o700)
        self.connection = sqlite3.connect(self.directory / "run.sqlite")
        try:
            self.connection.execute("PRAGMA synchronous = FULL")
            self.connection.execute("PRAGMA trusted_schema = OFF")
            self.connection.execute("PRAGMA user_version = 2")
            self.connection.execute("""CREATE TABLE events (
                sequence INTEGER PRIMARY KEY, kind TEXT NOT NULL, task_id TEXT,
                details TEXT NOT NULL, artifact BLOB,
                prev_sha256 TEXT NOT NULL, event_sha256 TEXT NOT NULL UNIQUE
            ) STRICT""")
        except BaseException:
            self.connection.close()
            raise
        return self

    def __exit__(self, *exc_info):
        self.connection.close()

    def _append(self, kind, task_id, artifact, details):
        sequence = self.sequence + 1
        artifact_hash = digest(artifact) if artifact is not None else None
        details = {"observed_at_ns": time_ns(), **details}
        current = event_digest(sequence, kind, task_id, details, self.previous, artifact_hash)
        self.connection.execute(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (sequence, kind, task_id, wire(details).decode(), artifact, self.previous, current),
        )
        self.sequence, self.previous = sequence, current
        return current

    def record(self, kind, *, task_id=None, artifact=None, **details):
        with self.connection:
            return self._append(kind, task_id, artifact, details)

    def receipt(self, *, task_id, request_sha256, plan_sha256, artifact=None, reason=None):
        status = "admitted" if artifact is not None else "denied"
        with self.connection:
            effect_hash = None
            if artifact is not None:
                effect_hash = self._append("effect_committed", task_id, artifact, {
                    "effect": self.effect, "artifact_sha256": digest(artifact),
                })
            return self._append(f"run_{status}", task_id, None, {
                "receipt_version": 1, "run_id": self.run_id, "status": status,
                "policy_id": self.policy_id, "generation": self.generation,
                "policy_sha256": self.policy_sha256, "request_sha256": request_sha256,
                "plan_sha256": plan_sha256, "effect_sha256": effect_hash, "reason": reason,
                "artifact_sha256": digest(artifact) if artifact is not None else None,
            })


@dataclass(frozen=True)
class Event:
    sequence: int
    kind: str
    task_id: str | None
    details: dict
    artifact_sha256: str | None
    sha256: str


def read_verified(path: Path, expected_receipt: str | None = None) -> tuple[Event, ...]:
    """Read a snapshot of a local ledger and optionally authenticate its receipt digest."""
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    events = []
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        require(connection.execute("PRAGMA user_version").fetchone() == (2,), "unsupported ledger schema")
        previous = EMPTY_HASH
        for sequence, kind, task_id, raw, artifact, prev, claimed in connection.execute("""
            SELECT sequence, kind, task_id, details, artifact, prev_sha256, event_sha256
            FROM events ORDER BY sequence
        """):
            require(sequence == len(events) + 1 and prev == previous, "broken ledger sequence")
            details = json.loads(raw)
            require(isinstance(details, dict) and wire(details).decode() == raw, "invalid event details")
            artifact_hash = digest(artifact) if artifact is not None else None
            require(event_digest(sequence, kind, task_id, details, prev, artifact_hash) == claimed,
                    "event digest mismatch")
            events.append(Event(sequence, kind, task_id, details, artifact_hash, claimed))
            previous = claimed
    except (sqlite3.Error, TypeError, ValueError) as error:
        if isinstance(error, Denied):
            raise
        raise Denied("invalid ledger") from None
    finally:
        connection.close()
    require(events and events[0].kind == "run_started", "missing run origin")
    require(all(event.kind not in TERMINAL for event in events[:-1]), "events follow terminal receipt")
    if expected_receipt is not None:
        require(events[-1].kind in TERMINAL and expected_receipt == events[-1].sha256,
                "receipt digest mismatch")
    return tuple(events)
