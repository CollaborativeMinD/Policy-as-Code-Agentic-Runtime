"""Run the native inventory chain with its checks, final reconciliation and ledger."""
from hashlib import sha256
import json
from pathlib import Path

from inventory_demo import CHECKS, decompose, execute as worker
from task_chain import load_policy, run, wire

TITLE = "Agentic Runtime"
OPERATIONS = {"inventory.run"}
REQUEST = Path(__file__).resolve().parents[1] / "inventory_request.json"


def validate(binding, inputs):
    if not isinstance(inputs, dict) or set(inputs) != {"quantity"} or type(inputs["quantity"]) is not int or not 0 <= inputs["quantity"] <= 1000000:
        raise ValueError("quantity must be an integer from zero through one million")


def snapshot(binding):
    policy = load_policy(binding["source"])
    raw = REQUEST.read_bytes()
    stamp = sha256(policy.sha256.encode() + raw).hexdigest()
    return policy, raw, stamp


def observe(binding):
    policy, _, stamp = snapshot(binding)
    return stamp, f"{policy.policy_id} · generation {policy.generation} · {len(policy.profiles)} profiles"


def execute(binding, inputs, directory, receipt_id, revision):
    policy, raw, stamp = snapshot(binding)
    if stamp != revision:
        raise ValueError("Workflow or request changed")
    request = json.loads(raw)
    request["inputs"]["records"][0]["quantity"] = inputs["quantity"]
    output = run(policy, wire(request), decompose, worker, CHECKS, directory / receipt_id, replay_safe=True)
    return {"artifact": json.loads(output), "ledger_directory": receipt_id, "policy_sha256": policy.sha256}
