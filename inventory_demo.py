"""Offline inventory workflow and trusted checks for the example policy."""

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from task_chain import Denied, load_policy, require, run, wire


ROOT = Path(__file__).resolve().parent
EXPECTED_REQUIREMENTS = {
    "normalize_locations": {
        "text": "Trim and uppercase each location without dropping rows.",
        "profiles": ["normalize"],
    },
    "count_inventory": {
        "text": "Return the total inventory quantity at each normalized location.",
        "profiles": ["count"],
    },
    "report_exceptions": {
        "text": "Include every zero-quantity record ID in lexical order.",
        "profiles": ["flag"],
    },
}


def decompose(packet):
    requirements = json.loads(packet)["request"]["requirements"]
    require(requirements == EXPECTED_REQUIREMENTS, "unsupported inventory requirement manifest")
    tasks = {}
    definitions = {
        "task_01_normalize": ("normalize", [], {"records": "records"}),
        "task_02_count": ("count", ["task_01_normalize"], {"receipt": "task_01_normalize"}),
        "task_03_flag": ("flag", ["task_01_normalize"], {"receipt": "task_01_normalize"}),
        "task_04_report": ("report", ["task_02_count", "task_03_flag"],
                           {"counts": "task_02_count", "exceptions": "task_03_flag"}),
    }
    for name, (profile, after, inputs) in definitions.items():
        coverage = [key for key, spec in requirements.items() if profile in spec["profiles"]]
        tasks[name] = {
            "profile": profile, "after": after, "inputs": inputs,
            "requirements": coverage,
        }
    return wire({"tasks": tasks})


def normalize(inputs):
    return {"rows": [row | {"location": row["location"].strip().upper()} for row in inputs["records"]]}


def count(inputs):
    totals = {}
    for row in inputs["receipt"]["rows"]:
        location = row["location"]
        totals[location] = totals.get(location, 0) + row["quantity"]
    return {"location_totals": totals}


def flag(inputs):
    return {"zero_quantity_rows": sorted(row["id"] for row in inputs["receipt"]["rows"] if row["quantity"] == 0)}


def report(inputs):
    return inputs["counts"] | inputs["exceptions"]


def execute(packet):
    task = json.loads(packet)
    handlers = {"normalize": normalize, "count": count, "flag": flag, "report": report}
    return wire(handlers[task["profile"]](task["inputs"]))


def normalized_receipt(context):
    records = json.loads(context.prompt)["inputs"]["records"]
    rows = json.loads(context.output).get("rows")
    if type(records) is not list or type(rows) is not list or len(rows) != len(records):
        return False
    ids = set()
    for raw, row in zip(records, rows):
        if (type(raw) is not dict or raw.keys() != {"id", "location", "quantity"}
                or type(raw["id"]) is not str or not raw["id"] or raw["id"] in ids
                or type(raw["location"]) is not str or not raw["location"].strip()
                or type(raw["quantity"]) is not int or raw["quantity"] < 0):
            return False
        ids.add(raw["id"])
        if wire(row) != wire(raw | {"location": raw["location"].strip().upper()}):
            return False
    return context.output == wire({"rows": rows})


def location_totals(context):
    rows = json.loads(context.prompt)["inputs"]["receipt"]["rows"]
    expected = {location: sum(row["quantity"] for row in rows if row["location"] == location)
                for location in {row["location"] for row in rows}}
    return context.output == wire({"location_totals": expected})


def zero_quantity_rows(context):
    rows = json.loads(context.prompt)["inputs"]["receipt"]["rows"]
    expected = sorted(row["id"] for row in rows if row["quantity"] == 0)
    return context.output == wire({"zero_quantity_rows": expected})


def report_assembly(context):
    parts = json.loads(context.prompt)["inputs"]
    return context.output == wire(parts["counts"] | parts["exceptions"])


def original_request_reconciliation(context):
    request = json.loads(context.request)
    if request["requirements"] != EXPECTED_REQUIREMENTS:
        return False
    rows = request["inputs"]["records"]
    totals = Counter()
    for row in rows:
        totals[row["location"].strip().upper()] += row["quantity"]
    expected = {"location_totals": dict(totals),
                "zero_quantity_rows": sorted(row["id"] for row in rows if row["quantity"] == 0)}
    return context.output == wire(expected)


CHECKS = {
    "normalized_receipt": normalized_receipt,
    "location_totals": location_totals,
    "zero_quantity_rows": zero_quantity_rows,
    "report_assembly": report_assembly,
    "original_request_reconciliation": original_request_reconciliation,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence_dir", type=Path, help="New directory for the run ledger")
    parser.add_argument("--policy", type=Path, default=ROOT / "workflow_policy.toml")
    parser.add_argument("--request", type=Path, default=ROOT / "inventory_request.json")
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        with args.request.open("rb") as source:
            request = source.read(policy.limits["request_bytes"] + 1)
        # This deterministic example supports the inventory request contract.
        result = run(policy, request, decompose, execute, CHECKS, args.evidence_dir)
    except (Denied, OSError) as error:
        sys.exit(str(error))
    print(result.decode())


if __name__ == "__main__":
    main()
