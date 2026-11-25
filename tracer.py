"""First vertical slice. Run this with Python 3.11 or later."""

import json
from graphlib import TopologicalSorter
from pathlib import Path
import tomllib


def run(reject=False, extra=0):
    policy = tomllib.loads(Path(__file__).with_name("tracer.toml").read_text())
    tasks = policy["task"]
    graph = {name: spec["after"] for name, spec in tasks.items()}
    graph.update({f"side-{index:04}": [] for index in range(extra)})
    scheduler = TopologicalSorter(graph)
    scheduler.prepare()
    ready = set()
    artifacts = {}
    trace = []
    for _ in graph:
        ready.update(scheduler.get_ready())
        name = min(ready)
        ready.remove(name)
        spec = tasks.get(name, {"rule": "Return the integer 0", "after": [], "expected": 0})
        packet = {
            "id": name, "rule": spec["rule"],
            "inputs": {key: artifacts[key] for key in spec["after"]},
        }
        wire = json.dumps(packet, sort_keys=True).encode()
        trace.append({"task": name, "bytes": len(wire), "inputs": list(packet["inputs"])})
        if name == "01":
            output = "wrong type" if reject else 2
        else:
            output = sum(packet["inputs"].values()) + (1 if name == "02" else 0)
        accepted = type(output) is int and output == spec["expected"]
        trace[-1]["decision"] = "admit" if accepted else "deny"
        if not accepted:
            break
        artifacts[name] = output
        scheduler.done(name)
    return trace


if __name__ == "__main__":
    baseline, denied, large = run(), run(reject=True), run(extra=512)
    if [(item["task"], item["decision"]) for item in baseline] != [("01", "admit"), ("02", "admit")]:
        raise RuntimeError("Admission did not release the successor")
    if [item["task"] for item in denied] != ["01"] or denied[0]["decision"] != "deny":
        raise RuntimeError("Denial did not block the successor")
    if large[:2] != baseline or len(large) != 514:
        raise RuntimeError("Unrelated branches changed the scoped prompts")
    print(json.dumps({"baseline": baseline, "denied": denied, "large_plan_tasks": len(large),
                      "large_plan_matching_prefix": large[:2]}, indent=2))
