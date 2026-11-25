"""Execute a policy-bound task graph using provider-neutral byte interfaces."""

from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
from hashlib import sha256
import heapq
import json
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
import tomllib


class Denied(ValueError):
    """An input or runtime transition failed admission."""


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def digest(raw):
    return sha256(raw).hexdigest()


def wire(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise Denied("invalid JSON value") from None


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw, limit, label):
    require(type(raw) is bytes and len(raw) <= limit, f"{label} exceeds wire limit or is not bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, RecursionError):
        raise Denied(f"invalid {label} JSON") from None
    wire(value)  # Reject non-finite numbers and invalid Unicode, including escapes.
    return value


def fields(value, expected, label):
    require(type(value) is dict and value.keys() == set(expected), f"unexpected fields in {label}")


def identifier(value):
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value) is not None


def names(value, label, *, nonempty=False):
    require(type(value) is list and all(identifier(item) for item in value)
            and len(set(value)) == len(value) and (value or not nonempty),
            f"invalid {label} list")
    return tuple(value)


def declaration(value):
    return type(value) is str and bool(value.strip())


@dataclass(frozen=True)
class Profile:
    objective: str
    rules: tuple[str, ...]
    inputs: Mapping[str, str]
    checks: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    sha256: str
    policy_id: str
    generation: int
    final_profile: str
    final_checks: tuple[str, ...]
    limits: Mapping[str, int]
    profiles: Mapping[str, Profile]


LIMIT_BOUNDS = {
    "request_bytes": 1_048_576,
    "planner_packet_bytes": 2_097_152,
    "plan_bytes": 1_048_576,
    "task_count": 4096,
    "predecessor_count": 64,
    "prompt_bytes": 262_144,
    "output_bytes": 262_144,
}


def load_policy(path: Path) -> Policy:
    with path.open("rb") as source:
        raw = source.read(65_537)
    require(len(raw) <= 65_536, "TOML exceeds policy file limit")
    try:
        config = tomllib.loads(raw.decode("utf-8"))
    except ValueError:
        raise Denied("invalid TOML policy") from None
    fields(config, ("version", "policy_id", "generation", "final_profile", "final_checks",
                    "limits", "profiles"), "policy")
    require(type(config["version"]) is int and config["version"] == 1, "unsupported policy version")
    require(identifier(config["policy_id"]), "invalid policy id")
    generation = config["generation"]
    require(type(generation) is int and generation >= 0, "invalid policy generation")
    limits = config["limits"]
    fields(limits, LIMIT_BOUNDS, "limits")
    for name, maximum in LIMIT_BOUNDS.items():
        require(type(limits[name]) is int and 1 <= limits[name] <= maximum, f"invalid {name} limit")

    definitions = config["profiles"]
    require(type(definitions) is dict and definitions and all(map(identifier, definitions)), "invalid profiles")
    final = config["final_profile"]
    require(identifier(final) and final in definitions, "undeclared final profile")
    final_checks = names(config["final_checks"], "final checks", nonempty=True)
    profiles = {}
    for name, definition in definitions.items():
        fields(definition, ("objective", "rules", "inputs", "checks"), f"profile {name}")
        objective, rules, inputs = (definition[key] for key in ("objective", "rules", "inputs"))
        require(declaration(objective), "invalid objective")
        require(type(rules) is list and rules and all(map(declaration, rules)), "invalid rules")
        require(type(inputs) is dict and len(inputs) <= 64, "invalid input declarations")
        for alias, source in inputs.items():
            require(identifier(alias) and type(source) is str, "invalid input declaration")
            kind, _, key = source.partition(".")
            require(identifier(key) and (kind == "request" or
                    (kind == "task" and key in definitions and key != final)),
                    f"invalid source for {name}.{alias}")
        checks = names(definition["checks"], f"{name} checks", nonempty=True)
        require(not set(checks).intersection(final_checks), "final check used as a task check")
        profiles[name] = Profile(objective, tuple(rules), MappingProxyType(inputs), checks)
    return Policy(digest(raw), config["policy_id"], generation, final, final_checks,
                  MappingProxyType(limits), MappingProxyType(profiles))


@dataclass(frozen=True)
class Task:
    profile: str
    after: tuple[str, ...]
    inputs: dict[str, str]
    requirements: tuple[str, ...]


def _validate_request(request, policy):
    fields(request, ("inputs", "requirements"), "request")
    require(type(request["inputs"]) is dict and all(map(identifier, request["inputs"])), "invalid request inputs")
    requirements = request["requirements"]
    require(type(requirements) is dict and requirements, "request requires a requirement manifest")
    for name, requirement in requirements.items():
        require(identifier(name), "invalid requirement id")
        fields(requirement, ("text", "profiles"), "requirement")
        require(declaration(requirement["text"]), "invalid requirement text")
        required = names(requirement["profiles"], "required profiles", nonempty=True)
        require(set(required) <= policy.profiles.keys(), "unknown required profile")


def _validate_plan(proposal, request, policy):
    fields(proposal, ("tasks",), "plan")
    rows = proposal["tasks"]
    require(type(rows) is dict and 0 < len(rows) <= policy.limits["task_count"], "invalid task count")
    tasks = {}
    finals = []
    requirements = request["requirements"]
    for name, row in rows.items():
        require(identifier(name), "invalid task id")
        fields(row, ("profile", "after", "inputs", "requirements"), "task")
        profile = row["profile"]
        require(identifier(profile) and profile in policy.profiles, "undeclared task profile")
        after = names(row["after"], "predecessor")
        require(len(after) <= policy.limits["predecessor_count"], "too many predecessors")
        require(set(after) <= rows.keys(), "undeclared predecessor")
        covered = names(row["requirements"], "task requirements")
        require(set(covered) <= requirements.keys(), "undeclared requirement")
        required = {key for key, spec in requirements.items() if profile in spec["profiles"]}
        require(required == set(covered), f"invalid requirement scope at {name}")
        fields(row["inputs"], policy.profiles[profile].inputs, "input bindings")
        tasks[name] = Task(profile, after, row["inputs"], covered)
        if profile == policy.final_profile:
            finals.append(name)

    require(len(finals) == 1, "plan requires exactly one final task")
    final = finals[0]
    used_profiles = {task.profile for task in tasks.values()}
    for spec in requirements.values():
        require(set(spec["profiles"]) <= used_profiles, "plan omits a required profile")
    for task in tasks.values():
        for alias, declaration in policy.profiles[task.profile].inputs.items():
            kind, _, key = declaration.partition(".")
            target = task.inputs[alias]
            require(identifier(target), "invalid input binding")
            if kind == "request":
                require(target == key and key in request["inputs"], "invalid request input binding")
            else:
                require(target in task.after and tasks[target].profile == key, "invalid artifact input binding")

    scheduler = TopologicalSorter({name: task.after for name, task in tasks.items()})
    try:
        scheduler.prepare()
    except CycleError:
        raise Denied("cyclic task plan") from None
    ancestors = {final}
    pending = [final]
    while pending:
        unseen = set(tasks[pending.pop()].after) - ancestors
        pending.extend(unseen)
        ancestors.update(unseen)
    require(ancestors == tasks.keys(), "task outside final dependency graph")
    return tasks, final, scheduler


@dataclass(frozen=True)
class CheckContext:
    prompt: bytes
    output: bytes
    request: bytes | None = None


Worker = Callable[[bytes], bytes]
Check = Callable[[CheckContext], bool]


def _planner_packet(policy, request):
    return wire({
        "request": request,
        "final_profile": policy.final_profile,
        "limits": dict(policy.limits),
        "profiles": {
            name: {"objective": profile.objective, "rules": profile.rules,
                   "inputs": dict(profile.inputs), "checks": profile.checks}
            for name, profile in policy.profiles.items()
        },
    })


def _task_packet(name, task, policy, request, accepted):
    profile = policy.profiles[task.profile]
    inputs = {}
    for alias, source in profile.inputs.items():
        target = task.inputs[alias]
        inputs[alias] = (request["inputs"][target] if source.startswith("request.")
                         else json.loads(accepted[target]))
    return wire({
        "task_id": name,
        "profile": task.profile,
        "objective": profile.objective,
        "rules": profile.rules,
        "checks": profile.checks,
        "requirements": {key: request["requirements"][key]["text"] for key in task.requirements},
        "inputs": inputs,
    })


def run(policy: Policy, request_wire: bytes, decompose: Worker, execute: Worker,
        checks: Mapping[str, Check], evidence_dir: Path) -> bytes:
    """Create one run in a new directory and return its final admitted JSON artifact."""
    registry = dict(checks)
    required_checks = set(policy.final_checks)
    required_checks.update(name for profile in policy.profiles.values() for name in profile.checks)
    require(all(callable(registry.get(name)) for name in required_checks), "unbound admission check")
    evidence_dir.mkdir()
    with closing(sqlite3.connect(evidence_dir / "run.sqlite")) as connection:
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("""CREATE TABLE events (
            sequence INTEGER PRIMARY KEY, kind TEXT NOT NULL, task_id TEXT,
            details TEXT NOT NULL, artifact BLOB
        )""")

        def record(kind, *, task_id=None, artifact=None, **details):
            with connection:
                connection.execute("INSERT INTO events(kind, task_id, details, artifact) VALUES (?, ?, ?, ?)",
                                   (kind, task_id, wire(details).decode(), artifact))

        active = None
        record("run_started", policy_id=policy.policy_id, policy_sha256=policy.sha256,
               generation=policy.generation)
        try:
            request = decode(request_wire, policy.limits["request_bytes"], "request")
            _validate_request(request, policy)
            planner_packet = _planner_packet(policy, request)
            require(len(planner_packet) <= policy.limits["planner_packet_bytes"], "planner packet exceeds limit")
            record("planning_started", request_sha256=digest(request_wire),
                   planner_packet_bytes=len(planner_packet), planner_packet_sha256=digest(planner_packet))
            plan_wire = _call(decompose, planner_packet, "decomposer failed")
            plan = decode(plan_wire, policy.limits["plan_bytes"], "plan")
            tasks, final, scheduler = _validate_plan(plan, request, policy)
            record("plan_admitted", plan_sha256=digest(wire(plan)), task_count=len(tasks), artifact=wire(plan))

            queue = list(scheduler.get_ready())
            heapq.heapify(queue)
            accepted = {}
            while queue:
                active = heapq.heappop(queue)
                task = tasks[active]
                packet = _task_packet(active, task, policy, request, accepted)
                require(len(packet) <= policy.limits["prompt_bytes"], "task prompt exceeds limit")
                record("task_dispatched", task_id=active, profile=task.profile,
                       prompt_bytes=len(packet), prompt_sha256=digest(packet),
                       artifact_inputs={alias: digest(accepted[target])
                                        for alias, target in task.inputs.items()
                                        if policy.profiles[task.profile].inputs[alias].startswith("task.")})
                output = _call(execute, packet, "executor failed")
                value = decode(output, policy.limits["output_bytes"], "output")
                require(type(value) is dict, "task output must be a JSON object")
                artifact = wire(value)
                require(len(artifact) <= policy.limits["output_bytes"], "canonical artifact exceeds limit")
                check_names = policy.profiles[task.profile].checks
                context = CheckContext(packet, artifact)
                for name in check_names:
                    verdict = _call(registry[name], context, f"admission check failed: {name}")
                    require(verdict is True, f"admission check denied: {name}")
                if active == final:
                    context = CheckContext(packet, artifact, request_wire)
                    for name in policy.final_checks:
                        verdict = _call(registry[name], context, f"final check failed: {name}")
                        require(verdict is True, f"final check denied: {name}")
                    check_names += policy.final_checks
                record("task_admitted", task_id=active, artifact=artifact, checks=check_names,
                       artifact_sha256=digest(artifact))
                accepted[active] = artifact
                scheduler.done(active)
                for ready in scheduler.get_ready():
                    heapq.heappush(queue, ready)
                active = None
            require(len(accepted) == len(tasks), "incomplete task graph")
            record("run_admitted", task_id=final, artifact_sha256=digest(accepted[final]))
            return accepted[final]
        except Denied as error:
            record("run_denied", task_id=active, reason=str(error))
            raise


def _call(callback, payload, failure):
    try:
        return callback(payload)
    except Exception:
        raise Denied(failure) from None
