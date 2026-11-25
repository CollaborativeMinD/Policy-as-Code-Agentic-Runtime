"""Execute a policy-bound task graph using provider-neutral byte interfaces."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
import heapq
import json
from pathlib import Path
import tomllib


from pydantic import ValidationError
from pyrsistent import pmap

from resilience_gate import CallWindow, TransientFailure, WindowClosed
from runtime_codec import Denied, decode, digest, require, wire
from run_ledger import RunLedger
from workflow_contracts import PlanSpec, PolicySpec, RequestSpec, Resilience


def validate(model, value, label):
    try:
        return model.model_validate(value)
    except ValidationError:
        raise Denied(f"invalid {label} declaration") from None


def unique(values, label):
    require(len(set(values)) == len(values), f"duplicate {label}")
    return tuple(values)


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
    resilience: Resilience
    effect: str


def load_policy(path: Path) -> Policy:
    with path.open("rb") as source:
        raw = source.read(65_537)
    require(len(raw) <= 65_536, "TOML exceeds policy file limit")
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except ValueError:
        raise Denied("invalid TOML policy") from None

    config = validate(PolicySpec, parsed, "policy")
    final = config.final_profile
    require(final in config.profiles, "undeclared final profile")
    final_checks = unique(config.final_checks, "final check")
    require(set(unique(config.resilience.replay_profiles, "replay profile")) <= config.profiles.keys(),
            "undeclared replay profile")
    profiles = {}
    for name, definition in config.profiles.items():
        for alias, source in definition.inputs.items():
            kind, _, key = source.partition(".")
            require(kind == "request" or (key in config.profiles and key != final),
                    f"invalid source for {name}.{alias}")
        checks = unique(definition.checks, "task check")
        require(not set(checks).intersection(final_checks), "final check used as a task check")
        profiles[name] = Profile(definition.objective, tuple(definition.rules),
                                 pmap(definition.inputs), checks)
    return Policy(digest(raw), config.policy_id, config.generation, final, final_checks,
                  pmap(config.limits.model_dump()), pmap(profiles), config.resilience, config.effect)


@dataclass(frozen=True)
class Task:
    profile: str
    after: tuple[str, ...]
    inputs: Mapping[str, str]
    requirements: tuple[str, ...]


def _validate_request(request, policy):
    request = validate(RequestSpec, request, "request")
    for requirement in request.requirements.values():
        required = unique(requirement.profiles, "required profile")
        require(set(required) <= set(policy.profiles), "unknown required profile")
    return request.model_dump()


def _validate_plan(proposal, request, policy):
    rows = validate(PlanSpec, proposal, "plan").tasks
    require(len(rows) <= policy.limits["task_count"], "invalid task count")
    tasks = {}
    finals = []
    requirements = request["requirements"]
    for name, row in rows.items():
        profile = row.profile
        require(profile in policy.profiles, "undeclared task profile")
        after = unique(row.after, "predecessor")
        require(len(after) <= policy.limits["predecessor_count"], "too many predecessors")
        require(set(after) <= rows.keys(), "undeclared predecessor")
        covered = unique(row.requirements, "task requirement")
        required = {key for key, spec in requirements.items() if profile in spec["profiles"]}
        require(required == set(covered), f"invalid requirement scope at {name}")
        require(set(row.inputs) == set(policy.profiles[profile].inputs), "unexpected input bindings")
        tasks[name] = Task(profile, after, pmap(row.inputs), covered)
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
    return pmap(tasks), final, scheduler


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
        checks: Mapping[str, Check], evidence_dir: Path, *, replay_safe: bool = False,
        violation_deadline_ns: Callable[[], int] | None = None) -> bytes:
    """Create one run in a new directory and return its final admitted JSON artifact."""
    registry = dict(checks)
    required_checks = set(policy.final_checks)
    required_checks.update(name for profile in policy.profiles.values() for name in profile.checks)
    require(all(callable(registry.get(name)) for name in required_checks), "unbound admission check")
    require(type(replay_safe) is bool, "invalid replay authority")
    window = CallWindow(policy.resilience, violation_deadline_ns)
    with RunLedger(evidence_dir, policy.policy_id, policy.generation, policy.sha256, policy.effect) as ledger:
        record = ledger.record
        active = None
        request_hash = (digest(request_wire) if type(request_wire) is bytes
                        and len(request_wire) <= policy.limits["request_bytes"] else None)
        plan_hash = None
        record("run_started", run_id=ledger.run_id, policy_id=policy.policy_id,
               policy_sha256=policy.sha256, generation=policy.generation, request_sha256=request_hash)
        try:
            request = _validate_request(decode(request_wire, policy.limits["request_bytes"], "request"), policy)
            planner_packet = _planner_packet(policy, request)
            require(len(planner_packet) <= policy.limits["planner_packet_bytes"], "planner packet exceeds limit")
            record("planning_started", request_sha256=request_hash,
                   planner_packet_bytes=len(planner_packet), planner_packet_sha256=digest(planner_packet))
            plan_wire = _guarded_call(window, decompose, planner_packet, record, stage="plan")
            plan = decode(plan_wire, policy.limits["plan_bytes"], "plan")
            tasks, final, scheduler = _validate_plan(plan, request, policy)
            plan_artifact = wire(plan)
            window.admit(policy.resilience.reserve_ns)
            plan_hash = digest(plan_artifact)
            record("plan_admitted", plan_sha256=plan_hash, task_count=len(tasks),
                   final_task=final, artifact=plan_artifact)

            queue = list(scheduler.get_ready())
            heapq.heapify(queue)
            accepted = pmap()
            while queue:
                active = heapq.heappop(queue)
                task = tasks[active]
                packet = _task_packet(active, task, policy, request, accepted)
                require(len(packet) <= policy.limits["prompt_bytes"], "task prompt exceeds limit")
                profile = policy.profiles[task.profile]
                sources = {alias: target for alias, target in task.inputs.items()
                           if profile.inputs[alias].startswith("task.")}
                request_sources = {alias: target for alias, target in task.inputs.items() if alias not in sources}
                record("task_dispatched", task_id=active, profile=task.profile,
                       prompt_bytes=len(packet), prompt_sha256=digest(packet),
                       predecessors=task.after, artifact_sources=sources, request_sources=request_sources,
                       artifact_inputs={alias: digest(accepted[target]) for alias, target in sources.items()})
                output = _guarded_call(window, execute, packet, record, stage="task",
                                       task_id=active,
                                       replay_safe=replay_safe and task.profile in policy.resilience.replay_profiles)
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
                window.admit(policy.resilience.reserve_ns)
                record("task_admitted", task_id=active, artifact=artifact, checks=check_names,
                       artifact_sha256=digest(artifact))
                accepted = accepted.set(active, artifact)
                scheduler.done(active)
                for ready in scheduler.get_ready():
                    heapq.heappush(queue, ready)
                active = None
            require(len(accepted) == len(tasks), "incomplete task graph")
            active = final
            window.admit(policy.resilience.reserve_ns)
            ledger.receipt(task_id=final, request_sha256=request_hash, plan_sha256=plan_hash,
                           artifact=accepted[final])
            return accepted[final]
        except WindowClosed as error:
            record("window_closed", task_id=active, **error.evidence)
            ledger.receipt(task_id=active, request_sha256=request_hash, plan_sha256=plan_hash, reason=str(error))
            raise Denied(str(error)) from None
        except Denied as error:
            ledger.receipt(task_id=active, request_sha256=request_hash, plan_sha256=plan_hash, reason=str(error))
            raise


def _guarded_call(window, operation, packet, record, *, stage, task_id=None, replay_safe=False):
    class CallbackFailed(Exception):
        pass

    def record_attempt(kind, **details):
        record(kind, task_id=task_id, stage=stage, **details)

    def invoke(payload):
        try:
            return operation(payload)
        except TransientFailure:
            raise
        except Exception:
            raise CallbackFailed from None

    try:
        return window.call(invoke, packet, record_attempt, replay_safe=replay_safe)
    except (TransientFailure, CallbackFailed):
        raise Denied("decomposer failed" if stage == "plan" else "executor failed") from None


def _call(callback, payload, failure):
    try:
        return callback(payload)
    except Exception:
        raise Denied(failure) from None
