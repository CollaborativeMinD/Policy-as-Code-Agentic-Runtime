# Policy-as-Code Agentic Runtime

The orchestrator holds the complete request and dependency graph. For each task it injects the applicable TOML rules, the requirements assigned to that task, and the explicitly bound inputs. It dispatches one task at a time. A committed admission record releases the task’s successors.

## Run locally

The wheel lock targets CPython 3.11 through 3.14 on Windows AMD64 and glibc Linux x86-64.

```sh
python -m pip install -r requirements.lock
python tracer.py
python -W error -m unittest -v
python inventory_demo.py local-inventory-run
python lineage_observe.py local-inventory-run/run.sqlite
```

The inventory example normalizes receipts, branches into totals and zero-quantity detection, then joins the two admitted artifacts. The final verifier rechecks the report against the original request. The CLI prints the final admitted JSON and saves the run in `local-inventory-run/run.sqlite`. Choose a new directory for each run.

## Policy and execution

| Input or interface | Responsibility |
| --- | --- |
| [`workflow_policy.toml`](workflow_policy.toml) | Operator-owned policy with version, generation, prompt rules, input bindings, size limits, retry authority, and registered admission checks. |
| [`inventory_request.json`](inventory_request.json) | Caller-owned input values and authoritative requirement manifest. Each requirement ID declares text and the profiles that must receive it. |
| `decompose(packet: bytes) -> bytes` | Proposes a graph using the admitted profiles. Receives the structured request and planning rules. |
| `execute(packet: bytes) -> bytes` | Receives one task packet and returns a JSON object. An integration can dispatch the packet to a fresh model call. |
| `checks` | Application-owned callable registry. Named checks return literal `True` to admit an output. Run-level final checks also receive the original request. |

A proposed task declares a profile, direct predecessors in `after`, an input binding for every alias in the profile, and the exact requirement IDs assigned to that profile. A `request.` input may bind only the declared request field. A `task.` input may bind only a direct predecessor with the declared profile. Control dependencies can release a task without transferring an artifact. The runtime rejects cycles, unknown names, missing requirement coverage, and tasks outside the final dependency graph.

Pydantic validates TOML, request manifests, and planner output with strict types and forbidden unknown fields. The runtime freezes validated policy and per-task bindings with pyrsistent collections. It uses the lexically smallest ready task ID and commits each admitted artifact to SQLite before advancing the graph.

## Resilience and effect admission

Tenacity retries only an adapter-raised `TransientFailure` when the task profile appears in `resilience.replay_profiles` and the caller explicitly passes `replay_safe=True`. Each retry uses the same packet. Planning gets one attempt. Invalid responses and failed admission checks stop the run. The shared monotonic window reserves time for the bounded attempt, backoff, fallback, and uncertainty. An optional caller-supplied deadline listener can tighten the window in the same clock domain. The guard runs before sleep, before callback dispatch, and after return. It detects synchronous overruns after control returns.

The only published effect is the admitted final JSON artifact. The runtime commits that effect and its receipt in one SQLite transaction. A policy denial produces a terminal receipt with no effect. After an interrupted run, inspect the ledger for a terminal receipt before starting a fresh run. Keep executor callbacks limited to replay-safe work when authorizing retries. The runtime has no cancellation mechanism for synchronous callbacks and no reconciliation protocol for their external side effects.

The timing rules follow `tenacity_stopping_conditions.py` and the qualification notes in the supplied `resilience_ooda.zip`. Archive SHA-256 `12efdb7f80c8ee2bdc3561e01bb2fd63ca03ab51f1d2eb5b156c92f6632369dc`. The checked-in nanosecond thresholds qualify the local witness. Deployment requires bounds measured for its own callbacks and fallback.

## Inspect origin, transforms, effect, and receipt

`lineage_observe.py` verifies the ordered event hash chain, admitted predecessor artifact hashes, and the links from the original request and policy generation through the plan, transforms, effect, and receipt. It exports timing and retry evidence, prompt sizes, check names, and hashes. It keeps prompt text, raw inputs, accepted artifacts, and adapter exception messages out of the projection.

Capture the receipt SHA-256 in a trusted independent location and pass it back with `--expect-receipt` to detect replacement of the entire ledger. Without a receipt pin the chain reports its internal consistency. Keep the SQLite directory private because it contains admitted artifacts. The observer reads the new ledger format created by this revision.

### PostgreSQL traversal

Use the optional PostgreSQL lock and configure libpq with `PGHOST`, `PGPORT`, `PGDATABASE`, and `PGUSER`, plus your usual credential mechanism. This observer sends a redacted graph as query parameters, then uses a read-only transaction and a fixed `WITH RECURSIVE` query to return the terminal receipt’s ancestors. It requires only a login with access to the database and native PostgreSQL JSON and SQL functions. [PostgreSQL recursive queries](https://www.postgresql.org/docs/18/queries-with.html)

```sh
python -m pip install -r requirements-postgres.lock
python lineage_observe.py local-inventory-run/run.sqlite --postgres
python verify_postgres.py
```

`verify_postgres.py` uses Docker to start a disposable, loopback-only PostgreSQL fixture with a non-superuser observer and tears it down after the suite.

## Verification scope

The standalone tracer verifies that two packets keep their original size when 512 independent tasks are added. The runtime tests cover scoped execution, fail-closed admission, retry limits and deadline tightening, effect rollback, ledger tampering, and final reconciliation. Forgejo installs the locked dependency set and publishes the test log, tracer, inventory result, lineage projection, and SQLite witness for the qualified commit. The Docker witness exercises the native PostgreSQL traversal separately.

The checked-in runs use deterministic inventory callbacks against a structured requirement manifest. Model integrations supply their own intent capture, decomposition, isolated execution, and verifiers for the request semantics. The supplied policy measures UTF-8 bytes and deterministically schedules a validated graph. Model quality, token counts, and tool side effects require separate verification.

## Install and deploy a qualified release

Forgejo builds the sdist and wheel on Linux and native Windows. Each job installs the wheel into a fresh environment and uses it to publish a result and verify its receipt. The AMD64 and ARM64 Compose jobs build images from the pinned [deployment policy](deployment.toml), run the writer and observer, and trace the receipt through PostgreSQL. They publish the image archive, rendered Compose file, and signed witness. [Forgejo workflow](.forgejo/workflows/distribution.yml)

To install a Python release, use its wheel in a dedicated virtual environment. Install the locked dependencies first.

```sh
python -m pip install -r requirements-postgres.lock
python -m pip install --no-deps ./policy_as_code_agentic_runtime-0.2.0-py3-none-any.whl
prompt-chain-run local-inventory
prompt-chain-observe local-inventory/run.sqlite
```

Load the image archive for your Linux architecture with `docker image load -i <archive>`. Use the image tag in its signed `verification.json`. Render the same deployment policy into a new directory, then run the writer and read-only observer against their shared volume.

```sh
python deploy_common.py render --platform linux/amd64 --image <qualified-image-tag> --output local-deploy
docker compose -f local-deploy/compose.json run --rm writer /state/inventory
docker compose -f local-deploy/compose.json run --rm observer /state/inventory/run.sqlite
```

The `postgres` profile adds a database on an internal network. It publishes no host port. Set `LINEAGE_PASSWORD` in the deployment environment and provision a non-superuser `lineage_reader` before invoking the observer with `--postgres`. The qualification job provisions its own disposable credentials and removes its test volumes.

The implementation follows the storage adapter’s operator-declared configuration, Telemetry-to-Iceberg’s strict typed policy and evidence, and HMT DevSecOps’ binding of validated policy to recognized runtime behavior. [Storage policy](https://github.com/CollaborativeMinD/Telemetry-Storage-Adapter-/blob/a7eee2f586e884fb0ec35308780164c8ef2b4b8e/config/storage_policy.toml) · [Telemetry-to-Iceberg policy](https://github.com/CollaborativeMinD/Telemetry-To-Iceberg-Stream/blob/192d04eb4766e5954e33ad511aa6ef2ec9ca8fd6/telemetry_iceberg_stream/policy.py) · [HMT policy](https://github.com/CollaborativeMinD/HMT-DevSecOPs-lib/blob/4f0624b2d5314005261f75391d390aa4a7c27d87/src/hmt_devsecops/policy.py)

## Live operator console

Use the [console guide](Console.md) to observe inventory, publish scoped TOML changes, run admitted tasks and verify their receipts.

## From policy change to release

Start with [workflow_policy.toml](workflow_policy.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `python -B -m unittest -v` in the project environment. Exercise the normal entry point and the denial. Review the final inventory artifact and task ledger. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.
