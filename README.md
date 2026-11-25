# Policy-as-Code Agentic Runtime

The orchestrator holds the complete request and dependency graph. For each task it injects the applicable TOML rules, the requirements assigned to that task, and the explicitly bound inputs. It dispatches one task at a time. A committed admission record releases the task’s successors.

## Run locally

Python 3.11 or later. The runtime and witness use the standard library.

```sh
python tracer.py
python -W error -m unittest -v
python inventory_demo.py local-inventory-run
```

The inventory example normalizes receipts, branches into totals and zero-quantity detection, then joins the two admitted artifacts. The final verifier rechecks the report against the original request. The CLI prints the final admitted JSON and saves the run in `local-inventory-run/run.sqlite`. Choose a new directory for each run.

## Policy and execution

| Input or interface | Responsibility |
| --- | --- |
| [`workflow_policy.toml`](workflow_policy.toml) | Operator-owned policy with version, generation, prompt rules, input bindings, size limits, and registered admission checks. |
| [`inventory_request.json`](inventory_request.json) | Caller-owned input values and authoritative requirement manifest. Each requirement ID declares text and the profiles that must receive it. |
| `decompose(packet: bytes) -> bytes` | Proposes a graph using the admitted profiles. Receives the structured request and planning rules. |
| `execute(packet: bytes) -> bytes` | Receives one task packet and returns a JSON object. An integration can dispatch the packet to a fresh model call. |
| `checks` | Application-owned callable registry. Named checks return literal `True` to admit an output. Run-level final checks also receive the original request. |

A proposed task declares a profile, direct predecessors in `after`, an input binding for every alias in the profile, and the exact requirement IDs assigned to that profile. A `request.` input may bind only the declared request field. A `task.` input may bind only a direct predecessor with the declared profile. Control dependencies can release a task without transferring an artifact. The runtime rejects cycles, unknown names, missing requirement coverage, and tasks outside the final dependency graph.

The runtime uses the lexically smallest ready task ID. The SQLite ledger records dispatch before calling the executor and commits the admitted artifact before advancing the graph. A denial stops the run. The ledger holds the canonical plan and accepted artifacts, plus the policy generation, SHA-256 hashes, prompt sizes, bindings by artifact hash, and check names. SHA-256 supports comparison against a trusted copy. Treat the ledger as sensitive when the accepted artifacts contain private data.

## Verification scope

The standalone tracer verifies that two packets keep their original size when 512 independent tasks are added. It also verifies that a rejected predecessor prevents its successor from running. The full runtime tests cover deterministic dispatch, scoped inputs, validation errors, prompt and output limits, committed admissions, and rejection at final reconciliation. Forgejo qualifies the exact checked-out SHA and publishes the test log, tracer, inventory result, and SQLite witness.

The checked-in runs use deterministic inventory callbacks against a structured requirement manifest. Model integrations supply their own intent capture, decomposition, isolated execution, and verifiers for the request semantics. The supplied policy measures UTF-8 bytes and deterministically schedules a validated graph. Model quality, token counts, and tool side effects require separate verification. Start a new run after interruption and use the prior ledger for inspection.

The implementation follows the storage adapter’s operator-declared configuration, Telemetry-to-Iceberg’s strict typed policy and evidence, and HMT DevSecOps’ binding of validated policy to recognized runtime behavior. [Storage policy](https://github.com/CollaborativeMinD/Telemetry-Storage-Adapter-/blob/a7eee2f586e884fb0ec35308780164c8ef2b4b8e/config/storage_policy.toml) · [Telemetry-to-Iceberg policy](https://github.com/CollaborativeMinD/Telemetry-To-Iceberg-Stream/blob/192d04eb4766e5954e33ad511aa6ef2ec9ca8fd6/telemetry_iceberg_stream/policy.py) · [HMT policy](https://github.com/CollaborativeMinD/HMT-DevSecOPs-lib/blob/4f0624b2d5314005261f75391d390aa4a7c27d87/src/hmt_devsecops/policy.py)
