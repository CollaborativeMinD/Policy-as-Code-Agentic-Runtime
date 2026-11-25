# Operator runbook

## From policy change to release

Start with [workflow_policy.toml](workflow_policy.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `python -B -m unittest -v` in the project environment. Exercise the normal entry point and the denial. Review the final inventory artifact and task ledger. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.

The version 2 `[runtime]` table in `console.toml` sets request size, concurrency and client deadlines. Version 1 files inherit the shipped budget. Reissue them as version 2 to pin these choices in the admitted document.
