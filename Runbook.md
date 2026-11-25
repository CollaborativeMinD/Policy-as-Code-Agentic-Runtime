# Operator runbook

## From policy change to release

Start with [workflow_policy.toml](workflow_policy.toml) for this component and [console.toml](console.toml) for terminal access. Write down the requested effect and one case that must be denied. Change the TOML first.

1. Apply the candidate to disposable state. An unknown field or unbound operation must fail admission before an effect. Keep that denial.
2. For supported behavior, continue with the existing runtime. For new behavior, implement the missing typed field and the method that enforces it. Run the same candidate again.
3. Run `python -B -m unittest -v` in the project environment. Exercise the normal entry point and the denial. Review the final inventory artifact and task ledger. Reconcile discrepancies and repeat.
4. Qualify the exact commit on local Forgejo. Review the package, image, security scan and receipt for each release target. Ship the reviewed artifacts and record their digests.

The version 2 `[runtime]` table in `console.toml` sets request size, concurrency and client deadlines. Version 1 files inherit the shipped budget. Reissue them as version 2 to pin these choices in the admitted document.

Set PostgreSQL connection and statement deadlines in [observer_policy.toml](observer_policy.toml). Supply a candidate with `prompt-chain-observe --postgres --observer-policy FILE LEDGER`.

## Build and ship this revision

Review [release/policy.toml](release/policy.toml) and the hash-locked dependency closure. Local Forgejo builds the Linux wheel, source distribution and exact-source ZIP. On the trusted Windows workstation set `PAC_CHECKOUT` to the clean checkout, `PAC_OUTPUT` to a fresh release directory, `PAC_BUILD_PYTHON` to a Python 3.13 environment with `release/build.lock`, and `PAC_SCANNER` to the pinned Trivy executable. Run this from the checkout.

```powershell
forgejo-runner exec --workflows release/workstation.yml --job workstation --image=-self-hosted --detect-event --env "PAC_CHECKOUT=$env:PAC_CHECKOUT" --env "PAC_OUTPUT=$env:PAC_OUTPUT" --env "PAC_BUILD_PYTHON=$env:PAC_BUILD_PYTHON" --env "PAC_SCANNER=$env:PAC_SCANNER"
```

The job builds and reinstalls the Windows wheel, checks the target machine and UID, exercises the native console effect in hardened Compose, scans the image, exports it and checks the restored image ID. For a package installation, install the release lock followed by the wheel with `--no-deps`. Use the command named by the release policy with `unpack NEW_DIRECTORY` to install the exact component tree. Follow its native runbook from there.

For a container installation, load the matching `.image.tar.gz` and use its accompanying `compose.json`. Provision the service's credential directory with `docker compose -f compose.json run --rm console credentials /state/credentials`. Apply the component's native setup before starting the console. The server binds loopback inside its own network namespace. Supply upstream files as read-only mounts and place a dependent local service or client in that same namespace. Review the policy digest, package hashes, image identity, scan report and effect before promoting the revision.

The release resolves the declared companion image to its child manifest for each CPU architecture and scans that exact digest. The image receipt records both the child digest and the scan hash.
