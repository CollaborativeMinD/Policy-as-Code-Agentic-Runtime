"""Compose release witness for the published artifact and its PostgreSQL ancestry."""

import json
import os
from pathlib import Path
from secrets import token_hex
from time import monotonic, sleep


ROOT = Path(__file__).resolve().parent
POLICY_FIELDS = {"postgres_image"}
RUNTIME_LOCK = "requirements-postgres.lock"
PRIMARY = "writer"
EXPECTED = {"location_totals": {"NORTH": 6, "SOUTH": 3}, "zero_quantity_rows": ["r2"]}


def validate_policy(data):
    if not data["postgres_image"].startswith("docker.io/library/postgres:"):
        raise ValueError("PostgreSQL image required")


def runtime_policy_sha256():
    from deploy_common import checksum
    return checksum(ROOT / "workflow_policy.toml")


def services(data, common):
    return {"services": {
        "writer": common | {"network_mode": "none", "volumes": ["state:/state"]},
        "observer": common | {
            "entrypoint": ["prompt-chain-observe"], "volumes": ["state:/state:ro"], "networks": ["lineage"],
            "environment": {"PGHOST": "database", "PGDATABASE": "runtime_lineage", "PGUSER": "lineage_reader",
                            "PGPASSWORD": "${LINEAGE_PASSWORD:-}"},
        },
        "database": {"image": data["postgres_image"], "platform": common["platform"], "profiles": ["postgres"],
                     "networks": ["lineage"], "environment": {"POSTGRES_DB": "runtime_lineage",
                     "POSTGRES_USER": "postgres", "POSTGRES_PASSWORD": "${LINEAGE_PASSWORD:-}"},
                     "volumes": ["postgres:/var/lib/postgresql"]},
    }, "networks": {"lineage": {"internal": True}}, "volumes": {"state": {}, "postgres": {}}}


def installed_smoke(scripts, cwd):
    from deploy_common import command, require
    suffix = ".exe" if os.name == "nt" else ""
    out = cwd / "installed-run"
    result = json.loads(command(str(scripts / f"prompt-chain-run{suffix}"), str(out), cwd=cwd))
    lineage = json.loads(command(str(scripts / f"prompt-chain-observe{suffix}"), str(out / "run.sqlite"), cwd=cwd))
    require(result == EXPECTED and lineage["status"] == "admitted", "Installed wheel effect differs")
    require(lineage["origin"]["policy_sha256"] == runtime_policy_sha256(), "Installed policy bytes differ")
    return {"result": result, "receipt_sha256": lineage["receipt"]["sha256"]}


def build_options():
    return []


def stack_env():
    return os.environ | {"LINEAGE_PASSWORD": token_hex(24)}


def compose_smoke(stack, output):
    from deploy_common import put, require
    stack("--profile", "postgres", "up", "-d", "database")
    deadline = monotonic() + 120
    while True:
        try:
            stack("exec", "-T", "database", "pg_isready", "-h", "127.0.0.1", "-U", "postgres",
                  "-d", "runtime_lineage", timeout=8)
            break
        except RuntimeError:
            require(monotonic() < deadline, "PostgreSQL did not become ready")
            sleep(1)
    password = stack.env["LINEAGE_PASSWORD"]
    setup = f"CREATE ROLE lineage_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '{password}';\n".encode()
    try:
        stack("exec", "-T", "database", "psql", "-X", "-U", "postgres", "-d", "runtime_lineage",
              "-v", "ON_ERROR_STOP=1", input=setup)
    except RuntimeError:
        raise RuntimeError("PostgreSQL reader setup failed") from None
    result = json.loads(stack.run("writer", "/state/witness"))
    lineage = json.loads(stack.run("observer", "/state/witness/run.sqlite", "--postgres"))
    require(result == EXPECTED and lineage["status"] == "admitted", "Compose effect differs")
    require(lineage["origin"]["policy_sha256"] == runtime_policy_sha256(), "Compose policy bytes differ")
    require(lineage["postgres_ancestors"] == lineage["nodes"], "PostgreSQL receipt ancestry is incomplete")
    receipt = lineage["receipt"]["sha256"]
    pinned = json.loads(stack.run("observer", "/state/witness/run.sqlite", "--expect-receipt", receipt))
    require(pinned["integrity"] == "pinned_receipt", "Receipt recheck failed")
    put(output / "lineage.json", lineage)
    return {"result": result, "receipt_sha256": receipt, "postgres_ancestors": len(lineage["postgres_ancestors"])}
