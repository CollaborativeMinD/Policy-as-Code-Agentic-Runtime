"""Run the test suite with an isolated PostgreSQL lineage observer fixture."""

import os
import secrets
import subprocess
import sys
from time import monotonic, sleep


IMAGE = "postgres@sha256:c699303802144847d238196173655dbbecf7a96aeca1565f2b02eb671a1f0b6b"


def main():
    name = f"policy-runtime-postgres-{secrets.token_hex(6)}"
    password = secrets.token_hex(24)
    subprocess.run(["docker", "run", "--detach", "--rm", "--name", name, "--env", "POSTGRES_PASSWORD",
                    "--env", "POSTGRES_DB=runtime_lineage", "--publish", "127.0.0.1::5432", IMAGE],
                   env=os.environ | {"POSTGRES_PASSWORD": password}, check=True, stdout=subprocess.DEVNULL)
    try:
        deadline = monotonic() + 30
        while subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1",
                              "-U", "postgres", "-d", "runtime_lineage"],
                             capture_output=True, timeout=5).returncode:
            if monotonic() >= deadline:
                raise RuntimeError("PostgreSQL fixture did not become ready")
            sleep(0.3)
        # A hex-only fixture password is passed on stdin. Do not relay server diagnostics.
        setup = subprocess.run(["docker", "exec", "-i", name, "psql", "-X", "-U", "postgres",
                                "-d", "runtime_lineage", "-v", "ON_ERROR_STOP=1"],
                               input=f"CREATE ROLE lineage_reader LOGIN NOSUPERUSER NOCREATEDB "
                                     f"NOCREATEROLE PASSWORD '{password}';\n",
                               text=True, capture_output=True, timeout=10)
        if setup.returncode:
            raise RuntimeError("PostgreSQL reader setup failed")
        port = subprocess.check_output(["docker", "port", name, "5432/tcp"], text=True).strip().rsplit(":", 1)[-1]
        environment = dict(os.environ, PGHOST="127.0.0.1", PGPORT=port, PGDATABASE="runtime_lineage",
                           PGUSER="lineage_reader", PGPASSWORD=password, CHAIN_TEST_POSTGRES="1")
        subprocess.run(["docker", "exec", name, "postgres", "--version"], check=True)
        subprocess.run([sys.executable, "-W", "error", "-m", "unittest", "-v"], check=True, env=environment)
    finally:
        subprocess.run(["docker", "stop", name], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
