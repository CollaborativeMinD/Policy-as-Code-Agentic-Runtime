"""Render an admitted Compose spec and qualify Python and container distributions."""

import argparse
from contextlib import closing
from hashlib import sha256
import gzip
import json
import os
from pathlib import Path
import re
from secrets import token_hex
import shutil
import subprocess
import sys
import tempfile
import tomllib

import deployment_effect as app


ROOT = Path(__file__).resolve().parent
PLATFORMS = {"linux/amd64", "linux/arm64"}
BASE = re.compile(r"docker\.io/library/[a-z][a-z0-9._:-]*@sha256:[a-f0-9]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(path):
    with path.open("rb") as source:
        from hashlib import file_digest
        return file_digest(source, "sha256").hexdigest()


def put(path, content):
    path.write_text(json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command(*args, cwd=ROOT, env=None, input=None, timeout=360):
    result = subprocess.run(args, cwd=cwd, env=env, input=input, capture_output=True, timeout=timeout)
    if result.returncode:
        tail = result.stderr.decode("utf-8", errors="replace")[-4000:]
        raise RuntimeError(f"{Path(args[0]).name} exited {result.returncode}: {tail}")
    return result.stdout


def policy(path):
    require(path.stat().st_size <= 65536, "Deployment declaration too large")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    keys = {"version", "name", "python_image", "platforms", "uid", "gid"} | app.POLICY_FIELDS
    if data.get("version") == 2:
        keys.add("python_apk")
    require(data.keys() == keys, "Unknown or missing deployment field")
    require(type(data["version"]) is int and data["version"] in (1, 2), "Unsupported deployment policy")
    require(type(data["name"]) is str and re.fullmatch(r"[a-z][a-z0-9-]{2,31}", data["name"]),
            "Invalid deployment name")
    platforms = data["platforms"]
    require(type(platforms) is list and all(type(item) is str for item in platforms)
            and len(platforms) == len(PLATFORMS) and set(platforms) == PLATFORMS,
            "Deployment must declare AMD64 and ARM64")
    for key in ("uid", "gid"):
        require(type(data[key]) is int and 1000 <= data[key] <= 65534, "Runtime must use an unprivileged ID")
    for key in app.POLICY_FIELDS:
        require(type(data[key]) is str and BASE.fullmatch(data[key]), f"Unpinned image: {key}")
    if data["version"] == 1:
        require(BASE.fullmatch(data["python_image"]) and data["python_image"].startswith("docker.io/library/python:"), "Pinned Python image required")
    else:
        require(re.fullmatch(r"cgr\.dev/chainguard/wolfi-base@sha256:[0-9a-f]{64}", data["python_image"])
                and re.fullmatch(r"3\.13\.\d+_git\d+-r\d+", data["python_apk"]), "Unbound Python base")
    app.validate_policy(data)
    return data


def render(data, platform, image):
    require(platform in data["platforms"], "Unadmitted platform")
    require(re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*(?:@sha256:[0-9a-f]{64})?", image), "Invalid target image")
    common = {
        "image": image, "platform": platform, "user": f"{data['uid']}:{data['gid']}",
        "read_only": True, "tmpfs": ["/tmp"], "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"], "init": True,
    }
    return app.services(data, common)


def revision():
    actual = command("git", "rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", actual), "Invalid revision")
    require(actual == os.environ.get("GITHUB_SHA", actual), "CI checkout differs from triggering revision")
    return actual


def evidence_sign(output):
    local = Path("C:/Program Files/Git/usr/bin/openssl.exe")
    openssl = shutil.which("openssl") or (str(local) if local.is_file() else None)
    require(openssl is not None, "OpenSSL required to sign deployment evidence")
    with tempfile.TemporaryDirectory() as temporary:
        key = Path(temporary) / "private.pem"
        command(openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(key))
        public = output / "verification-public.pem"
        proof = output / "verification.json"
        signature = output / "verification.sig"
        command(openssl, "pkey", "-in", str(key), "-pubout", "-out", str(public))
        command(openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                "-in", str(proof), "-out", str(signature))
    command(openssl, "pkeyutl", "-verify", "-pubin", "-rawin", "-inkey", str(public),
            "-in", str(proof), "-sigfile", str(signature))


def package(output, commit):
    tests = subprocess.run([sys.executable, "-B", "-W", "error", "-m", "unittest", "-v"],
                           cwd=ROOT, capture_output=True, timeout=240)
    (output / "tests.txt").write_bytes(tests.stdout + tests.stderr)
    print((tests.stdout + tests.stderr).decode("utf-8", errors="replace"))
    tests.check_returncode()
    distributions = output / "dist"
    command(sys.executable, "-m", "build", "--no-isolation", "--outdir", str(distributions), timeout=240)
    wheel, = distributions.glob("*.whl")
    source, = distributions.glob("*.tar.gz")
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        command(sys.executable, "-m", "venv", str(temp / "install"))
        scripts = temp / "install" / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        command(str(python), "-m", "pip", "install", "-r", str(ROOT / app.RUNTIME_LOCK))
        command(str(python), "-m", "pip", "install", "--no-deps", str(wheel))
        command(str(python), "-m", "pip", "check")
        observed = app.installed_smoke(scripts, temp)
    put(output / "verification.json", {"status": "PASS", "revision": commit,
        "platform": sys.platform, "python": sys.version.split()[0],
        "runtime_policy_sha256": app.runtime_policy_sha256(),
        "distributions": {file.name: checksum(file) for file in (wheel, source)}, "witness": observed})
    evidence_sign(output)


class Stack:
    def __init__(self, spec, project, env):
        self.compose = ("docker", "compose", "-f", str(spec), "-p", project)
        self.env = env
        self.project = project

    def __call__(self, *args, **kwargs):
        return command(*self.compose, *args, env=self.env, **kwargs)

    def run(self, service, *args, input=None, entrypoint=None):
        override = ("--entrypoint", entrypoint) if entrypoint else ()
        return self("run", "--rm", "-T", *override, service, *args, input=input)


def save_image(image, archive):
    with tempfile.TemporaryFile() as errors, subprocess.Popen(
        ["docker", "image", "save", image], stdout=subprocess.PIPE, stderr=errors,
    ) as process, archive.open("xb") as sink, gzip.GzipFile(fileobj=sink, mode="wb", compresslevel=5, mtime=0) as packed:
        with closing(process.stdout) as source:
            shutil.copyfileobj(source, packed)
        require(process.wait(timeout=30) == 0, "Image export failed")


def qualify_compose(path, platform, output, commit):
    data = policy(path)
    arch = platform.rpartition("/")[2]
    project = f"{data['name']}-{arch}-{token_hex(4)}"
    image = f"{data['name']}:{commit[:12]}-{arch}"
    spec = output / "compose.json"
    put(spec, render(data, platform, image))
    args = {
        "PYTHON_IMAGE": data["python_image"], "SERVICE_UID": data["uid"],
        "SERVICE_GID": data["gid"], "REVISION": commit,
    }
    if data["version"] == 2:
        args["PYTHON_APK"] = data["python_apk"]
    build = ["docker", "buildx", "build", "--platform", platform, "--load", "--tag", image]
    for key, value in args.items():
        build.extend(("--build-arg", f"{key}={value}"))
    build.extend(app.build_options())
    build.append(".")
    command(*build, timeout=1200)
    inspected, = json.loads(command("docker", "image", "inspect", image))
    require(f'{inspected["Os"]}/{inspected["Architecture"]}' == platform, "Image platform mismatch")
    require(inspected["Config"]["Labels"]["org.opencontainers.image.revision"] == commit, "Image revision mismatch")
    from release.qualify import Release, scan
    report_sha256 = scan(Release.read(), image, output / "scan.json", os.environ.get("PAC_SCANNER", "trivy"))
    stack = Stack(spec, project, app.stack_env())
    try:
        stack("config", "--quiet")
        facts = json.loads(stack.run(app.PRIMARY, "-c",
            "import json, os, platform; print(json.dumps([os.getuid(),os.getgid(),platform.machine()]))",
            entrypoint="python"))
        require(facts == [data["uid"], data["gid"], {"amd64": "x86_64", "arm64": "aarch64"}[arch]],
                "Running identity or architecture differs from deployment policy")
        observed = app.compose_smoke(stack, output)
    finally:
        stack("--profile", "*", "down", "--volumes", "--remove-orphans", timeout=120)
    archive = output / f"{data['name']}-{arch}.image.tar.gz"
    save_image(image, archive)
    command("docker", "image", "load", "--input", str(archive), timeout=240)
    restored, = json.loads(command("docker", "image", "inspect", image))
    require(restored["Id"] == inspected["Id"], "Restored distribution differs from the qualified image")
    put(output / "verification.json", {
        "status": "PASS", "revision": commit, "platform": platform, "execution_identity": facts, "scan_sha256": report_sha256,
        "deployment_policy_sha256": checksum(path), "runtime_policy_sha256": app.runtime_policy_sha256(),
        "compose_sha256": checksum(spec), "image": image, "image_id": inspected["Id"],
        "distribution": {"name": archive.name, "sha256": checksum(archive)}, "witness": observed,
    })
    evidence_sign(output)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("mode", choices=("render", "package", "compose"))
    cli.add_argument("--policy", type=Path, default=ROOT / "deployment.toml")
    cli.add_argument("--platform", choices=sorted(PLATFORMS), default="linux/amd64")
    cli.add_argument("--image")
    cli.add_argument("--output", required=True, type=Path)
    args = cli.parse_args()
    output = args.output.resolve()
    output.mkdir()
    if args.mode == "render":
        require(args.image is not None, "Supply the qualified image for rendering")
        put(output / "compose.json", render(policy(args.policy), args.platform, args.image))
    elif args.mode == "package":
        package(output, revision())
    else:
        qualify_compose(args.policy, args.platform, output, revision())


if __name__ == "__main__":
    main()
