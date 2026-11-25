"""Install the policy-pinned scanner in the current CI job's private temp folder."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile
import tomllib
from urllib.request import urlopen
from zipfile import ZipFile


def install() -> Path:
    with Path("release/policy.toml").open("rb") as stream:
        policy = tomllib.load(stream)["scan"]
    version = policy["scanner_version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid scanner version")
    directory = Path(tempfile.mkdtemp(dir=os.environ["RUNNER_TEMP"], prefix="trivy-"))
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_windows-64bit.zip"
    with tempfile.TemporaryFile(dir=directory) as archive:
        with urlopen(url, timeout=120) as response:
            shutil.copyfileobj(response, archive)
        archive.seek(0)
        if hashlib.file_digest(archive, "sha256").hexdigest() != policy["windows_zip_sha256"].lower():
            raise ValueError("Scanner archive failed verification")
        executable = directory / "trivy.exe"
        with ZipFile(archive) as bundle, bundle.open("trivy.exe") as source, executable.open("xb") as target:
            shutil.copyfileobj(source, target)
    return executable


if __name__ == "__main__":
    print(install())
