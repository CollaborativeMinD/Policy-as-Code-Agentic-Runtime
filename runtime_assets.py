"""Find identical policy and SQL files in a checkout or an installed wheel."""

from pathlib import Path
import sysconfig


def asset(name: str) -> Path:
    source = Path(__file__).with_name(name)
    if source.is_file():
        return source
    return Path(sysconfig.get_path("data")) / "share" / "prompt-chain" / name
