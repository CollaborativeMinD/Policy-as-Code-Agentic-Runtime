"""Admit operational budgets independently of model and wire contracts."""
from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(frozen=True)
class ObserverBudget:
    connect_seconds: int
    statement_ms: int

    @classmethod
    def read(cls, path):
        with Path(path).open("rb") as stream:
            values = tomllib.load(stream)
        if set(values) != set(cls.__annotations__):
            raise ValueError("Unknown or missing runtime budget")
        if type(values["connect_seconds"]) is not int or not 1 <= values["connect_seconds"] <= 60:
            raise ValueError("Invalid connect_seconds")
        if type(values["statement_ms"]) is not int or not 1 <= values["statement_ms"] <= 120000:
            raise ValueError("Invalid statement_ms")
        return cls(**values)
