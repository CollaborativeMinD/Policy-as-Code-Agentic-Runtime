"""Typed declarations for untrusted input and operator-owned TOML."""

from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, model_validator


Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
Source = Annotated[str, StringConstraints(pattern=r"^(request|task)\.[a-z][a-z0-9_-]{0,63}$")]
def nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError("empty text")
    return value


Text = Annotated[str, AfterValidator(nonblank)]
ProfileNames = Annotated[tuple[Identifier, ...], BeforeValidator(
    lambda value: tuple(value) if type(value) is list else value
)]


class Declaration(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class Limits(Declaration):
    request_bytes: Annotated[int, Field(ge=1, le=1_048_576)]
    planner_packet_bytes: Annotated[int, Field(ge=1, le=2_097_152)]
    plan_bytes: Annotated[int, Field(ge=1, le=1_048_576)]
    task_count: Annotated[int, Field(ge=1, le=4096)]
    predecessor_count: Annotated[int, Field(ge=1, le=64)]
    prompt_bytes: Annotated[int, Field(ge=1, le=262_144)]
    output_bytes: Annotated[int, Field(ge=1, le=262_144)]


class Resilience(Declaration):
    attempts: Annotated[int, Field(ge=1, le=8)] = 1
    window_ns: Annotated[int, Field(gt=0, le=3_600_000_000_000)] = 60_000_000_000
    attempt_bound_ns: Annotated[int, Field(gt=0)] = 5_000_000_000
    fallback_reserve_ns: Annotated[int, Field(ge=0)] = 100_000_000
    uncertainty_ns: Annotated[int, Field(ge=0)] = 10_000_000
    backoff_ns: Annotated[int, Field(ge=0)] = 50_000_000
    replay_profiles: ProfileNames = ()

    @property
    def reserve_ns(self) -> int:
        return self.fallback_reserve_ns + self.uncertainty_ns

    @model_validator(mode="after")
    def check_window(self):
        needed = self.attempt_bound_ns + self.reserve_ns
        if self.attempts > 1:
            needed += self.backoff_ns
        if needed >= self.window_ns:
            raise ValueError("retry budget must leave positive margin")
        return self


class ProfileSpec(Declaration):
    objective: Text
    rules: Annotated[list[Text], Field(min_length=1)]
    inputs: Annotated[dict[Identifier, Source], Field(max_length=64)]
    checks: Annotated[list[Identifier], Field(min_length=1)]


class PolicySpec(Declaration):
    version: Annotated[int, Field(ge=1, le=1)]
    policy_id: Identifier
    generation: Annotated[int, Field(ge=0)]
    final_profile: Identifier
    final_checks: Annotated[list[Identifier], Field(min_length=1)]
    effect: Literal["publish_final_artifact"] = "publish_final_artifact"
    limits: Limits
    profiles: Annotated[dict[Identifier, ProfileSpec], Field(min_length=1, max_length=64)]
    resilience: Resilience = Resilience()


class RequirementSpec(Declaration):
    text: Text
    profiles: Annotated[list[Identifier], Field(min_length=1)]


class RequestSpec(Declaration):
    inputs: dict[Identifier, Any]
    requirements: Annotated[dict[Identifier, RequirementSpec], Field(min_length=1)]


class TaskSpec(Declaration):
    profile: Identifier
    after: list[Identifier]
    inputs: dict[Identifier, Identifier]
    requirements: list[Identifier]


class PlanSpec(Declaration):
    tasks: Annotated[dict[Identifier, TaskSpec], Field(min_length=1, max_length=4096)]
