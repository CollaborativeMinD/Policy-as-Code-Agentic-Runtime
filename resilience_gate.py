"""Strict monotonic attempt admission adapted from the supplied OODA depot."""

from collections.abc import Callable
from time import monotonic_ns

from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_fixed

from workflow_contracts import Resilience


class TransientFailure(ConnectionError):
    """Adapter assertion that a transient failure occurred and replay may be considered."""


class WindowClosed(TimeoutError):
    def __init__(self, reason, observed_ns, deadline_ns, required_ns):
        super().__init__(reason)
        self.evidence = {
            "reason": reason, "observed_ns": observed_ns,
            "deadline_ns": deadline_ns, "required_ns": required_ns,
        }


class CallWindow:
    def __init__(self, policy: Resilience, listener: Callable[[], int] | None = None,
                 *, clock=monotonic_ns):
        self.policy = policy
        self.listener = listener
        self.clock = clock
        self.deadline = clock() + policy.window_ns

    def _clamp(self, reason, observed, required):
        raise WindowClosed(reason, observed, self.deadline, required)

    def admit(self, required):
        if self.listener is not None:
            try:
                deadline = self.listener()
                if type(deadline) is not int or deadline < 0:
                    raise ValueError("invalid timing evidence")
            except Exception:
                self._clamp("invalid_time_evidence", self.clock(), required)
            self.deadline = min(self.deadline, deadline)
        observed = self.clock()
        if required >= self.deadline - observed:
            self._clamp("insufficient_margin", observed, required)
        return observed

    def call(self, operation, packet, record, *, replay_safe=False):
        policy = self.policy
        required = policy.attempt_bound_ns + policy.reserve_ns
        attempts = 0

        def before_sleep(state):
            self.admit(required + policy.backoff_ns)
            record("retry_scheduled", attempt=state.attempt_number, delay_ns=policy.backoff_ns)
            self.admit(required + policy.backoff_ns)

        def guarded():
            nonlocal attempts
            self.admit(required)
            attempts += 1
            record("attempt_admitted", attempt=attempts)
            # Evidence I/O may consume the margin before the callback starts.
            started = self.admit(required)
            try:
                result = operation(packet)
            except Exception as error:
                observed = self.clock()
                record("attempt_failed", attempt=attempts,
                       classification="transient" if isinstance(error, TransientFailure) else "terminal")
                finish(observed, started)
                raise
            observed = self.clock()
            finish(observed, started)
            record("attempt_completed", attempt=attempts)
            self.admit(policy.reserve_ns)
            return result

        def finish(observed, started):
            if observed - started > policy.attempt_bound_ns:
                self._clamp("attempt_bound_exceeded", observed, required)
            self.admit(policy.reserve_ns)

        retry = Retrying(
            stop=stop_after_attempt(policy.attempts if replay_safe else 1),
            retry=retry_if_exception_type(TransientFailure),
            wait=wait_fixed(policy.backoff_ns / 1_000_000_000),
            before_sleep=before_sleep,
            reraise=True,
        )
        return retry(guarded)
