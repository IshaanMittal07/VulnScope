"""The result of one ownership check."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Outcome:
    verified: bool
    reason: str

    @classmethod
    def ok(cls, reason: str) -> "Outcome":
        return cls(verified=True, reason=reason)

    @classmethod
    def fail(cls, reason: str) -> "Outcome":
        return cls(verified=False, reason=reason)
