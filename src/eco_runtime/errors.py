from __future__ import annotations


class EcoRuntimeError(Exception):
    """Base class for expected runtime failures."""


class ContractValidationError(EcoRuntimeError):
    """A runtime record failed structural validation."""

    def __init__(self, errors: list[str]):
        self.errors = tuple(errors)
        super().__init__("; ".join(errors))


class RuntimePolicyError(EcoRuntimeError):
    """A runtime operation failed closed at the policy boundary."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RuntimeStateError(EcoRuntimeError):
    """An event would violate the fail-closed runtime state machine."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RuntimeBudgetError(EcoRuntimeError):
    """A run attempted to exceed an immutable budget."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class BrokerError(EcoRuntimeError):
    """A broker operation failed closed before returning untrusted content."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RuntimeStoreError(EcoRuntimeError):
    """Durable runtime state is unavailable, inconsistent, or untrusted."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RuntimeAdapterError(EcoRuntimeError):
    """A pinned model adapter failed without exposing provider-controlled text."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)
