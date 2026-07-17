from __future__ import annotations


class ResearchToolError(RuntimeError):
    """Stable, content-free failure at the governed research boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def fail(code: str, message: str) -> ResearchToolError:
    return ResearchToolError(code, message)
