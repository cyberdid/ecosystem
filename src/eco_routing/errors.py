from __future__ import annotations


class RoutingError(Exception):
    """A trusted routing input is invalid; ordinary ineligibility is a typed denial."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)
