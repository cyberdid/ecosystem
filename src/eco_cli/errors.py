class EcoError(Exception):
    """Expected user-facing error."""


class ValidationFailure(EcoError):
    """Canonical configuration is invalid."""


class SurfaceConflict(EcoError):
    """A vendor surface exists but is not managed by eco."""

