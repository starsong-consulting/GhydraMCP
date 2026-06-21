"""Exceptions for the dynamic (Unicorn) emulation subsystem."""

from ..client.exceptions import GhidraError


class ProviderError(GhidraError):
    """A lazy byte-provider could not return real image bytes for an address.

    Raised when the underlying fetch failed (transport/API error), when the
    source has no bytes for the address, or when the response was malformed.
    Its message is embedded into run()'s ``last_error`` (wrapped with the
    faulting page address) when the resulting access faults. Subclasses
    GhidraError so it is caught uniformly by the CLI's ``except GhidraError``
    handlers if it ever escapes the engine's boundary catch.
    """
