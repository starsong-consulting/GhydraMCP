"""Exceptions for the dynamic (Unicorn) emulation subsystem."""


class ProviderError(Exception):
    """A lazy byte-provider could not return real image bytes for an address.

    Raised when the underlying fetch failed (transport/API error), when the
    source has no bytes for the address, or when the response was malformed.
    Carries the message surfaced as run()'s ``last_error``.
    """
