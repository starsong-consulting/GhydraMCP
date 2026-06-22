"""Byte provider that pulls original image bytes from a Ghidra instance."""

from typing import Callable

from .exceptions import ProviderError


def make_ghidra_provider(client) -> Callable[[int, int], bytes]:
    """Build an (address, length) -> bytes provider backed by Ghidra's /memory API.

    The returned provider returns exactly the bytes Ghidra returned -- neither
    truncated nor padded to `length`, so the result may be shorter (or, in
    principle, longer) than requested but is never zero-filled -- and raises
    ProviderError when no real image bytes are available, so genuine fetch
    failures fault loudly instead of masquerading as zero data.
    """

    def provider(address: int, length: int) -> bytes:
        endpoint = f"memory/{address:x}"
        try:
            resp = client.get(endpoint, params={"length": length, "format": "hex"})
        except Exception as e:
            raise ProviderError(f"fetch failed at {hex(address)}: {e}") from e
        result = resp.get("result", resp) if isinstance(resp, dict) else {}
        hex_str = (result or {}).get("hex", "") or ""
        if not hex_str:
            raise ProviderError(f"no image bytes at {hex(address)}")
        try:
            return bytes.fromhex(hex_str)
        except ValueError as e:
            raise ProviderError(f"malformed hex at {hex(address)}: {e}") from e

    return provider
