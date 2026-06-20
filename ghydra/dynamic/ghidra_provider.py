"""Byte provider that pulls original image bytes from a Ghidra instance."""

from typing import Callable


def make_ghidra_provider(client) -> Callable[[int, int], bytes]:
    """Build an (address, length) -> bytes provider backed by Ghidra's /memory API."""

    def provider(address: int, length: int) -> bytes:
        endpoint = f"memory/{address:x}"
        try:
            resp = client.get(endpoint, params={"length": length, "format": "hex"})
        except Exception:
            return b"\x00" * length
        result = resp.get("result", resp) if isinstance(resp, dict) else {}
        hex_str = (result or {}).get("hex", "") or ""
        raw = bytes.fromhex(hex_str) if hex_str else b""
        if len(raw) < length:
            raw = raw + b"\x00" * (length - len(raw))
        return raw[:length]

    return provider
