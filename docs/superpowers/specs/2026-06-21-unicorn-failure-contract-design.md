# Unicorn Lazy-Mapping Failure Contract — Design

**Date:** 2026-06-21
**Status:** Approved (pending written-spec review)
**Scope:** The Critical chain C1–C4 from the PR review of `feature/pcode-emulation`, plus the
directly-coupled bridge/CLI consumers and tests. Cosmetic/independent fixes are deferred to a
separate follow-up plan (see *Out of Scope*).

## Problem

The Unicorn dynamic-emulation feature pulls original image bytes from Ghidra on demand: when
emulation touches an unmapped page, an `UC_HOOK_MEM_UNMAPPED` hook fetches that page from Ghidra
via an injected byte-provider and continues. Today the failure handling silently fabricates data:

- **C1** — `ghydra/dynamic/ghidra_provider.py` wraps the whole fetch in `except Exception: return b"\x00" * length`. Connection-refused, timeout, HTTP 4xx/5xx, malformed JSON — every failure becomes a zero page the emulator then executes as if it were real code/data.
- **C2** — a successful response with missing/short `hex` is silently zero-padded to the requested length, so "Ghidra returned nothing" is indistinguishable from a full read.
- **C3** — the lazy hook (`unicorn_engine.py`) maps the page **before** calling the provider and `return True` (retry) unconditionally, so even a no-data fetch leaves a mapped zero page and destroys the genuine unmapped-access fault (a wild-pointer signal).
- **C4** — `run()` cannot distinguish a clean run from "ran off into fabricated zeros"; `_last_error` is set on the session but never returned; the bridge `unicorn_run` returns `success: true` regardless of `stop_reason`, and the CLI `dump` prints the memory range even if the run faulted.

Net effect: for a feature whose entire purpose is producing **trustworthy** decrypted/unpacked
bytes, a Ghidra outage (or any fetch failure) yields an all-zeros emulation reported as success.

## Key constraint discovered during design

`GhidraHTTPClient.get()` / `_handle_response` **raise** on every failure mode — `GhidraConnectionError`
(unreachable/timeout/non-JSON) and `GhidraAPIError` (HTTP ≥400 or a `success:false` envelope) — and
**return** a dict only on `success:true`.

Crucially, `MemoryService.readBytes` **throws** (→ error envelope → `get()` raises `GhidraAPIError`)
when Ghidra cannot read an address: outside any block, or an uninitialized/BSS block where
`Memory.getBytes` throws `MemoryAccessException`. So "this address has no image bytes" arrives as a
**raise**, the same channel as "Ghidra is down". A naive "any raise → fault" rule would therefore
break the legitimate stack/BSS case — emulation would die on the first `push`. (In fact the current
swallow-to-zeros bug is what makes stack/BSS work today, by accident.)

## Decision

Adopt the **purist contract**: lazy mapping serves **only real image bytes**. Any address Ghidra
cannot satisfy — for any reason — **faults**. Callers establish scratch/stack memory explicitly
before running. This gives the strongest trust guarantee: every unmapped fault is a real signal,
and a mapped page always contains genuine image bytes (or bytes the caller wrote).

Locked sub-decisions:

- **Stop-reason taxonomy:** keep `DONE` / `COUNT` / `ERROR`; add `LAZY_FETCH_FAILED`.
- **Success flag:** `success: true` only for `DONE`. `COUNT`, `ERROR`, `LAZY_FETCH_FAILED` → `false`.
- **Return shape:** keep the plain `dict` from `run()`; add a `last_error` key (no dataclass).

## Components

### 1. Provider (`ghydra/dynamic/ghidra_provider.py`)

`provider(address, length) -> bytes` — returns the real bytes Ghidra has (length may be **less than**
requested; no zero-padding). **Raises `ProviderError`** when no real image bytes are available:

| Situation | Behavior |
|---|---|
| `client.get` raises (`GhidraConnectionError` / `GhidraAPIError`) | `raise ProviderError(f"fetch failed at {hex(address)}: {cause}") from e` |
| success, `hex` present and well-formed | decode and `return` the real bytes |
| success, `hex` empty/absent | `raise ProviderError(f"no image bytes at {hex(address)}")` |
| success, `hex` present but malformed (`bytes.fromhex` raises) | `raise ProviderError(...)` |

The `except Exception: return zeros` fallback (C1) and the zero-pad-to-length (C2) are removed.
The injected-provider abstraction stays `Callable[[int, int], bytes]` (it may raise) — no signature
change for consumers.

`ProviderError` is a new exception class defined in `ghydra/dynamic/` (e.g.
`ghydra/dynamic/exceptions.py`); it carries the message surfaced as `last_error`.

### 2. Lazy hook — map only on success (`ghydra/dynamic/unicorn_engine.py`)

The hook is reordered so a page is **never mapped unless real bytes arrive** (fixes C3 and the
latent "mapped zero page on miss" bug):

```python
def _unmapped_hook(uc, access, address, size, value, _user):
    page = address & ~(self.PAGE - 1)
    if page in self._mapped or lazy["n"] >= max_lazy_pages or self.byte_provider is None:
        return False                      # cannot satisfy -> let Unicorn fault
    try:
        data = self.byte_provider(page, self.PAGE)
    except Exception as e:                # boundary catch: must not cross emu_start
        lazy_fail["msg"] = f"lazy fetch failed at {hex(page)}: {e}"
        return False
    if not data:
        lazy_fail["msg"] = f"no image bytes at {hex(page)}"
        return False
    uc.mem_map(page, self.PAGE)
    self._mapped.add(page)
    uc.mem_write(page, data[:self.PAGE])
    lazy["n"] += 1
    return True
```

The broad `except Exception` is deliberate and correct **at this boundary**: it runs inside a
Unicorn C callback, and allowing a Python exception to propagate through `emu_start` is unsafe. It
records the message and faults (returns `False`) rather than swallowing. On failure the page is left
unmapped, preserving the fault as a real signal.

### 3. `run()` — stop reason and `last_error`

- A `lazy_fail` closure (e.g. `{"msg": None}`) captures the hook's failure message.
- In `except UcError as e`: if `lazy_fail["msg"]` is set → `stop_reason = "LAZY_FETCH_FAILED"`,
  `last_error = lazy_fail["msg"]`; otherwise → `stop_reason = "ERROR"`, `last_error = str(e)`.
- The returned dict gains `"last_error"` (a `str`, or `None` on a clean run). The `self._last_error`
  instance attribute is removed in favor of the returned field.

`DONE` and `COUNT` paths set `last_error = None`. The dict keys are otherwise unchanged
(`pc`, `steps`, `stop_reason`, `registers`, `trace`, `mem_writes`, `last_error`).

### 4. Bridge + CLI surfacing (the payoff)

- **`bridge_mcp_hydra.py` `unicorn_run`:** `success = (state["stop_reason"] == "DONE")`; add
  `"last_error": state["last_error"]` to the returned payload. (Today it hard-codes `success: True`.)
  **Behavior change for MCP consumers:** a run that hits the instruction cap now returns
  `stop_reason="COUNT"` **with `success: false`** — previously every non-faulting run reported
  `success: true`. This is intended (a truncated run did not reach its target, so its memory state
  must not be presented as trustworthy), but existing LLM workflows that lean on the cap will start
  seeing failures. The `unicorn_run` docstring MUST call this out explicitly: `COUNT` means "ran
  cleanly but stopped at the instruction budget — raise `count` or set an `until`," distinct from a
  fault. The CLI `run` output likewise already prints `stop_reason`, so the distinction is visible
  there.
- **CLI `ghydra dynamic dump` (`ghydra/cli/dynamic.py`):** after `run()`, if `stop_reason != "DONE"`,
  write `stop_reason` + `last_error` to **stderr** and exit non-zero — do **not** print the hex dump.
  A faulted unpacker must not present its partial/garbage memory as a successful result.
- **CLI `ghydra dynamic run`:** print `last_error` when present, alongside the existing
  `pc/steps/stop` line.

### 5. Usage-model change

With purist mapping, the bridge `unicorn_reset → unicorn_run` flow **faults with
`LAZY_FETCH_FAILED` the instant emulated code touches un-pre-mapped memory** (e.g. a stack `push`,
since the stack is not in the static image). This is the intended trade-off.

Callers establish scratch/stack memory before `run()` using the **existing**
`UnicornSession.map_bytes(addr, b"\x00" * size)` (maps + zero-writes a region). The
`LAZY_FETCH_FAILED` message names the faulting address and hints that scratch/stack memory must be
mapped explicitly.

A stack-setup convenience for the bridge/CLI (auto-map a default stack on reset, or a dedicated map
tool) is **explicitly deferred** to the follow-up plan — it is usability, not part of the trust
contract.

## Data flow (after change)

```
emulated access to unmapped page
        │
        ▼
_unmapped_hook ── provider(page, PAGE)
        │                  │
        │        success+hex│            raise / empty / malformed
        │                  ▼                       │
        │        map + write real bytes            ▼
        │        return True (continue)   record last_error, return False
        │                                          │
        ▼                                          ▼
   run continues                         Unicorn faults → UcError
                                                   │
                                                   ▼
                                 stop_reason = LAZY_FETCH_FAILED, last_error set
                                                   │
                                                   ▼
                          unicorn_run success=false + last_error
                          dynamic dump → stderr + non-zero exit (no hex)
```

## Error handling summary

| Layer | Failure | Result |
|---|---|---|
| Provider | `client.get` raises | `ProviderError` (chained) |
| Provider | empty/malformed hex on success | `ProviderError` |
| Lazy hook | provider raises or returns falsy | record `last_error`, leave page unmapped, fault |
| `run()` | lazy fault | `stop_reason=LAZY_FETCH_FAILED`, `last_error` populated |
| `run()` | other UC fault | `stop_reason=ERROR`, `last_error=str(UcError)` |
| Bridge | `stop_reason != DONE` | `success: false`, `last_error` in payload |
| CLI `dump` | `stop_reason != DONE` | stderr message, non-zero exit, no hex |

## Testing (directly-coupled only)

1. **Provider** (`tests/test_ghidra_provider.py`): real hex → bytes; **short read returns the real
   bytes only, NOT zero-padded to `length`**; empty hex → `ProviderError`; `client.get` raising
   (`GhidraConnectionError`/`GhidraAPIError`) → `ProviderError`; malformed hex → `ProviderError`.
   Rewrites **both** existing provider tests: `test_provider_zero_fills_on_miss` (now expects
   `ProviderError`) **and** `test_provider_decodes_hex_to_bytes` (its `assert len(data) == 4` from a
   3-byte response asserts the old zero-pad behavior and must become `data == b"\x90\x90\xcc"`).
2. **Lazy hook** (`tests/test_unicorn_engine.py`): a provider that raises (or returns falsy) during a
   run → `stop_reason == "LAZY_FETCH_FAILED"`, `last_error` populated, and the failed page is **not**
   in `_mapped` (assert a subsequent access faults / page absent).
3. **`run()` return shape**: `last_error` key present; `None` on a clean `DONE` run.
4. **Bridge** `unicorn_run` success mapping: `DONE → success:true`, `LAZY_FETCH_FAILED → success:false`
   with `last_error` (exercised with a fake byte-provider; no live Ghidra).
5. **CLI `dump` guard**: a faulted run → non-zero exit and no hex on stdout (Click `CliRunner` +
   fake client).
6. **Regression**: the existing e2e (`tests/test_dynamic_e2e.py`) and
   `test_lazy_maps_code_page_from_provider` still pass — their providers return real bytes and the
   programs use no stack.

## Out of scope (follow-up plan)

- Stack-setup convenience for bridge/CLI (auto-map default stack / dedicated map tool).
- `UnicornSession.uc` → `_uc` privatization and routing the hook's `mem_map` through `_ensure_mapped`.
- Session-dict (`_UNICORN_SESSIONS`) locking for parity with `instances_lock`.
- Trace-truncation flag at `_TRACE_CAP`.
- CLI `_make_session` except-narrowing (distinguish "unicorn not installed" from a `UcError`).
- General negative-path coverage not tied to the contract: `COUNT` cap, `max_lazy_pages` cap,
  missing-dependency `RuntimeError`, Java `EmulationService.stepOnce` classification.
- Re-running the comment/docs-accuracy review aspect (did not complete during the PR review).

## Self-review notes

- No placeholders or TBDs; every component names concrete files and behavior.
- Internally consistent: the success-flag table (§4), the stop-reason taxonomy (Decision), and the
  data-flow/error tables agree.
- Single-plan scope: one cohesive contract change with a bounded test set; larger/independent items
  are explicitly deferred.
- Ambiguity resolved: "no image bytes" (empty/raise) uniformly faults; only a non-empty real
  response maps. An all-zero **non-empty** provider response counts as real bytes (Ghidra returned an
  initialized-to-zero region) and maps — distinct from an empty/absent response, which faults.
