# skill_todo — requirements for the GhydraMCP agent skill set

Goal: a set of agent skills that let an LLM drive GhydraMCP for reverse engineering
**correctly and repeatably**, without re-learning the API each session. This file is the
spec the skills must satisfy — not the skills themselves.

Grounding: the MCP exposes one HATEOAS REST API over three clients (Java plugin = source of
truth, `ghydra` CLI, `bridge_mcp_hydra.py`). Static namespaces (`functions_*`, `data_*`,
`xrefs_*`, …) plus the dynamic stack: Unicorn (`unicorn_*`) and PCode (`emulation_*`, incl.
the `call`/`hooks` added by the 2026-06-24 plan). See `dynamic-emulation-direction` memory.

---

## Skill set (build these)

1. **`ghydra-session`** — connect & target the right instance. Lowest layer; every other
   skill assumes it ran.
2. **`ghydra-recon`** — static triage of an unknown binary (entry points, imports, strings,
   xrefs, candidate functions) to decide *what* to analyze.
3. **`ghydra-dynamic`** — drive emulation: pick Unicorn vs PCode, set up a `call`, stub
   imports with hooks, read back results, iterate on faults.
4. **`ghydra-annotate`** — write findings back (rename, set signatures/comments, define
   structs/types) so analysis compounds across sessions.

Each skill MUST state in its description the trigger ("reverse engineering with Ghidra",
"emulate / call a function", etc.) and link the others.

---

## Hard requirements (every skill)

### R1 — Always establish the instance first
- Call `instances_list()` before any program operation; if the target isn't current, call
  `instances_use(port)`. Never assume port 8192.
- Most tools accept an optional `port`; when working across several open programs, pass it
  explicitly rather than relying on "current".
- If `instances_list()` is empty, tell the user to open a CodeBrowser in Ghidra — do not
  retry in a loop.

### R2 — Respect the API contract, don't reinvent it
- Addresses are hex strings (`"0x401000"`). Names are FQN: `MyClass::method`; a bare name is
  the global namespace only. Renaming with `::` *moves* a symbol into that namespace.
- Responses are the `{success, result, _links, …}` envelope (the bridge strips
  `id/instance/timestamp`). Check `success` before using `result`; on `success=false` read
  `error.code` / `error.message`.
- Follow `_links` for pagination (`next`/`prev`) instead of guessing offsets.

### R3 — Mutations are real and must be deliberate
- Renames, signature/type/struct edits, comments, and memory/register writes change program
  state. State intent before mutating; prefer reversible steps; never bulk-rename
  speculatively.
- Decompile/analysis can be slow on big binaries (HTTP timeout 900s, decompile 1200s). Don't
  treat a long call as hung; surface partial/retry metadata when returned.

### R4 — Verification before claims
- After a mutation, re-read the affected item to confirm (e.g. `functions_get` after
  `functions_rename`). Don't report success from the request alone.

---

## Dynamic-emulation requirements (`ghydra-dynamic`)

### D1 — Choose the engine deliberately
- **Unicorn (`unicorn_*`)**: fast, in-process, lazily pulls bytes from Ghidra; x86-64 only;
  good for unpackers, tight loops, bulk `call`. Needs `ghydramcp[unicorn]` installed.
- **PCode (`emulation_*`)**: Ghidra's own emulator, any arch Ghidra models for stepping/state;
  the `call`/hooks primitive is x86-64 (sysv/ms). Use when Unicorn isn't installed or when you
  want Ghidra-native semantics / interactive stepping + breakpoints.
- The two share the same conceptual contract; the skill must present them as interchangeable
  and pick one, not blend calls from both on the same session.

### D2 — The call flow is fixed; follow it in order
1. `*_reset(start=func)` to create a session.
2. `*_hook_set(addr, action, …)` for **every** import/syscall the function reaches, or it
   will fault. Actions: `return_const` (sets RAX, may carry `mem_writes`), `skip`, `log`,
   `trap`.
3. `*_call(func, args, convention)` — `args` are ints and/or `{"bytes": hex}` pointer args;
   floats/by-value structs unsupported.
4. Inspect: `success` is true **only** for `stopReason`/`stop_reason == DONE`. On
   `HOOK_TRAP` / `REDIRECT_STORM` / `ERROR` / `LAZY_FETCH_FAILED` / `MAX_STEPS`, read the
   partial state, add the missing hook (a trap/fault usually means an un-stubbed call), retry.

### D3 — Read results, don't assume
- Return value is the return register (RAX) in the result; memory side-effects are read back
  with `*_read_memory`. PCode does **not** return a per-instruction memory-write trace
  (Unicorn-only); the skill must not rely on it for PCode.
- Dispose sessions (`*_dispose`) when done — sessions are stateful and not auto-cleaned.

### D4 — Surface faults usefully
- Map each non-DONE stop to an action for the user: `HOOK_TRAP`→which address trapped;
  `ERROR`→`last_error`; `REDIRECT_STORM`→a hook is looping; `MAX_STEPS`→raise `count` or the
  function doesn't return. Never silently treat a fault as success.

---

## Acceptance criteria for the skills

- A cold agent, given only "analyze function X in the open binary", runs
  `instances_list → instances_use → functions_get/decompile` without being told the API.
- Given "what does `sub_401000` return for input 5", the agent runs the full D2 flow,
  stubs the imports it hits, and reports the DONE return value (or the specific fault +
  the fix it would try) — without confusing Unicorn and PCode tools.
- Every reported finding that involved a mutation was verified per R4.
- No skill hard-codes port 8192 or assumes a single instance.

## Out of scope (for now)
- Non-x86-64 `call` (PCode stepping/state still works for other arches).
- Floating-point / by-value-struct call args.
- Automatic import discovery (the agent still decides what to hook from xrefs/decompile).
