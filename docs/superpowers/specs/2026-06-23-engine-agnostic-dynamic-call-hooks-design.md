# Engine-agnostic dynamic call & hooks — design

> Date: 2026-06-23. Branch: `feature/pcode-emulation`.
> Predecessors: `2026-06-21-unicorn-failure-contract-design.md`,
> `2026-06-22-unicorn-dynamic-hardening.md` (executed).
> Status: approved design, ready for implementation plan.

## Goal

Give an AI agent two new dynamic-analysis capabilities, delivered identically
across both concrete-execution engines (Ghidra PCode and Unicorn):

1. **Import/syscall hooking (stubs)** — register a handler on a target address or
   resolved symbol so a `call` into an unmapped import does not dead-end at
   `LAZY_FETCH_FAILED` (Unicorn) or wander (PCode). The agent stubs the callee
   instead of faulting into it.
2. **High-level `call(func, args)`** — set up the calling convention, run the
   function to completion against a synthetic return address, and report the
   return value plus memory side-effects. Useless on real code *without* hooking
   (inner calls hit imports), so the two ship together.

On top of these primitives the user will later build a dedicated **agent skill
set for this MCP**; the design therefore optimizes for clean, composable,
stable primitives over breadth.

## Non-goals (explicit, deferred to later specs)

- XMM/float arguments and by-value struct arguments (ABI-specific decomposition).
  `call` v1 supports **integer and pointer (`{"bytes": hex}`) arguments only**.
- Snapshot / restore of session state (branch-and-rollback exploration).
- Unicorn non-x86-64 architectures (register map + start registers are
  x86-64-hardcoded today).
- The agent skill set itself (separate spec once these primitives are stable).
- Hook persistence across `reset` is **decided, not deferred**: hooks are
  session-scoped and wiped on reset (see Hook lifecycle).

## Architecture decision: two namespaces, one shared contract

GhydraMCP carries two concrete-execution engines that live in different
languages and process layers:

- **PCode** — Java, in-process with Ghidra, `EmulationService.java` driving
  `EmulatorHelper`. Same address space/symbols/image as the program;
  architecture-neutral (any SLEIGH spec). Interpreted PCode, slower.
- **Unicorn** — Python, in-process with the bridge, `unicorn_engine.py`. JIT
  (QEMU TCG) fast on tight loops; hardcoded x86-64; separate, lazily-mapped
  memory.

We keep the **two existing namespaces separate** (`emulation_*` = PCode,
`unicorn_*` = Unicorn) and give them an **identical contract**: same action
vocabulary, same unified stop-reason set, same DTO shapes, same
calling-convention rules. "Engine-agnostic facade" therefore means *one contract
expressed across two namespaces*, not one namespace with an `engine=` switch.
This matches the existing bridge convention, has zero blast radius on current
tools, and maps naturally onto the intended "parallel subagents on different
engines" workflow.

Per-instruction hook dispatch **cannot** be orchestrated from the bridge over
HTTP (one round-trip per instruction). Hook and `call` *execution* is therefore
implemented natively inside each engine's run loop:

- PCode: inside `EmulationService.run()` / `stepOnce()` (Java).
- Unicorn: inside `UnicornSession.run()`'s `UC_HOOK_CODE` callback (Python).

The only genuinely shared *logic* is the calling-convention arg-marshalling
table + alignment math, captured once as pure functions and unit-tested
directly in each language.

### Sessions and concurrency

Sessions stay keyed per engine so two subagents can run PCode and Unicorn
against the same program concurrently without colliding:

- PCode: the existing per-`Program` `sessions` map in `EmulationService`.
- Unicorn: the existing locked `_UNICORN_SESSIONS` registry (keyed by port).

## Unified stop reasons

Each engine maps its native reason onto one closed set; the engine-native value
is preserved in a `detail` field for diagnosis.

| Unified      | PCode native              | Unicorn native                       |
|--------------|---------------------------|--------------------------------------|
| `COMPLETED`  | TARGET_REACHED (incl. `call` sentinel) | DONE / sentinel-fetch       |
| `BREAKPOINT` | BREAKPOINT                | (no breakpoint primitive yet)        |
| `HOOK_TRAP`  | (new — via breakpoint path) | (new — stop-in-code-hook)          |
| `STEP_LIMIT` | MAX_STEPS                 | COUNT                                |
| `UNMAPPED`   | ERROR (no image bytes)    | LAZY_FETCH_FAILED / LAZY_CAP_REACHED |
| `ERROR`      | ERROR                     | ERROR                                |

`success` is true only for `COMPLETED`. `BREAKPOINT` and `HOOK_TRAP` are
"stopped as intended," not failures: an agent derives `intended_stop` as
`stop_reason ∈ {COMPLETED, BREAKPOINT, HOOK_TRAP}` (documented; not a stored
field).

**Where the unified vocabulary lives.** The unified names are a **wire/bridge-
layer** vocabulary, not a rewrite of the engines' internal enums. The Java
`StopReason` enum grows exactly one genuinely-new value — `HOOK_TRAP` — and
otherwise keeps its existing names (`TARGET_REACHED`, `MAX_STEPS`, …); it does
**not** gain a `COMPLETED` value (a `call` completion stays `TARGET_REACHED`
internally, since the sentinel is just an `until` target). The bridge formatters
own the translation to the unified set (`TARGET_REACHED`/sentinel → `COMPLETED`,
`MAX_STEPS` → `STEP_LIMIT`, etc.). Unicorn similarly keeps its native constants
and translates at the bridge. The implementation plan must state this mapping
table explicitly so it is not re-derived.

## Hook registry (the stub mechanism)

A session carries a registry of hooks keyed by **address**. Symbol/import names
are resolved to addresses **eagerly at registration** (via
`symbols_imports`/`symbols_exports`), so the per-instruction hot path is a pure
address-map lookup (same cost as the existing `breakpoints` set check).
Registration **hard-errors immediately** if a symbol cannot be resolved.

Before executing the instruction at an address, the engine consults the
registry; a present hook applies its **action** instead of (or alongside) normal
execution.

### Action vocabulary (closed set, identical both engines)

| Action          | Effect |
|-----------------|--------|
| `return_const`  | Set the ABI return register to `return_value`, then `simulate_ret` (the call never executes). May carry `mem_writes` side-effects applied before resuming. |
| `skip`          | `call` target → `simulate_ret` with the return register **untouched**; non-`call` → advance PC past the instruction (`PC += instruction_length`). No side effects. |
| `log`           | Resolve and record the first N arguments into the session trace, then continue normally (non-intercepting). |
| `trap`          | Halt with `HOOK_TRAP`, surfacing PC + resolved args; hand control back to the agent. |

`mem_writes` (`[{address, hex}]`) are allowed **only on `return_const`** (faking
`malloc`/`strcpy`-style buffer effects). Not on `log`/`skip` (YAGNI).

### `simulate_ret(session, return_value=None)` — shared contract

`EmulatorHelper` exposes no push/pop, so the ret sequence is an explicit named
helper with the same contract in both engines:

1. `addr = read RSP`
2. `ret = read_memory(addr, 8)` (little-endian)
3. `write PC = ret`
4. `write RSP = addr + 8`
5. if `return_value` is not None: `write <return reg> = return_value`

The helper can fail if RSP points at unmapped memory at hook time; that surfaces
as `ERROR` with a clear message.

### Per-engine execution

- **PCode (Java):** at the top of the `run()` loop, before `stepOnce`, consult
  the hook map for the current PC. `return_const`/`skip`/`trap` are applied
  *instead of* `stepOnce` (via `writeRegister`/`writeMemory` + `simulate_ret`);
  `log` records then falls through to `stepOnce`. `trap` reuses the existing
  breakpoint-halt machinery, surfacing `HOOK_TRAP` (a distinct stop_reason from
  an explicit `BREAKPOINT`) plus resolved args. `skip` on a non-`call`
  instruction reads the instruction length from the program listing.
- **Unicorn (Python):** the `UC_HOOK_CODE` callback already fires per
  instruction — consult the hook map there; apply via `reg_write`/`mem_write` +
  `simulate_ret`. `trap` calls `emu_stop()` and sets `HOOK_TRAP` via the
  established flag pattern.

### Hook lifecycle

Hooks persist across `run`/`step`/`call` within a session. They are
**session-scoped: wiped on `reset`** (which replaces the `Session` /
`UnicornSession` object — a clean slate, the correctness-safe choice). The
"same stubs, different inputs" RE workflow is served by registering hooks once
and calling **`call()` repeatedly**; `call` does not wipe hooks, so reset
wiping them costs that workflow nothing.

## `call(func, args)` primitive

One tool per namespace (`emulation_call` / `unicorn_call`), built on the hooks
and the auto-stack:

1. **Resolve target.** A named function → `function.getEntryPoint()` (start at
   the prologue); otherwise (shellcode, mid-function, address-only) → raw
   `resolveAddress`.
2. **Ensure a stack.** Reuse the opt-in auto-stack (Unicorn already has it;
   PCode gains it — see Prerequisite). If no SP is set, allocate scratch and
   point SP mid-region.
3. **Marshal args** per the resolved calling convention (table below). Integer
   args → registers then stack; a `{"bytes": hex}` arg is written into the
   scratch region and the **pointer** is passed.
4. **Push the sentinel** return address (see below).
5. **Run until** PC == sentinel → `COMPLETED`. A hook `trap`/`HOOK_TRAP`,
   `UNMAPPED`, or `ERROR` short-circuits and returns that reason with full
   state, so the agent can add a missing hook and retry.
6. **Report** via `CallResultDto`: `return_value` (return reg), `convention`,
   `args_passed`, final registers, `mem_writes` (when `trace`), unified
   `stop_reason`, `detail`.

### Calling conventions (v1: x86-64 only)

| Convention      | Integer args                                  | Return | Notes |
|-----------------|-----------------------------------------------|--------|-------|
| `x86-64 SysV`   | RDI, RSI, RDX, RCX, R8, R9, then stack         | RAX    | default on non-Windows x64 |
| `x86-64 MS`     | RCX, RDX, R8, R9, then stack, **+32B shadow**  | RAX    | shadow space pre-allocated |

Resolution order: explicit `convention=` arg → cached `compiler_spec_id` on the
instance (`"windows"` → MS) → **SysV fallback** (also when the field is empty /
not yet discovered). **Unsupported architecture ⇒ `call` is rejected**, as are
`return_const` and `skip`-on-`call` hooks (they require a known return register);
`log`/`trap` arg resolution merely degrades to `null` on unsupported arch.

### Stack discipline (must be explicit in code)

- **MS shadow space:** after writing the 4 register args and before pushing any
  stack-position args, `RSP -= 32`. Omitting this corrupts stack args when the
  callee spills into the shadow.
- **Bytes-arg scratch layout:** bytes-args bump-allocate from the **bottom** of
  the scratch region (low addresses, growing up); the real stack lives at the
  **top** (growing down), with a defined split point so the two never collide.
  The cumulative bytes-args allocation is **bounded by the split point** (e.g.
  256 KiB of a 1 MiB scratch region); a `call` whose `{"bytes"}` args exceed it
  is rejected with a clear message rather than overrunning into the stack.
- **16-byte alignment:** the ABI requires `RSP ≡ 0 (mod 16)` at the call site,
  i.e. `RSP ≡ 8 (mod 16)` at callee entry (return address occupies the low 8
  bytes). Since we set PC directly and push the sentinel manually, align
  explicitly: push stack args, 16-align RSP, then push the 8-byte sentinel so
  entry satisfies `RSP ≡ 8 (mod 16)`.

### Sentinel return address

A deliberately **unmapped** address (outside image and auto-stack) so a real
`ret` to it cannot collide with code.

- **Unicorn:** when PC reaches the unmapped sentinel, the fetch faults into
  `UC_HOOK_MEM_UNMAPPED` (the code hook never fires for unmapped pages). The
  guard sits in `_unmapped_hook` as the **first** check, gated on the access
  type:

  ```python
  if access == UC_MEM_FETCH_UNMAPPED and (address & ~(PAGE - 1)) == SENTINEL_PAGE:
      stop_signal["reason"] = StopReason.COMPLETED
      return False  # stop; translate the resulting UcError to COMPLETED
  ```

  The `UC_MEM_FETCH_UNMAPPED` gate is required: a wild data read/write to the
  sentinel page must **not** be misclassified as completion. In the
  `except UcError` handler, the sentinel `COMPLETED` check has **priority over**
  `lazy_fail` — a completion is not a failure.
- **PCode:** set as the `run()` loop's `until` address; `pc.equals(until)` is
  checked at the top of the loop before any fetch, so the sentinel page never
  needs mapping. `TARGET_REACHED` → `COMPLETED`.

### Prerequisite (in this spec): PCode auto-stack

`call` is impossible on PCode without a stack (nothing to push the sentinel
onto). `EmulationService.reset()` gains an opt-in `auto_stack: boolean`
(`ResetRequest` field) mirroring Unicorn's `_apply_default_stack`: allocate a
~1 MiB scratch region, point RSP/RBP mid-region, record the stack base on the
`Session`. `EmulatorHelper` manages its own address space, so this is a
`writeMemory` of zeroes + `writeRegister` — no `mem_map` equivalent needed.

## Tool / REST / CLI surface

### MCP tools (mirrored, identical contract)

| PCode                  | Unicorn              | Purpose |
|------------------------|----------------------|---------|
| `emulation_hook_set`   | `unicorn_hook_set`   | register a hook: `address`/`symbol`, `action`, `return_value?`, `mem_writes?` |
| `emulation_hook_clear` | `unicorn_hook_clear` | remove the hook at an address |
| `emulation_hook_list`  | `unicorn_hook_list`  | inspect registered hooks (separate from breakpoint state) |
| `emulation_call`       | `unicorn_call`       | `func`, `args[]`, `convention?`, `trace?` → `CallResultDto` |

### REST (Java / PCode)

New routes on `EmulationResource`, logic in `EmulationService`:

- `POST /emulation/hooks` (set), `DELETE /emulation/hooks/{address}` (clear),
  `GET /emulation/hooks` (list)
- `POST /emulation/call` → `CallResultDto`
- `ResetRequest` gains `auto_stack: boolean`
- `EmulationStateDto` gains an additive-nullable `detail` (engine-native reason).
  `CallResultDto` is a **new** DTO returned only by `/emulation/call`
  (`return_value`, `convention`, `args_passed`, `mem_writes`, `stop_reason`,
  `detail`) — keeping `call`'s richer shape off the state snapshot.

### Unicorn (no REST — in-process with the bridge)

`UnicornSession` gains a hook-registry dict + `call()`; the bridge `unicorn_*`
tools dispatch directly. Hooks persist across MCP calls within the bridge
process via `_UNICORN_SESSIONS`.

### CLI (`ghydra`)

- `emulation` group (REST-backed, persistent Java session): gains
  `hook set/clear/list` and `call` subcommands.
- `dynamic` group (Unicorn): **per-invocation** — `_make_session` creates an
  ephemeral session per command, so a separately-registered hook would not
  survive to a later `call`. Therefore the CLI composes hooks **into** the call:
  `ghydra dynamic call --func F --hook addr:action[:retval] ...`. The persistent
  hook-registry story is MCP-only.
- Formatters updated in all three (`Table`/`JSON`) per CLAUDE.md.

### Versioning

Additive only ⇒ `API_VERSION` **unchanged**. `BRIDGE_VERSION`
`v3.1.0-rc.3` → `rc.4` (graduating to `v3.2.0` when the feature lands complete);
`PLUGIN_VERSION` bumped in parallel. `CHANGELOG.md` updated.

## Testing

- **Unicorn (Python, no live Ghidra — the bulk, runs in CI like the existing 35
  tests):** hook registry per action; `simulate_ret`; the sentinel
  `_unmapped_hook` guard incl. fetch-vs-data discrimination and `COMPLETED`-over-
  `lazy_fail` priority; bytes-arg bump allocation + stack/arg split; convention
  marshalling (SysV vs MS arg slots, shadow space, 16-byte alignment); `call()`
  end-to-end on a tiny hand-assembled shellcode blob mapped via `map_bytes`.
- **Shared marshalling logic:** convention table + alignment math as pure
  functions, unit-tested directly.
- **PCode (Java):** pure functions — `simulate_ret` arithmetic, convention/
  alignment table — go in `EmulationServiceTest.java` and **run now** under
  `mvn test` (no Ghidra dependency). Only live-`EmulatorHelper` integration
  (hook firing during a real `stepOnce`, `call` round-trip) is **deferred** to
  the JUnit/live-Ghidra harness gap tracked alongside the existing `stepOnce`
  BREAKPOINT-vs-ERROR coverage deferral. The deferred label must not shelter
  anything testable today.

## Risks / assumptions

- **PCode hook interception point.** Applying actions *before* `stepOnce` (vs
  `EmulatorHelper`'s post-step model) must correctly leave PC/SP so the next
  loop iteration resumes cleanly. Validated conceptually against the existing
  breakpoint-halt path; final confirmation lands with the deferred live-Ghidra
  integration tests.
- **Sentinel collision-freedom** depends on choosing an address outside image +
  auto-stack; both engines keep it unmapped by construction.
- **Convention detection** relies on the cached `compiler_spec_id`; the SysV
  fallback covers the not-yet-discovered / empty case.
