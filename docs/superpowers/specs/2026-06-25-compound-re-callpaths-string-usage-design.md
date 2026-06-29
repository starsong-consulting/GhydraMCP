# Design — Compound RE Operations: Call Paths + String Usage Tracing

> Source gap: `docs/COMPETITIVE_GAPS.md` §3.5 "Compound RE Operations".
> Scope of this spec: the two call-graph/xref-based operations only —
> `functions_find_call_paths` and `strings_trace_usage`. The remaining §3.5
> operations (`cpp_vtable_analyze`, `cpp_classes_discover`, `functions_find_similar`)
> are explicitly **out of scope**.
> Date: 2026-06-25.

## 1. Overview

Add two high-level "compound" reverse-engineering operations that let an AI agent (or a
human via CLI) work at the level of *intent* instead of stitching together 10–20 primitive
calls:

1. **Call-path discovery** — "show me how execution can get from function A to function B."
2. **String-usage tracing** — "which functions use this string, and who calls them?"

Both are read-only analyses built on top of the existing call-graph / xref / string-listing
services. They follow the project's existing `/analysis/*` namespace convention and wire
through the full stack: Java plugin → MCP bridge → Python CLI, plus docs and tests.

## 2. Background — existing infrastructure reused

- `AnalysisService` (`service/AnalysisService.java`) already performs call-graph traversal
  (`callGraph`, `callers`, `callees`) using `FunctionService` + `XrefService`, wrapped in
  `GhidraSwing.runRead` (reentrant; runs the whole read on the EDT).
- `XrefService`: `getReferencesTo(program, addr)`, `getCallsTo(program, addr)`,
  `getCallsFromFunction(program, fn)` → `List<XrefDto>` with `fromAddress`/`toAddress` and
  `fromFunctionAddress`/`toFunctionAddress`.
- `FunctionService`: `requireFunctionByName`, `requireFunctionByAddress`, `findByAddress`
  (entry-point match), `findContaining(program, addr)` (function containing an address).
- `DataService.listStrings(program)` → `List<DataDto>` where each `DataDto` has
  `address`, `label`, `value`.
- HATEOAS envelope via `hateoas/Response` + `Paginator`; error envelope via
  `middleware/ErrorHandler`.

## 3. Architecture & placement (Approach A)

Both operations extend the existing `/analysis/*` family rather than introducing new
namespaces. This preserves the codebase's 1:1 convention (`analysis_*` MCP tool ↔
`/analysis/*` endpoint, e.g. `analysis_get_callgraph`).

- **Logic** → two new methods on `AnalysisService`: `findCallPaths(...)` and
  `traceStringUsage(...)`, plus private helpers. `AnalysisService` gains a constructor-injected
  `DataService` (for string enumeration) alongside its existing `FunctionService`/`XrefService`.
  **Both the no-arg constructor and the DI constructor are retained** (the no-arg path is what
  the embedded server instantiates; keeping it avoids reflection-instantiation breakage).
- **Routes** → two new handlers registered in `AnalysisResource.register(...)`.
- **DTOs** → `CallPathDto`, `StringUsageDto`, `CallerRefDto` (see §6).

All traversal runs inside a single `GhidraSwing.runRead(...)` per request, consistent with the
existing call-graph code.

## 4. Operation 1 — Call-path discovery

### 4.1 Endpoint

```
GET /analysis/callpaths
```

### 4.2 Parameters

| Param | Type | Default | Cap | Notes |
|---|---|---|---|---|
| `from` | string | — (required) | — | Function resolved by name **or** address. |
| `to` | string | — (required) | — | Function resolved by name **or** address. |
| `max_depth` | int | 5 | 15 | Max path length in edges. |
| `max_paths` | int | 50 | 500 | Max number of complete paths returned. |
| `max_visited_edges` | int | 10,000 | 100,000 | Deterministic search budget (see §4.4). |

Resolution accepts either form per param (mirrors `callgraph`'s name/address handling); an
address-looking value resolves by address, otherwise by name.

### 4.3 Algorithm

Directed DFS from `from`, expanding **callees** via
`xrefService.getCallsFromFunction(fn)` → `toFunctionAddress` → `functionService.findByAddress`.

- Maintain a visited set scoped to the **current path only**, so paths are simple (loop-free),
  but a function may appear across multiple distinct paths.
- Record a complete path when the frontier reaches the `to` function.
- Prune a branch when its depth reaches `max_depth`.
- Stop the whole search once `max_paths` complete paths are collected.
- Increment a `visitedEdges` counter on every edge expansion; if it reaches
  `max_visited_edges`, abort the search and return the paths found so far.

This is wrapped in one `GhidraSwing.runRead(...)`.

### 4.4 Bounding rationale

`max_visited_edges` is a **deterministic** budget (not a wall-clock timeout) so the traversal
is reproducible and unit-testable, and so a dense graph (e.g. paths between `main` and a
ubiquitous leaf) cannot block the EDT/`runRead` lock indefinitely. Hitting any cap
(`max_paths` or `max_visited_edges`) sets `truncated = true`.

### 4.5 Response

Not paginated — the result is a *set of paths*, bounded by `max_paths`.

```json
{
  "success": true,
  "result": {
    "from": "FUN_00401000",
    "to": "FUN_00405abc",
    "max_depth": 5,
    "max_paths": 50,
    "truncated": false,
    "paths": [
      { "length": 3, "functions": [ {FunctionSummaryDto}, {FunctionSummaryDto}, {FunctionSummaryDto} ] }
    ]
  },
  "_links": { "self": {...}, "function": {...}, "callgraph": {...} }
}
```

### 4.6 Errors

- Unresolvable `from`/`to` → 404 `FUNCTION_NOT_FOUND` (existing `requireFunction*` behavior).
- Missing `from` or `to` → 400.
- No path found is **not** an error: returns `paths: []`.

## 5. Operation 2 — String-usage tracing

### 5.1 Endpoint

```
GET /analysis/strings/usage
```

### 5.2 Parameters

| Param | Type | Default | Cap | Notes |
|---|---|---|---|---|
| `value` | string | — (required) | — | The search string. |
| `match` | enum | `substring` | — | `substring` (case-sensitive `contains`) or `regex` (`Pattern.find`). |
| `caller_depth` | int | 0 | 5 | 0 = direct users only; >0 walks the reverse call graph upward. |
| `max_strings` | int | 200 | 1,000 | Cap on matched strings processed/returned (applied before pagination). |
| `max_functions` | int | 500 | 5,000 | **Global** cap across the whole request's caller expansion. |

### 5.3 Algorithm

1. `dataService.listStrings(program)` → filter by `value` according to `match` in **one O(n)
   pass**, building the filtered list. (The full string-table scan cost is inherent and
   acceptable; pagination then slices the in-memory filtered list — no per-page re-scan.)
2. For each matched string: `xrefService.getReferencesTo(string.address)`; for each xref
   source, `functionService.findContaining(fromAddress)`; dedupe → **direct users**.
3. If `caller_depth > 0`, BFS **upward** from the union of direct users
   (`xrefService.getCallsTo` → `findContaining`), bounded by `caller_depth`, a single
   **global visited set** spanning the whole request, and the **global** `max_functions` cap.

### 5.4 Caller representation

`callers` is a **flat, globally-deduplicated list** of `CallerRefDto` (`{ function, depth }`),
**not** a nested tree. A function reachable as a caller of multiple direct users appears
**once**, under the first direct-user that reaches it (deterministic by processing order). The
global visited set prevents infinite loops on recursive functions and eliminates duplicate
sub-tree bloat in the JSON. `depth` is the BFS layer (1 = direct caller of a direct user).

### 5.5 Bounding

Reaching `max_strings` or the global `max_functions` cap sets `truncated = true` and stops
further expansion gracefully (partial results returned).

### 5.6 Response

Paginated over `matches` via the existing `Paginator` (`matches` is a flat list of matched
strings; `size`/`offset`/`limit` + `next`/`prev` apply).

```json
{
  "success": true,
  "result": {
    "value": "CreateFileW",
    "match": "substring",
    "caller_depth": 1,
    "truncated": false,
    "size": 2, "offset": 0, "limit": 50,
    "matches": [
      {
        "string": { "address": "0x004080a0", "value": "CreateFileW" },
        "directUsers": [ {FunctionSummaryDto} ],
        "callers": [ { "function": {FunctionSummaryDto}, "depth": 1 } ]
      }
    ]
  },
  "_links": { "self": {...}, "prev": {...}, "next": {...}, "program": {...} }
}
```

`callers` is omitted (or empty) when `caller_depth = 0`.

### 5.7 Errors

- Missing `value` → 400.
- `match=regex` with an invalid pattern → 400 with a clear message
  (`BadRequestException("Invalid regex pattern: <detail>")`) so the message reaches the MCP
  client (see §8).
- No matches is **not** an error: returns `matches: []`.

## 6. DTOs (`dto/`)

- `CallPathDto` — `record CallPathDto(int length, List<FunctionSummaryDto> functions)`.
- `CallerRefDto` — `record CallerRefDto(FunctionSummaryDto function, int depth)`.
- `StringUsageDto` — matched string `{address, value}`, `List<FunctionSummaryDto> directUsers`,
  `List<CallerRefDto> callers`. Built via a static factory consistent with the other DTOs.

Reuse `FunctionSummaryDto` throughout (already the call-graph summary shape).

## 7. Client wiring

### 7.1 MCP bridge (`bridge_mcp_hydra.py`)

Two tools in the `analysis_*` namespace:

- `analysis_find_call_paths(from_fn, to_fn, max_depth=5, max_paths=50, port=None)`
- `analysis_trace_string_usage(value, match="substring", caller_depth=0, offset=0, limit=50, port=None)`

Each proxies its endpoint via the standard request helper, returning the result through
`simplify_response` (which strips `id`/`instance`/`timestamp` but preserves `error`).
No `API_VERSION` change (additive). See §8 for error propagation.

### 7.2 Python CLI (`ghydra/cli/analysis.py`)

Two commands in the existing `analysis` group:

- `ghydra analysis call-paths --from <fn> --to <fn> [--max-depth N] [--max-paths N]`
- `ghydra analysis string-usage <value> [--match substring|regex] [--caller-depth N] [--limit N] [--offset N]`

Both honor the global `--host/--port/--json/--no-color` flags.

### 7.3 Formatters

Add a format method to **all three** formatters (`BaseFormatter`, `TableFormatter`,
`JSONFormatter`) for each command, per the CLAUDE.md convention.

- `TableFormatter` for call-paths: one row per path (index, length, `A → B → C` arrow chain).
- `TableFormatter` for string-usage: the matched strings table; for `caller_depth > 0`, render
  the flat `callers` list with a **`depth` column** (or depth-derived `├─`/`└─` indentation on
  the function name). Because `callers` is already flat, no nested-tree rendering is needed.
- `JSONFormatter`: passthrough of the raw result.

## 8. Error handling / bubbling

The plugin must emit a proper error envelope with a human-readable `error.message` for the
controlled failures (400 invalid regex, 404 unresolvable function). The bridge request helper
already normalizes error bodies into `{code, message, status_code}`, and the MCP tools return
that envelope through `simplify_response` **unchanged**, so a bad regex surfaces to the
LLM/user as the specific message (e.g. "Invalid regex pattern: …") rather than a generic
"500 Server Error". This is a hard requirement and is covered by a bridge test (§10).

## 9. Versioning (CLAUDE.md rules)

Purely additive REST routes/tools → **bump `PLUGIN_VERSION` and `BRIDGE_VERSION`; do NOT bump
`API_VERSION`/`REQUIRED_API_VERSION`.** Update `CHANGELOG.md` with the user-facing additions.

## 10. Testing

No offline Java harness exists yet (that is the separate §6.1 gap, out of scope here), so we
follow existing precedent — live-instance integration tests that auto-skip without Ghidra.

- `test_http_api.py` — both endpoints, mirroring the existing `/analysis/callgraph` test:
  - call-paths: a known path returns ≥1 path; `max_depth` prunes; `max_paths` cap sets
    `truncated`; `max_visited_edges` cap sets `truncated`; no-path returns `[]`; missing
    `from`/`to` → 400; bad function → 404.
  - string-usage: `substring` vs `regex` match; `caller_depth=0` (no `callers`) vs `>0`
    (flat list with `depth`); global `max_functions` cap sets `truncated`; pagination over
    `matches`; invalid regex → 400 with message; no-match returns `[]`.
- `test_mcp_client.py` — both bridge tools, including the **invalid-regex error message
  passthrough** assertion (§8).

## 11. Out of scope / non-goals

- The other §3.5 operations (`cpp_vtable_analyze`, `cpp_classes_discover`,
  `functions_find_similar`).
- Any offline Java test harness (§6.1).
- Subagent-based result chunking — output size is handled server-side (caps + pagination);
  how an agent consumer chooses to chunk a large response is a consumer concern.
- Cross-binary / multi-program features.

## 12. Resolved decisions (no open questions)

- Naming/placement: Approach A (`/analysis/*`, `analysis_*` tools).
- Call-paths: bounded all-simple-paths (`max_depth` + `max_paths` + deterministic
  `max_visited_edges`).
- String match: `substring` (default) | `regex`; `caller_depth` 0..5.
- Callers: flat, globally-deduplicated list with `depth`; global visited set + global
  `max_functions` cap.
- Wiring: full stack (plugin + bridge + CLI) + docs + version bumps.
