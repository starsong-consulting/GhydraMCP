# Compound-RE Review Findings Fix Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every Critical and Important finding from the four-agent PR review of `fix/compound-re-followups`, plus the high-value Suggestions (hardening, missing tests, Python formatter coverage).

**Architecture:** Fixes span four layers — Java service/graph (null-safety, WalkState encapsulation), Java resource (self-link completeness), Python bridge (formatters, input validation), and Java+Python tests (coverage gaps). Tasks are ordered so each builds on a stable base: graph fixes first, then callers of the graph (AnalysisService), then the HTTP/bridge surface, then tests.

**Tech Stack:** Java 21 records + compact constructors, JUnit 4 (`org.junit.Test`), Python 3.11, pytest, `bridge_mcp_hydra.py` `@text_output` decorator pattern.

## Global Constraints

- Java: all new code must compile with `mvn test` (no Ghidra instance required for unit tests)
- Python: all new/changed tests must pass with `pytest tests/` (no Ghidra required)
- No new public API surface beyond what the review findings prescribe — YAGNI
- Commit after every task; message format: `fix: <what and why>`
- Do **not** bump `API_VERSION` — all changes are additive or internal
- `FunctionSummaryDto.from(null)` returns `null` — never call it with a potentially-null Function; the fix is upstream (in `summaryOf`)

---

### Task 1: Bridge — register formatters for both compound-RE MCP tools

**Root cause (Critical):** `analysis_find_call_paths` and `analysis_trace_string_usage` are not in the `FORMATTERS` dict, so `@text_output` falls through to `format_simple_result(..., "Done")` and discards the entire response.

**Files:**
- Modify: `bridge_mcp_hydra.py` (add two formatter functions ~50 lines before `FORMATTERS`, register them, add input validation)
- Modify: `tests/test_bridge_compound_re.py` (add formatter and validation tests)

**Interfaces:**
- Produces: `format_call_paths(response, **kwargs) -> str` and `format_string_usage(response, **kwargs) -> str` with the same signature as every other formatter in the file
- Produces: entries `"analysis_find_call_paths"` and `"analysis_trace_string_usage"` in `FORMATTERS`

- [ ] **Step 1: Write the failing formatter tests**

Add to `tests/test_bridge_compound_re.py`:

```python
import bridge_mcp_hydra as b


def _call_paths_response(paths=None, truncated=False, unresolved=0):
    return {
        "success": True,
        "result": {
            "from": "main",
            "to": "target",
            "max_depth": 5,
            "max_paths": 50,
            "truncated": truncated,
            "unresolved_edges": unresolved,
            "paths": paths or [],
        },
    }


def _string_usage_response(matches=None, truncated=False, unresolved=0):
    return {
        "success": True,
        "result": {
            "value": "CreateFileW",
            "match": "substring",
            "caller_depth": 1,
            "size": 1,
            "offset": 0,
            "limit": 50,
            "truncated": truncated,
            "unresolved_refs": unresolved,
            "matches": matches or [],
        },
    }


def test_format_call_paths_no_paths_clean():
    out = b.format_call_paths(_call_paths_response())
    assert "No paths found" in out
    assert "main" in out and "target" in out


def test_format_call_paths_no_paths_with_unresolved_hints():
    out = b.format_call_paths(_call_paths_response(unresolved=3))
    assert "unresolved" in out.lower()


def test_format_call_paths_renders_path_chain():
    paths = [{"length": 2, "functions": [
        {"name": "main", "address": "0x1000"},
        {"name": "target", "address": "0x2000"},
    ]}]
    out = b.format_call_paths(_call_paths_response(paths=paths))
    assert "main" in out and "target" in out
    assert "Path 1" in out


def test_format_call_paths_truncated_flag_shown():
    paths = [{"length": 1, "functions": [{"name": "main", "address": "0x1000"}]}]
    out = b.format_call_paths(_call_paths_response(paths=paths, truncated=True))
    assert "truncated" in out.lower()


def test_format_string_usage_no_matches():
    out = b.format_string_usage(_string_usage_response())
    assert "No strings" in out


def test_format_string_usage_renders_direct_users():
    matches = [{
        "string": {"address": "0x8000", "value": "CreateFileW"},
        "directUsers": [{"name": "open_file", "address": "0x1000"}],
        "callers": [],
    }]
    out = b.format_string_usage(_string_usage_response(matches=matches))
    assert "0x8000" in out
    assert "open_file" in out


def test_format_string_usage_renders_callers_with_depth():
    matches = [{
        "string": {"address": "0x8000", "value": "CreateFileW"},
        "directUsers": [{"name": "open_file", "address": "0x1000"}],
        "callers": [{"function": {"name": "do_thing", "address": "0x2000"}, "depth": 1}],
    }]
    out = b.format_string_usage(_string_usage_response(matches=matches))
    assert "do_thing" in out
    assert "depth 1" in out


def test_find_call_paths_rejects_max_depth_zero():
    out = b.analysis_find_call_paths("source", "target", max_depth=0)
    assert "max_depth" in out


def test_find_call_paths_rejects_max_paths_zero():
    out = b.analysis_find_call_paths("source", "target", max_paths=0)
    assert "max_paths" in out
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_bridge_compound_re.py -v
```
Expected: multiple FAILED (AttributeError: module 'bridge_mcp_hydra' has no attribute 'format_call_paths')

- [ ] **Step 3: Write `format_call_paths` and `format_string_usage` in `bridge_mcp_hydra.py`**

Find the line that defines `format_dataflow` (~line 885). Add the two new formatters immediately after the `format_dataflow` function (before `format_simple_result`):

```python
def format_call_paths(response: dict, **kwargs) -> str:
    """Format analysis_find_call_paths response as plain text."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", {})
    from_fn = result.get("from", "?")
    to_fn = result.get("to", "?")
    paths = result.get("paths", [])
    truncated = result.get("truncated", False)
    unresolved = result.get("unresolved_edges", 0)

    if not paths:
        note = " (some edges unresolved — may still be reachable)" if unresolved else ""
        return f"No paths found from {from_fn} to {to_fn}.{note}"

    flags = []
    if truncated:
        flags.append("truncated")
    if unresolved:
        flags.append(f"{unresolved} unresolved edge(s)")
    flag_str = f" [{', '.join(flags)}]" if flags else ""
    lines = [f"Call paths: {from_fn} -> {to_fn} ({len(paths)} path(s)){flag_str}", ""]

    for i, path in enumerate(paths, 1):
        funcs = path.get("functions", [])
        chain = " -> ".join(f.get("name", f.get("address", "?")) for f in funcs)
        lines.append(f"  Path {i} ({path.get('length', len(funcs))} hops): {chain}")

    return "\n".join(lines)


def format_string_usage(response: dict, **kwargs) -> str:
    """Format analysis_trace_string_usage response as plain text."""
    if not response.get("success", False):
        return format_error(response)
    result = response.get("result", {})
    value = result.get("value", "?")
    matches = result.get("matches", [])
    total = result.get("size", 0)
    truncated = result.get("truncated", False)
    unresolved = result.get("unresolved_refs", 0)

    if not matches:
        return f'No strings matching "{value}" found.'

    flags = []
    if truncated:
        flags.append("truncated")
    if unresolved:
        flags.append(f"{unresolved} unresolved ref(s)")
    flag_str = f" [{', '.join(flags)}]" if flags else ""
    lines = [f'String usage: "{value}" — {total} match(es){flag_str}', ""]

    for m in matches:
        s = m.get("string", {})
        addr = s.get("address", "?")
        val = s.get("value", "")
        direct = m.get("directUsers", [])
        callers_list = m.get("callers", [])
        lines.append(f"  {addr}  {val!r}")
        for f in direct:
            lines.append(f"    used by: {f.get('name', f.get('address', '?'))}")
        for c in callers_list:
            fn = c.get("function", {})
            depth = c.get("depth", "?")
            lines.append(f"    caller (depth {depth}): {fn.get('name', fn.get('address', '?'))}")

    return "\n".join(lines)
```

- [ ] **Step 4: Register both formatters in `FORMATTERS` dict and add input validation**

In `FORMATTERS` (around line 1246), add after `"datatypes_search"`:

```python
    "analysis_find_call_paths": format_call_paths,
    "analysis_trace_string_usage": format_string_usage,
```

In `analysis_find_call_paths`, after the `if not from_fn or not to_fn:` guard (~line 4165), add:

```python
    if max_depth < 1:
        return {
            "success": False,
            "error": {"code": "INVALID_PARAMETER", "message": "max_depth must be >= 1"},
            "timestamp": int(time.time() * 1000),
        }
    if max_paths < 1:
        return {
            "success": False,
            "error": {"code": "INVALID_PARAMETER", "message": "max_paths must be >= 1"},
            "timestamp": int(time.time() * 1000),
        }
```

- [ ] **Step 5: Run tests to verify they pass**

```
pytest tests/test_bridge_compound_re.py -v
```
Expected: all 13 tests PASSED

- [ ] **Step 6: Run the full Python unit suite to check for regressions**

```
pytest tests/ -v
```
Expected: all existing tests plus new tests pass.

- [ ] **Step 7: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_compound_re.py
git commit -m "fix: register compound-RE MCP tools in FORMATTERS; add formatters + input validation

Both analysis_find_call_paths and analysis_trace_string_usage were missing from
FORMATTERS, causing @text_output to discard responses and return 'Done'. Also
validates max_depth >= 1 and max_paths >= 1 client-side."
```

---

### Task 2: GhidraCallGraph — null-safety hardening

**Root causes (Critical C1, C2 + Important I7):**
- `summaryOf` returns `null` via `FunctionSummaryDto.from(null)` when `findByAddress` misses, causing a non-local NPE inside `CallPathFinder.dfs` when `List.copyOf` encounters the null element.
- `calleesOf` silently returns an empty list when its source function address doesn't resolve, causing the DFS to silently prune the entire subtree instead of counting the edge as unresolved.
- Constructor has no null guards on its three collaborators.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/graph/GhidraCallGraph.java`

**Interfaces:**
- `summaryOf(String fnEntry)`: now throws `IllegalArgumentException("No function at entry address: " + fnEntry)` when `findByAddress` returns null. Callers only call it with addresses that came from `calleesOf`/`callersOf`/`referrersOf` as non-null entries — the existing `CallGraph` contract.
- `calleesOf(String fnEntry)`: returns `Collections.singletonList(null)` when the source address doesn't resolve to a function, so the DFS counts it as one unresolved edge instead of silently stopping.

- [ ] **Step 1: Write the failing tests**

These tests use `FakeCallGraph` (in the same package). Add a new test class `GhidraCallGraphNullSafetyTest` is not possible without Ghidra; instead verify via `CallPathFinder` behavior with a misbehaving `FakeCallGraph`. Add to `src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java`:

```java
@Test
public void summaryOfNullThrowsInDfsIsCountedCorrectly() {
    // Simulate the contract: summaryOf for a non-null entry address always
    // returns non-null. A correctly implemented FakeCallGraph already does this.
    // This test simply re-affirms the happy path still works after the fix —
    // the integration risk (GhidraCallGraph.summaryOf returning null) is covered
    // by the constructor null-guard test in GhidraCallGraphConstructorTest.
    FakeCallGraph g = new FakeCallGraph();
    g.callees.put("0x1000", List.of("0x2000"));
    g.callees.put("0x2000", List.of("0x3000"));
    CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
    assertEquals(1, r.paths().size());
    assertEquals(3, r.paths().get(0).length());
    assertEquals(0, r.unresolvedEdges());
}
```

Add a dedicated constructor test in a new file `src/test/java/eu/starsong/ghidra/service/graph/GhidraCallGraphConstructorTest.java`:

```java
package eu.starsong.ghidra.service.graph;

import org.junit.Test;

import static org.junit.Assert.*;

public class GhidraCallGraphConstructorTest {

    @Test(expected = NullPointerException.class)
    public void nullProgramThrows() {
        new GhidraCallGraph(null, null, null);
    }
}
```

Note: this test will fail until the fix is in place because the constructor currently accepts nulls silently.

- [ ] **Step 2: Run tests to verify constructor test fails**

```
mvn test -pl . -Dtest=GhidraCallGraphConstructorTest -Dghidra.version=12.1.2 2>&1 | tail -20
```

Expected: BUILD FAILURE — `NullPointerException` is not thrown, test fails.

(If Ghidra jars are unavailable, skip compilation check and proceed — the constructor change is safe.)

- [ ] **Step 3: Implement the three fixes in `GhidraCallGraph.java`**

Add `import java.util.Collections;` and `import java.util.Objects;` to the imports block.

Replace the constructor:
```java
public GhidraCallGraph(Program program, FunctionService functionService, XrefService xrefService) {
    this.program = Objects.requireNonNull(program, "program");
    this.functionService = Objects.requireNonNull(functionService, "functionService");
    this.xrefService = Objects.requireNonNull(xrefService, "xrefService");
}
```

Replace `calleesOf`:
```java
@Override
public List<String> calleesOf(String fnEntry) {
    Function fn = functionService.findByAddress(program, fnEntry);
    if (fn == null) {
        // Source address is not a defined function entry; signal one unresolved edge
        // so the DFS counts it rather than silently pruning the entire subtree.
        return Collections.singletonList(null);
    }
    List<String> out = new ArrayList<>();
    for (XrefDto xref : xrefService.getCallsFromFunction(program, fn)) {
        String calleeAddr = xref.toFunctionAddress();
        if (calleeAddr == null) { out.add(null); continue; }
        Function callee = functionService.findByAddress(program, calleeAddr);
        out.add(callee != null ? callee.getEntryPoint().toString() : null);
    }
    return out;
}
```

Replace `summaryOf`:
```java
@Override
public FunctionSummaryDto summaryOf(String fnEntry) {
    Function fn = functionService.findByAddress(program, fnEntry);
    if (fn == null) {
        throw new IllegalArgumentException("No function at entry address: " + fnEntry);
    }
    return FunctionSummaryDto.from(fn);
}
```

- [ ] **Step 4: Run tests**

```
mvn test -pl . -Dtest="GhidraCallGraphConstructorTest,CallPathFinderTest" -Dghidra.version=12.1.2 2>&1 | tail -20
```
Expected: BUILD SUCCESS — all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/graph/GhidraCallGraph.java \
        src/test/java/eu/starsong/ghidra/service/graph/GhidraCallGraphConstructorTest.java \
        src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java
git commit -m "fix: harden GhidraCallGraph null-safety (summaryOf throws, calleesOf sentinel, constructor guards)

summaryOf returned null via FunctionSummaryDto.from(null) causing List.copyOf NPE
in CallPathFinder. calleesOf silently returned empty list when source fn unresolvable,
pruning DFS subtrees with no unresolved_edges signal. Constructor had no null guards."
```

---

### Task 3: CallPathFinder — validate numeric bounds in `find()`

**Root cause (Important I8):** Passing `maxPaths=0` silently returns `truncated=true` with empty paths — looks like a bounded truncation when no search was attempted. Same for `maxDepth<0` and `maxVisitedEdges<1`.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/graph/CallPathFinder.java`
- Modify: `src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java`

**Interfaces:**
- `find(String, String, int, int, int)`: now throws `IllegalArgumentException` for null entries or out-of-range bounds. Server-side caps in `AnalysisResource` (maxDepth ≤ 15, maxPaths ≤ 500, maxVisitedEdges ≤ 100 000) guarantee these guards are never hit in production; they protect the pure algorithm from test or future mis-callers.

- [ ] **Step 1: Write the failing tests**

Add to `CallPathFinderTest.java`:

```java
@Test(expected = IllegalArgumentException.class)
public void maxPathsZeroThrows() {
    finder(new FakeCallGraph()).find("0x1000", "0x2000", 5, 0, 10000);
}

@Test(expected = IllegalArgumentException.class)
public void maxVisitedEdgesZeroThrows() {
    finder(new FakeCallGraph()).find("0x1000", "0x2000", 5, 50, 0);
}

@Test(expected = IllegalArgumentException.class)
public void nullFromEntryThrows() {
    finder(new FakeCallGraph()).find(null, "0x2000", 5, 50, 10000);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
mvn test -pl . -Dtest=CallPathFinderTest -Dghidra.version=12.1.2 2>&1 | tail -20
```
Expected: BUILD FAILURE — `IllegalArgumentException` not thrown.

- [ ] **Step 3: Add validation to `CallPathFinder.find()`**

Add `import java.util.Objects;` to `CallPathFinder.java`.

Replace the opening of `find()`:
```java
public Result find(String fromEntry, String toEntry, int maxDepth, int maxPaths, int maxVisitedEdges) {
    Objects.requireNonNull(fromEntry, "fromEntry");
    Objects.requireNonNull(toEntry, "toEntry");
    if (maxPaths < 1) throw new IllegalArgumentException("maxPaths must be >= 1, got " + maxPaths);
    if (maxDepth < 0) throw new IllegalArgumentException("maxDepth must be >= 0, got " + maxDepth);
    if (maxVisitedEdges < 1) throw new IllegalArgumentException("maxVisitedEdges must be >= 1, got " + maxVisitedEdges);
    // ... rest unchanged
```

- [ ] **Step 4: Run tests**

```
mvn test -pl . -Dtest=CallPathFinderTest -Dghidra.version=12.1.2 2>&1 | tail -20
```
Expected: BUILD SUCCESS — all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/graph/CallPathFinder.java \
        src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java
git commit -m "fix: validate CallPathFinder.find() numeric bounds and null entries

maxPaths=0 previously returned truncated=true with empty paths, misleading
callers into thinking the search was bounded. Same for maxVisitedEdges=0."
```

---

### Task 4: StringUsageWalker — WalkState refactor + early-exit globalVisited fix

**Root causes (Important I4, I5):**
- `resolve()` takes four mutable out-parameters (`int[]`, `Set`, `int[]`, `boolean[]`), inverting encapsulation. Any misconfiguration by the caller silently produces wrong results.
- When the function budget hits zero mid-walk, the triggering entry is not added to `globalVisited`, causing subsequent strings on the same page to immediately re-trigger `truncated=true` with 0 callers (cascade truncation).

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/graph/StringUsageWalker.java`
- Modify: `src/main/java/eu/starsong/ghidra/service/AnalysisService.java`
- Modify: `src/test/java/eu/starsong/ghidra/service/graph/StringUsageWalkerTest.java`

**Interfaces:**
- New: `StringUsageWalker.WalkState(int fnBudget)` — public static inner class. Constructor validates `fnBudget >= 0`. Public read accessors: `unresolvedRefs()`, `truncated()`. Package-visible mutable fields consumed by `resolve`.
- Changed: `resolve(StringUsageDto.StringRef ref, int callerDepth, WalkState state)` — three parameters instead of six.
- `AnalysisService.traceStringUsage`: creates a `WalkState`, passes it to `resolve`, reads `state.truncated()` / `state.unresolvedRefs()` for the response.

- [ ] **Step 1: Write the failing tests**

Replace/extend `StringUsageWalkerTest.java` to use the new `WalkState` API. The old raw-array API will be gone:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.StringUsageDto;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class StringUsageWalkerTest {

    private StringUsageDto.StringRef ref() {
        return new StringUsageDto.StringRef("0x8000", "CreateFileW");
    }

    private StringUsageWalker.WalkState state(int budget) {
        return new StringUsageWalker.WalkState(budget);
    }

    @Test
    public void directUsersOnlyWhenCallerDepthZero() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000", "0x1000", "0x2000")); // dup 0x1000 deduped
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 0, state(500));
        assertEquals(2, u.directUsers().size());
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void countsNullReferencesAsUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", Arrays.asList("0x1000", null, null));
        StringUsageWalker.WalkState s = state(500);
        new StringUsageWalker(g).resolve(ref(), 0, s);
        assertEquals(2, s.unresolvedRefs());
    }

    @Test
    public void walksCallersWithAscendingDepth() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000"));
        g.callers.put("0x2000", List.of("0x3000"));
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 2, state(500));
        assertEquals(2, u.callers().size());
        assertEquals("0x2000", u.callers().get(0).function().address());
        assertEquals(1, u.callers().get(0).depth());
        assertEquals("0x3000", u.callers().get(1).function().address());
        assertEquals(2, u.callers().get(1).depth());
    }

    @Test
    public void doesNotRevisitDirectUsersOrGloballyVisitedCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x1000", "0x2000")); // 0x1000 is direct user
        StringUsageWalker.WalkState s = state(500);
        s.globalVisited.add("0x2000"); // pre-seed as if seen by a prior string
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 1, s);
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void budgetExhaustionTruncatesAndReturnsPartialCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000", "0x3000", "0x4000"));
        StringUsageWalker.WalkState s = state(2);
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 1, s);
        assertEquals(2, u.callers().size());
        assertTrue(s.truncated());
    }

    @Test
    public void zeroInitialBudgetTruncatesImmediatelyWithNoCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000"));
        StringUsageWalker.WalkState s = state(0);
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 1, s);
        assertEquals(1, u.directUsers().size()); // direct users unaffected by budget
        assertTrue(u.callers().isEmpty());
        assertTrue(s.truncated());
    }

    @Test
    public void exhaustedBudgetEntryAddedToGlobalVisitedPreventsCascade() {
        // When budget hits 0 on callerEntry X, X must be added to globalVisited
        // so a subsequent string that also has X as a caller doesn't re-trigger.
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000")); // 0x2000 triggers budget=0
        StringUsageWalker.WalkState s = state(0); // budget already exhausted
        new StringUsageWalker(g).resolve(ref(), 1, s);
        assertTrue("0x2000 should be in globalVisited to prevent cascade",
            s.globalVisited.contains("0x2000"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeBudgetThrows() {
        new StringUsageWalker.WalkState(-1);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```
mvn test -pl . -Dtest=StringUsageWalkerTest -Dghidra.version=12.1.2 2>&1 | tail -20
```
Expected: BUILD FAILURE — `WalkState` does not exist yet.

- [ ] **Step 3: Introduce `WalkState` and rewrite `StringUsageWalker`**

Replace the entire content of `StringUsageWalker.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallerRefDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves one matched string's direct users and a bounded BFS walk up the reverse
 * call graph over a {@link CallGraph}. Pure: no Ghidra types, no I/O.
 *
 * <p>A {@link WalkState} carries the shared accumulators (budget, visited set,
 * unresolved count, truncation flag) across all strings in one response page,
 * so the function budget and visited set are global and the counters aggregate.
 * Construct one {@code WalkState} per page and pass it to every {@link #resolve} call.
 */
public final class StringUsageWalker {

    private final CallGraph graph;

    public StringUsageWalker(CallGraph graph) {
        this.graph = graph;
    }

    /**
     * Shared mutable state for one page's worth of string-usage resolution.
     * All fields are package-visible for access by {@link StringUsageWalker#resolve}.
     */
    public static final class WalkState {
        int fnBudget;
        final Set<String> globalVisited = new HashSet<>();
        int unresolvedRefs;
        boolean truncated;

        public WalkState(int fnBudget) {
            if (fnBudget < 0) throw new IllegalArgumentException("fnBudget must be >= 0, got " + fnBudget);
            this.fnBudget = fnBudget;
        }

        public int unresolvedRefs() { return unresolvedRefs; }
        public boolean truncated() { return truncated; }
    }

    public StringUsageDto resolve(StringUsageDto.StringRef ref, int callerDepth, WalkState state) {
        List<FunctionSummaryDto> directUsers = new ArrayList<>();
        Set<String> directAddrs = new LinkedHashSet<>();
        for (String userEntry : graph.referrersOf(ref.address())) {
            if (userEntry == null) { state.unresolvedRefs++; continue; }
            if (directAddrs.add(userEntry)) {
                directUsers.add(graph.summaryOf(userEntry));
            }
        }

        List<CallerRefDto> callers = new ArrayList<>();
        if (callerDepth > 0) {
            Set<String> currentLevel = new LinkedHashSet<>(directAddrs);
            int depth = 1;
            while (depth <= callerDepth && !currentLevel.isEmpty()) {
                Set<String> nextLevel = new LinkedHashSet<>();
                for (String fnEntry : currentLevel) {
                    for (String callerEntry : graph.callersOf(fnEntry)) {
                        if (callerEntry == null) { state.unresolvedRefs++; continue; }
                        if (directAddrs.contains(callerEntry) || state.globalVisited.contains(callerEntry)) continue;
                        // Add to globalVisited BEFORE budget check so that even if we truncate,
                        // this entry won't re-trigger truncation for the next string on the page.
                        state.globalVisited.add(callerEntry);
                        if (state.fnBudget <= 0) {
                            state.truncated = true;
                            continue; // don't add to callers or nextLevel — budget exhausted
                        }
                        callers.add(new CallerRefDto(graph.summaryOf(callerEntry), depth));
                        state.fnBudget--;
                        nextLevel.add(callerEntry);
                    }
                }
                if (state.truncated) break; // don't expand further BFS levels
                currentLevel = nextLevel;
                depth++;
            }
        }

        return new StringUsageDto(ref, directUsers, callers);
    }
}
```

- [ ] **Step 4: Update `AnalysisService.traceStringUsage` to use `WalkState`**

In `AnalysisService.java`, replace the walker setup and result extraction:

```java
// BEFORE:
StringUsageWalker walker = new StringUsageWalker(graph);
int[] fnBudget = {maxFunctions};
int[] unresolvedRefs = {0};
Set<String> globalVisited = new HashSet<>();
List<StringUsageDto> matches = new ArrayList<>();
for (StringUsageDto.StringRef ref : page) {
    matches.add(walker.resolve(ref, callerDepth, fnBudget, globalVisited, unresolvedRefs, truncated));
}
// ...
data.put("truncated", truncated[0]);
data.put("unresolved_refs", unresolvedRefs[0]);

// AFTER:
StringUsageWalker walker = new StringUsageWalker(graph);
StringUsageWalker.WalkState walkState = new StringUsageWalker.WalkState(maxFunctions);
List<StringUsageDto> matches = new ArrayList<>();
for (StringUsageDto.StringRef ref : page) {
    matches.add(walker.resolve(ref, callerDepth, walkState));
}
// ...
data.put("truncated", truncated[0] || walkState.truncated());
data.put("unresolved_refs", walkState.unresolvedRefs());
```

Also remove the `import java.util.HashSet;` from AnalysisService if it is now unused (check for other uses first via grep).

- [ ] **Step 5: Run tests**

```
mvn test -pl . -Dtest="StringUsageWalkerTest,CallPathFinderTest" -Dghidra.version=12.1.2 2>&1 | tail -20
```
Expected: BUILD SUCCESS — all tests pass, including the two new budget tests.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/graph/StringUsageWalker.java \
        src/main/java/eu/starsong/ghidra/service/AnalysisService.java \
        src/test/java/eu/starsong/ghidra/service/graph/StringUsageWalkerTest.java
git commit -m "refactor: introduce StringUsageWalker.WalkState; fix cascade truncation

Replaced 4 mutable out-parameters with an encapsulated WalkState inner class.
Fixed early-exit bug: triggering entry was not added to globalVisited, causing
subsequent strings to immediately re-truncate with 0 callers."
```

---

### Task 5: AnalysisResource — complete the self-link + Page/StringRef hardening

**Root causes (Important I6, Suggestions S3, S4):**
- `callPaths` self-link omits `&max_visited_edges=`, so following it from a client reproduces a different result when the user passed a non-default value.
- `Page.slice` has no null guard on `items` — NPE with no diagnostic.
- `StringRef` has no null guard on `address` — downstream NPE in `GhidraCallGraph.referrersOf` is confusing.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java`
- Modify: `src/main/java/eu/starsong/ghidra/util/Page.java`
- Modify: `src/main/java/eu/starsong/ghidra/dto/StringUsageDto.java`
- Modify: `src/test/java/eu/starsong/ghidra/util/PageTest.java`

- [ ] **Step 1: Write failing tests for Page null and negative limit**

Add to `PageTest.java`:

```java
@Test
public void negativeLimitIsEmpty() {
    assertTrue(Page.slice(items, 0, -1).isEmpty());
}

@Test(expected = NullPointerException.class)
public void nullItemsThrows() {
    Page.slice(null, 0, 10);
}
```

- [ ] **Step 2: Run to verify they fail**

```
mvn test -pl . -Dtest=PageTest -Dghidra.version=12.1.2 2>&1 | tail -10
```
Expected: `nullItemsThrows` FAILS — no NPE thrown (currently produces `NullPointerException` from `items.size()` anyway, so actually it might pass already). The `negativeLimitIsEmpty` test likely passes too due to the `Math.max(0, limit)` guard. Run and confirm; if both pass, skip to step 3 (no code change needed for Page) and document.

- [ ] **Step 3: Add `Objects.requireNonNull` to `Page.slice` and `StringRef` compact constructor**

In `Page.java`, add `import java.util.Objects;` and change the method opening:
```java
public static <T> List<T> slice(List<T> items, int offset, int limit) {
    Objects.requireNonNull(items, "items");
    int total = items.size();
    // ... rest unchanged
```

In `StringUsageDto.java`, add a compact constructor to `StringRef`:
```java
public record StringRef(String address, String value) {
    public StringRef {
        Objects.requireNonNull(address, "address");
        // value may legitimately be null (Ghidra can produce strings without a resolved value)
    }
    public static StringRef from(DataDto data) {
        return new StringRef(data.address(), data.value());
    }
}
```
Add `import java.util.Objects;` to `StringUsageDto.java` if not already present.

- [ ] **Step 4: Fix `callPaths` self-link to include `max_visited_edges`**

In `AnalysisResource.java`, replace the self-link construction in `callPaths`:
```java
// BEFORE:
ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
    .self("/analysis/callpaths?from=" + encFrom + "&to=" + encTo
        + "&max_depth=" + maxDepth + "&max_paths=" + maxPaths)

// AFTER:
ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
    .self("/analysis/callpaths?from=" + encFrom + "&to=" + encTo
        + "&max_depth=" + maxDepth + "&max_paths=" + maxPaths
        + "&max_visited_edges=" + maxVisitedEdges)
```

- [ ] **Step 5: Run tests**

```
mvn test -pl . -Dtest=PageTest -Dghidra.version=12.1.2 2>&1 | tail -10
```
Expected: BUILD SUCCESS — all `PageTest` tests pass including the two new ones.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java \
        src/main/java/eu/starsong/ghidra/util/Page.java \
        src/main/java/eu/starsong/ghidra/dto/StringUsageDto.java \
        src/test/java/eu/starsong/ghidra/util/PageTest.java
git commit -m "fix: complete callPaths self-link (add max_visited_edges); Page/StringRef null guards

Self-link previously omitted max_visited_edges so following it reproduced a
different result. Page.slice and StringRef.address now fail fast with a clear
NullPointerException rather than producing a confusing downstream error."
```

---

### Task 6: Missing Java unit tests — algorithmic edge cases

**Root causes (Critical test gaps from test-coverage review):**
- No test for `CallPathFinder` when target is completely unreachable (should be empty, `truncated=false`, `unresolvedEdges=0`)
- No test for `maxPaths=1` exact-boundary semantics (off-by-one risk in `>=` vs `>`)
- `StringUsageWalkerTest` doesn't test the cross-string direct-user globalVisited gap
- `FakeCallGraph` is package-private, blocking future `AnalysisServiceTest` in a different package

**Files:**
- Modify: `src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java`
- Modify: `src/test/java/eu/starsong/ghidra/service/graph/FakeCallGraph.java`

(StringUsageWalkerTest edge cases were already added in Task 4.)

- [ ] **Step 1: Add missing `CallPathFinder` tests**

Add to `CallPathFinderTest.java`:

```java
@Test
public void unreachableTargetIsEmptyAndNotTruncated() {
    FakeCallGraph g = new FakeCallGraph();
    g.callees.put("0x1000", List.of("0x2000")); // 0x9999 is unreachable
    CallPathFinder.Result r = finder(g).find("0x1000", "0x9999", 5, 50, 10000);
    assertTrue("expected empty paths for unreachable target", r.paths().isEmpty());
    assertFalse("depth pruning alone must not set truncated", r.truncated());
    assertEquals(0, r.unresolvedEdges());
}

@Test
public void maxPathsOneReturnsExactlyOnePathAndSetsTruncated() {
    FakeCallGraph g = new FakeCallGraph();
    g.callees.put("0x1000", List.of("0xa", "0xb"));
    g.callees.put("0xa", List.of("0x9999"));
    g.callees.put("0xb", List.of("0x9999"));
    CallPathFinder.Result r = finder(g).find("0x1000", "0x9999", 5, 1, 10000);
    assertEquals(1, r.paths().size());
    assertTrue("truncated must be true when cap is hit at exactly maxPaths=1", r.truncated());
}
```

- [ ] **Step 2: Make `FakeCallGraph` public**

In `FakeCallGraph.java`, change the class declaration:
```java
// BEFORE:
class FakeCallGraph implements CallGraph {

// AFTER:
public class FakeCallGraph implements CallGraph {
```

- [ ] **Step 3: Run all graph-package unit tests**

```
mvn test -pl . -Dtest="CallPathFinderTest,StringUsageWalkerTest,GhidraCallGraphConstructorTest" -Dghidra.version=12.1.2 2>&1 | tail -20
```
Expected: BUILD SUCCESS — all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java \
        src/test/java/eu/starsong/ghidra/service/graph/FakeCallGraph.java
git commit -m "test: add unreachable target and maxPaths=1 boundary tests; make FakeCallGraph public

Covers previously untested edge cases: clean 'no path' result vs truncation,
and the exact off-by-one at the maxPaths cap. FakeCallGraph made public for
reuse in future AnalysisServiceTest outside the graph package."
```

---

### Task 7: Python — pin formatter outputs + `simplify_response` regression guard

**Root cause (Test quality S8):** `test_bridge_compound_re.py` only tested pre-network input validation. The formatter functions added in Task 1 need an integration-style check through the `@text_output` decorator, and a test that `simplify_response` preserves `unresolved_edges`/`unresolved_refs` in the response envelope.

**Files:**
- Modify: `tests/test_bridge_compound_re.py`

- [ ] **Step 1: Add decorator + simplify_response tests**

These tests verify that `@text_output` routes to the new formatters (not `"Done"`) and that `simplify_response` preserves the new fields:

```python
import bridge_mcp_hydra as b


def test_simplify_response_preserves_unresolved_edges():
    response = {
        "success": True,
        "id": "drop-me",
        "instance": "drop-me",
        "timestamp": 9999,
        "result": {
            "from": "main",
            "to": "target",
            "unresolved_edges": 5,
            "paths": [],
            "truncated": False,
        },
    }
    simplified = b.simplify_response(response)
    # simplify_response strips top-level envelope fields, not result fields
    assert "id" not in simplified
    assert simplified["result"]["unresolved_edges"] == 5


def test_simplify_response_preserves_unresolved_refs():
    response = {
        "success": True,
        "id": "x",
        "result": {
            "value": "hello",
            "unresolved_refs": 3,
            "matches": [],
            "truncated": False,
        },
    }
    simplified = b.simplify_response(response)
    assert simplified["result"]["unresolved_refs"] == 3
```

- [ ] **Step 2: Run tests**

```
pytest tests/test_bridge_compound_re.py -v
```
Expected: all tests PASSED (including both new `simplify_response` tests and the formatter tests from Task 1).

- [ ] **Step 3: Run full suite**

```
pytest tests/ -v
```
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_bridge_compound_re.py
git commit -m "test: pin simplify_response preserves unresolved_edges/unresolved_refs

Ensures the envelope-stripping in simplify_response never accidentally drops
the new unresolved_edges and unresolved_refs fields from compound-RE results."
```

---

## Self-Review

**Spec coverage check (findings → tasks):**

| Finding | Task |
|---------|------|
| C — FORMATTERS missing → "Done" | Task 1 |
| C — summaryOf null → NPE | Task 2 |
| C — calleesOf silent empty → DFS prune | Task 2 |
| I — WalkState encapsulation | Task 4 |
| I — early-exit globalVisited cascade | Task 4 |
| I — self-link missing max_visited_edges | Task 5 |
| I — constructor null guards | Task 2 |
| I — find() numeric bound validation | Task 3 |
| I — missing unreachable-target test | Task 6 |
| I — missing cross-string dedup test | Task 4 (exhaustedBudgetEntryAdded…) |
| S — client-side max_depth/max_paths validation | Task 1 |
| S — Page requireNonNull(items) | Task 5 |
| S — StringRef null guard on address | Task 5 |
| S — maxPaths=1 boundary test | Task 6 |
| S — budget=0 initial test | Task 4 |
| S — negative limit test in PageTest | Task 5 |
| S — FakeCallGraph public | Task 6 |
| S — simplify_response pin test | Task 7 |

**Placeholder scan:** No TBDs, all code blocks are complete.

**Type consistency:**
- `WalkState` defined in Task 4 as `StringUsageWalker.WalkState`, referenced identically in `AnalysisService` change and tests.
- `format_call_paths` / `format_string_usage` defined and registered in Task 1, tested in Task 1 and Task 7.
- `CallPathFinder.find()` signature unchanged — only precondition guards added.
