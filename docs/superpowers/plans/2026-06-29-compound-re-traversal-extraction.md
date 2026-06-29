# Compound-RE Traversal Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the compound-RE call-path and string-usage traversal logic unit-testable without a live Ghidra by extracting it onto an address-keyed graph abstraction, while keeping the HTTP/MCP/CLI behaviour byte-for-byte identical.

**Architecture:** Introduce a small `CallGraph` interface that exposes the call graph and string references as plain `List<String>` of function-entry addresses (with `null` marking an edge/reference that cannot be attributed to a defined function). The pure algorithms — `CallPathFinder` (DFS) and `StringUsageWalker` (BFS up the reverse call graph) — depend only on this interface, so they run under JUnit with a hand-written in-memory fake. A single production adapter, `GhidraCallGraph`, is the only new class that touches Ghidra types; `AnalysisService` keeps the outer `GhidraSwing.runRead` boundary, the regex/pagination glue, and the response-map assembly.

**Tech Stack:** Java 21, Maven, JUnit 4 (Ghidra plugin module). No new dependencies.

## Global Constraints

- Java 21; build with `mvn -o ...` (offline; jars are in `lib/`, `ghidra.version` defaults to `12.1.2` in `pom.xml`).
- Test framework is **JUnit 4** (`org.junit.Test`, `static org.junit.Assert.*`). **No Mockito** — fakes are hand-written.
- **Behaviour-preserving refactor.** The public signatures `AnalysisService.findCallPaths(Program, String, String, int, int, int)` and `AnalysisService.traceStringUsage(Program, String, String, int, int, int, int, int)` and the exact keys/values of their returned `Map<String,Object>` (`from, to, max_depth, max_paths, truncated, unresolved_edges, paths` and `value, match, caller_depth, size, offset, limit, truncated, unresolved_refs, matches`) MUST NOT change. Existing tests (`CompoundReDtoTest`, `test_http_api.py`, formatter tests) MUST stay green.
- New code lives in package `eu.starsong.ghidra.service.graph`; new tests in `src/test/java/eu/starsong/ghidra/service/graph/`.
- Counting rule (must be preserved exactly): a `null` element returned by any `CallGraph` method represents one edge/reference that exists but is not attributable to a defined function entry; the algorithm counts it as `unresolved` and skips it. A repeated non-null entry is de-duplicated by the algorithm (not the graph) and is **not** counted as unresolved. Cycle skips (revisiting a node already on the current path) are **not** counted.

---

### Task 1: `CallGraph` interface, `FakeCallGraph` test double, and `CallPathFinder` (DFS)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/service/graph/CallGraph.java`
- Create: `src/main/java/eu/starsong/ghidra/service/graph/CallPathFinder.java`
- Test: `src/test/java/eu/starsong/ghidra/service/graph/FakeCallGraph.java` (shared test double)
- Test: `src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java`

**Interfaces:**
- Consumes: `eu.starsong.ghidra.dto.CallPathDto`, `eu.starsong.ghidra.dto.FunctionSummaryDto` (existing).
- Produces:
  - `interface CallGraph` with `List<String> calleesOf(String fnEntry)`, `List<String> callersOf(String fnEntry)`, `List<String> referrersOf(String dataAddr)`, `FunctionSummaryDto summaryOf(String fnEntry)`.
  - `class CallPathFinder` with constructor `CallPathFinder(CallGraph graph)` and `CallPathFinder.Result find(String fromEntry, String toEntry, int maxDepth, int maxPaths, int maxVisitedEdges)`.
  - `record CallPathFinder.Result(List<CallPathDto> paths, boolean truncated, int unresolvedEdges)`.
  - `class FakeCallGraph implements CallGraph` (test package) exposing public mutable maps `callees`, `callers`, `referrers` (all `Map<String,List<String>>`).

- [ ] **Step 1: Write the `CallGraph` interface**

Create `src/main/java/eu/starsong/ghidra/service/graph/CallGraph.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.FunctionSummaryDto;

import java.util.List;

/**
 * Read-only, address-keyed view of the program's call graph and string references,
 * decoupled from Ghidra types so the traversal algorithms are unit-testable.
 *
 * <p>Every list method returns one element per underlying call site / reference, in
 * iteration order, preserving duplicates. A {@code null} element marks an edge or
 * reference that exists but is not attributable to a defined function entry
 * (thunk/PLT, indirect/computed call, data-region or undisassembled reference); the
 * caller counts these as "unresolved" and skips them. De-duplication of repeated
 * non-null entries is the algorithm's responsibility, not the graph's.
 */
public interface CallGraph {

    /** Callee entry addresses for each CALL out of the function at {@code fnEntry}. */
    List<String> calleesOf(String fnEntry);

    /** Caller entry addresses for each CALL into the function at {@code fnEntry}. */
    List<String> callersOf(String fnEntry);

    /** Caller entry addresses for each reference to the data at {@code dataAddr}. */
    List<String> referrersOf(String dataAddr);

    /** Function summary for a resolved (non-null) entry address. */
    FunctionSummaryDto summaryOf(String fnEntry);
}
```

- [ ] **Step 2: Write the `FakeCallGraph` test double**

Create `src/test/java/eu/starsong/ghidra/service/graph/FakeCallGraph.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.FunctionSummaryDto;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** In-memory CallGraph for unit tests. Lists may contain null entries (unresolved edges/refs). */
class FakeCallGraph implements CallGraph {
    final Map<String, List<String>> callees = new HashMap<>();
    final Map<String, List<String>> callers = new HashMap<>();
    final Map<String, List<String>> referrers = new HashMap<>();

    @Override public List<String> calleesOf(String fnEntry) { return callees.getOrDefault(fnEntry, List.of()); }
    @Override public List<String> callersOf(String fnEntry) { return callers.getOrDefault(fnEntry, List.of()); }
    @Override public List<String> referrersOf(String dataAddr) { return referrers.getOrDefault(dataAddr, List.of()); }

    @Override public FunctionSummaryDto summaryOf(String fnEntry) {
        return new FunctionSummaryDto("fn_" + fnEntry, fnEntry, "fn_" + fnEntry + "(void)", "void", false, false, 0);
    }
}
```

- [ ] **Step 3: Write the failing `CallPathFinderTest`**

Create `src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallPathDto;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class CallPathFinderTest {

    private CallPathFinder finder(FakeCallGraph g) { return new CallPathFinder(g); }

    @Test
    public void selfToSelfYieldsSingleTrivialPath() {
        FakeCallGraph g = new FakeCallGraph();
        CallPathFinder.Result r = finder(g).find("0x1000", "0x1000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(1, r.paths().get(0).length());
        assertFalse(r.truncated());
        assertEquals(0, r.unresolvedEdges());
    }

    @Test
    public void findsSimpleLinearPath() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x3000"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        CallPathDto p = r.paths().get(0);
        assertEquals(3, p.length());
        assertEquals(Arrays.asList("0x1000", "0x2000", "0x3000"),
            p.functions().stream().map(f -> f.address()).toList());
    }

    @Test
    public void avoidsCyclesAndDoesNotCountThemUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x1000", "0x3000")); // back-edge to 0x1000 is a cycle
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(0, r.unresolvedEdges());
        assertFalse(r.truncated());
    }

    @Test
    public void countsNullEdgesAsUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", Arrays.asList(null, "0x2000", null));
        g.callees.put("0x2000", List.of("0x3000"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(2, r.unresolvedEdges());
    }

    @Test
    public void maxPathsCapTruncatesAtExactBoundary() {
        FakeCallGraph g = new FakeCallGraph();
        // 0x1000 -> {a,b,c} each -> target: three distinct paths.
        g.callees.put("0x1000", List.of("0xa", "0xb", "0xc"));
        g.callees.put("0xa", List.of("0x9999"));
        g.callees.put("0xb", List.of("0x9999"));
        g.callees.put("0xc", List.of("0x9999"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x9999", 5, 2, 10000);
        assertEquals(2, r.paths().size());
        assertTrue(r.truncated());
    }

    @Test
    public void maxVisitedEdgesCapTruncates() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0xa", "0xb", "0xc", "0xd"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x9999", 5, 50, 2);
        assertTrue(r.truncated());
        assertTrue(r.paths().isEmpty());
    }

    @Test
    public void depthLimitPrunesWithoutSettingTruncated() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x3000")); // target is 2 edges deep
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 1, 50, 10000);
        assertTrue(r.paths().isEmpty());
        assertFalse(r.truncated()); // max_depth alone does NOT set truncated
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `mvn -o test -Dtest=CallPathFinderTest`
Expected: FAIL — compilation error, `CallPathFinder` does not exist.

- [ ] **Step 5: Implement `CallPathFinder`**

Create `src/main/java/eu/starsong/ghidra/service/graph/CallPathFinder.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallPathDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Enumerates bounded, simple (loop-free) call paths between two function entries
 * over a {@link CallGraph}. Pure: no Ghidra types, no I/O.
 */
public final class CallPathFinder {

    private final CallGraph graph;

    public CallPathFinder(CallGraph graph) {
        this.graph = graph;
    }

    public Result find(String fromEntry, String toEntry, int maxDepth, int maxPaths, int maxVisitedEdges) {
        List<CallPathDto> paths = new ArrayList<>();
        int[] visitedEdges = {0};
        int[] unresolvedEdges = {0};
        boolean[] truncated = {false};

        List<String> path = new ArrayList<>();
        Set<String> onPath = new HashSet<>();
        path.add(fromEntry);
        onPath.add(fromEntry);

        dfs(fromEntry, toEntry, maxDepth, maxPaths, maxVisitedEdges,
            path, onPath, paths, visitedEdges, unresolvedEdges, truncated);

        return new Result(List.copyOf(paths), truncated[0], unresolvedEdges[0]);
    }

    private void dfs(String current, String toEntry, int depth, int maxPaths, int maxVisitedEdges,
                     List<String> path, Set<String> onPath, List<CallPathDto> paths,
                     int[] visitedEdges, int[] unresolvedEdges, boolean[] truncated) {
        if (current.equals(toEntry)) {
            List<FunctionSummaryDto> fns = new ArrayList<>();
            for (String entry : path) {
                fns.add(graph.summaryOf(entry));
            }
            paths.add(CallPathDto.of(fns));
            if (paths.size() >= maxPaths) truncated[0] = true;
            return;
        }
        if (depth <= 0) return;

        for (String callee : graph.calleesOf(current)) {
            if (paths.size() >= maxPaths) { truncated[0] = true; return; }
            if (visitedEdges[0] >= maxVisitedEdges) { truncated[0] = true; return; }
            visitedEdges[0]++;

            if (callee == null) { unresolvedEdges[0]++; continue; }
            if (onPath.contains(callee)) continue; // cycle: expected, not unresolved

            onPath.add(callee);
            path.add(callee);
            dfs(callee, toEntry, depth - 1, maxPaths, maxVisitedEdges,
                path, onPath, paths, visitedEdges, unresolvedEdges, truncated);
            path.remove(path.size() - 1);
            onPath.remove(callee);
        }
    }

    public record Result(List<CallPathDto> paths, boolean truncated, int unresolvedEdges) {
    }
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `mvn -o test -Dtest=CallPathFinderTest`
Expected: PASS — `Tests run: 7, Failures: 0, Errors: 0`.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/graph/CallGraph.java \
        src/main/java/eu/starsong/ghidra/service/graph/CallPathFinder.java \
        src/test/java/eu/starsong/ghidra/service/graph/FakeCallGraph.java \
        src/test/java/eu/starsong/ghidra/service/graph/CallPathFinderTest.java
git commit -m "refactor: extract call-path DFS onto a unit-testable CallGraph"
```

---

### Task 2: `StringUsageWalker` (BFS reverse-call-graph walk)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/service/graph/StringUsageWalker.java`
- Test: `src/test/java/eu/starsong/ghidra/service/graph/StringUsageWalkerTest.java`

**Interfaces:**
- Consumes: `CallGraph` (Task 1), `FakeCallGraph` (Task 1), `eu.starsong.ghidra.dto.StringUsageDto`, `eu.starsong.ghidra.dto.StringUsageDto.StringRef`, `eu.starsong.ghidra.dto.CallerRefDto` (existing).
- Produces: `class StringUsageWalker` with constructor `StringUsageWalker(CallGraph graph)` and method
  `StringUsageDto resolve(StringUsageDto.StringRef ref, int callerDepth, int[] fnBudget, java.util.Set<String> globalVisited, int[] unresolvedRefs, boolean[] truncated)`.
  The four mutable accumulators (`fnBudget`, `globalVisited`, `unresolvedRefs`, `truncated`) are shared across all strings in one page so caps and counts are global; the caller owns them.

- [ ] **Step 1: Write the failing `StringUsageWalkerTest`**

Create `src/test/java/eu/starsong/ghidra/service/graph/StringUsageWalkerTest.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.StringUsageDto;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class StringUsageWalkerTest {

    private StringUsageDto.StringRef ref() {
        return new StringUsageDto.StringRef("0x8000", "CreateFileW");
    }

    @Test
    public void directUsersOnlyWhenCallerDepthZero() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000", "0x1000", "0x2000")); // dup 0x1000 deduped
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 0, new int[]{500}, new HashSet<>(), new int[]{0}, new boolean[]{false});
        assertEquals(2, u.directUsers().size());
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void countsNullReferencesAsUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", Arrays.asList("0x1000", null, null));
        int[] unresolved = {0};
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 0, new int[]{500}, new HashSet<>(), unresolved, new boolean[]{false});
        assertEquals(1, u.directUsers().size());
        assertEquals(2, unresolved[0]);
    }

    @Test
    public void walksCallersWithAscendingDepth() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));   // direct user
        g.callers.put("0x1000", List.of("0x2000"));      // depth 1
        g.callers.put("0x2000", List.of("0x3000"));      // depth 2
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 2, new int[]{500}, new HashSet<>(), new int[]{0}, new boolean[]{false});
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
        g.callers.put("0x1000", List.of("0x1000", "0x2000")); // 0x1000 is a direct user -> skipped
        Set<String> globalVisited = new HashSet<>();
        globalVisited.add("0x2000"); // already seen by a previous string -> skipped
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 1, new int[]{500}, globalVisited, new int[]{0}, new boolean[]{false});
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void budgetExhaustionTruncatesAndReturnsPartialCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000", "0x3000", "0x4000"));
        int[] budget = {2};
        boolean[] truncated = {false};
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 1, budget, new HashSet<>(), new int[]{0}, truncated);
        assertEquals(2, u.callers().size()); // only 2 fit the budget
        assertTrue(truncated[0]);
        assertEquals(0, budget[0]);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn -o test -Dtest=StringUsageWalkerTest`
Expected: FAIL — compilation error, `StringUsageWalker` does not exist.

- [ ] **Step 3: Implement `StringUsageWalker`**

Create `src/main/java/eu/starsong/ghidra/service/graph/StringUsageWalker.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallerRefDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves one matched string's direct users and a bounded BFS walk up the reverse
 * call graph over a {@link CallGraph}. Pure: no Ghidra types, no I/O.
 *
 * <p>The {@code fnBudget}, {@code globalVisited}, {@code unresolvedRefs}, and
 * {@code truncated} accumulators are shared across all strings in one response page,
 * so the function budget and visited set are global and the counters aggregate.
 */
public final class StringUsageWalker {

    private final CallGraph graph;

    public StringUsageWalker(CallGraph graph) {
        this.graph = graph;
    }

    public StringUsageDto resolve(StringUsageDto.StringRef ref, int callerDepth,
                                  int[] fnBudget, Set<String> globalVisited,
                                  int[] unresolvedRefs, boolean[] truncated) {
        List<FunctionSummaryDto> directUsers = new ArrayList<>();
        Set<String> directAddrs = new LinkedHashSet<>();
        for (String userEntry : graph.referrersOf(ref.address())) {
            if (userEntry == null) { unresolvedRefs[0]++; continue; }
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
                        if (callerEntry == null) { unresolvedRefs[0]++; continue; }
                        if (directAddrs.contains(callerEntry) || globalVisited.contains(callerEntry)) continue;
                        if (fnBudget[0] <= 0) {
                            truncated[0] = true;
                            return new StringUsageDto(ref, directUsers, callers);
                        }
                        globalVisited.add(callerEntry);
                        callers.add(new CallerRefDto(graph.summaryOf(callerEntry), depth));
                        fnBudget[0]--;
                        nextLevel.add(callerEntry);
                    }
                }
                currentLevel = nextLevel;
                depth++;
            }
        }

        return new StringUsageDto(ref, directUsers, callers);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `mvn -o test -Dtest=StringUsageWalkerTest`
Expected: PASS — `Tests run: 5, Failures: 0, Errors: 0`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/graph/StringUsageWalker.java \
        src/test/java/eu/starsong/ghidra/service/graph/StringUsageWalkerTest.java
git commit -m "refactor: extract string-usage caller walk onto CallGraph"
```

---

### Task 3: `Page.slice` pagination helper

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/util/Page.java`
- Test: `src/test/java/eu/starsong/ghidra/util/PageTest.java`

**Interfaces:**
- Produces: `final class Page` with `static <T> List<T> slice(List<T> items, int offset, int limit)` — clamps `offset`/`limit` and returns the in-range sublist (empty when out of range). Reproduces the existing `start = max(0, min(offset, total)); end = min(total, start + limit)` math from `AnalysisService.traceStringUsage`.

- [ ] **Step 1: Write the failing `PageTest`**

Create `src/test/java/eu/starsong/ghidra/util/PageTest.java`:

```java
package eu.starsong.ghidra.util;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class PageTest {

    private final List<String> items = List.of("a", "b", "c", "d", "e");

    @Test
    public void returnsRequestedWindow() {
        assertEquals(List.of("b", "c"), Page.slice(items, 1, 2));
    }

    @Test
    public void clampsLimitToRemainder() {
        assertEquals(List.of("d", "e"), Page.slice(items, 3, 10));
    }

    @Test
    public void offsetAtOrBeyondTotalIsEmpty() {
        assertTrue(Page.slice(items, 5, 10).isEmpty());
        assertTrue(Page.slice(items, 99, 10).isEmpty());
    }

    @Test
    public void zeroLimitIsEmpty() {
        assertTrue(Page.slice(items, 0, 0).isEmpty());
    }

    @Test
    public void negativeOffsetIsClampedToZero() {
        assertEquals(List.of("a", "b"), Page.slice(items, -5, 2));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn -o test -Dtest=PageTest`
Expected: FAIL — compilation error, `Page` does not exist.

- [ ] **Step 3: Implement `Page`**

Create `src/main/java/eu/starsong/ghidra/util/Page.java`:

```java
package eu.starsong.ghidra.util;

import java.util.Collections;
import java.util.List;

/** Pure pagination helper: returns the in-range window of a list for an offset/limit. */
public final class Page {

    private Page() {
    }

    /**
     * Returns the sublist starting at {@code offset} (clamped to {@code [0, size]}) with at
     * most {@code limit} elements. Returns an empty list when the window is out of range.
     */
    public static <T> List<T> slice(List<T> items, int offset, int limit) {
        int total = items.size();
        int start = Math.max(0, Math.min(offset, total));
        int end = Math.min(total, start + Math.max(0, limit));
        return start < end ? items.subList(start, end) : Collections.emptyList();
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `mvn -o test -Dtest=PageTest`
Expected: PASS — `Tests run: 5, Failures: 0, Errors: 0`.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/util/Page.java \
        src/test/java/eu/starsong/ghidra/util/PageTest.java
git commit -m "refactor: extract Page.slice pagination helper"
```

---

### Task 4: `GhidraCallGraph` adapter + rewire `AnalysisService`

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/service/graph/GhidraCallGraph.java`
- Modify: `src/main/java/eu/starsong/ghidra/service/AnalysisService.java` (replace `findCallPaths` body, replace `traceStringUsage` body, delete the private `dfsCallPaths` and `resolveStringUsage` methods, adjust imports)

**Interfaces:**
- Consumes: `CallGraph`, `CallPathFinder`, `CallPathFinder.Result`, `StringUsageWalker` (Tasks 1–2), `Page.slice` (Task 3), the existing `FunctionService.findByAddress/findContaining`, `XrefService.getCallsFromFunction/getCallsTo/getReferencesTo`, `XrefDto.toFunctionAddress/fromAddress`, `DataService.listStrings`, `StringUsageDto.StringRef.from(DataDto)`.
- Produces: `final class GhidraCallGraph implements CallGraph` with constructor `GhidraCallGraph(Program program, FunctionService functionService, XrefService xrefService)`. No change to any public `AnalysisService` signature or response shape.

- [ ] **Step 1: Implement the `GhidraCallGraph` adapter**

Create `src/main/java/eu/starsong/ghidra/service/graph/GhidraCallGraph.java`:

```java
package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.service.FunctionService;
import eu.starsong.ghidra.service.XrefService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

/**
 * Production {@link CallGraph} backed by a live {@link Program} and the existing services.
 * The only graph implementation that touches Ghidra types. Construct and use it inside a
 * {@code GhidraSwing.runRead} boundary (see {@code AnalysisService}); the underlying service
 * calls run their own reentrant reads.
 *
 * <p>Each list method emits one element per call site / reference, in order. An edge or
 * reference whose source/target is not a defined function entry is emitted as {@code null}.
 */
public final class GhidraCallGraph implements CallGraph {

    private final Program program;
    private final FunctionService functionService;
    private final XrefService xrefService;

    public GhidraCallGraph(Program program, FunctionService functionService, XrefService xrefService) {
        this.program = program;
        this.functionService = functionService;
        this.xrefService = xrefService;
    }

    @Override
    public List<String> calleesOf(String fnEntry) {
        Function fn = functionService.findByAddress(program, fnEntry);
        List<String> out = new ArrayList<>();
        for (XrefDto xref : xrefService.getCallsFromFunction(program, fn)) {
            String calleeAddr = xref.toFunctionAddress();
            if (calleeAddr == null) { out.add(null); continue; }
            Function callee = functionService.findByAddress(program, calleeAddr);
            out.add(callee != null ? callee.getEntryPoint().toString() : null);
        }
        return out;
    }

    @Override
    public List<String> callersOf(String fnEntry) {
        List<String> out = new ArrayList<>();
        for (XrefDto x : xrefService.getCallsTo(program, fnEntry)) {
            Function caller = functionService.findContaining(program, x.fromAddress());
            out.add(caller != null ? caller.getEntryPoint().toString() : null);
        }
        return out;
    }

    @Override
    public List<String> referrersOf(String dataAddr) {
        List<String> out = new ArrayList<>();
        for (XrefDto x : xrefService.getReferencesTo(program, dataAddr)) {
            Function f = functionService.findContaining(program, x.fromAddress());
            out.add(f != null ? f.getEntryPoint().toString() : null);
        }
        return out;
    }

    @Override
    public FunctionSummaryDto summaryOf(String fnEntry) {
        return FunctionSummaryDto.from(functionService.findByAddress(program, fnEntry));
    }
}
```

- [ ] **Step 2: Rewire `AnalysisService.findCallPaths`**

In `src/main/java/eu/starsong/ghidra/service/AnalysisService.java`, replace the entire `findCallPaths` method (the javadoc block stays — keep the existing `unresolved_edges` javadoc) body so it delegates to the finder. The method now reads:

```java
    public Map<String, Object> findCallPaths(Program program, String from, String to,
                                             int maxDepth, int maxPaths, int maxVisitedEdges) {
        return GhidraSwing.runRead(() -> {
            Function fromFn = resolveFunction(program, from);
            Function toFn = resolveFunction(program, to);
            String fromEntry = fromFn.getEntryPoint().toString();
            String toEntry = toFn.getEntryPoint().toString();

            CallGraph graph = new GhidraCallGraph(program, functionService, xrefService);
            CallPathFinder.Result r =
                new CallPathFinder(graph).find(fromEntry, toEntry, maxDepth, maxPaths, maxVisitedEdges);

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("from", fromEntry);
            data.put("to", toEntry);
            data.put("max_depth", maxDepth);
            data.put("max_paths", maxPaths);
            data.put("truncated", r.truncated());
            data.put("unresolved_edges", r.unresolvedEdges());
            data.put("paths", r.paths());
            return data;
        });
    }
```

Then **delete** the private `dfsCallPaths(...)` method in its entirety.

- [ ] **Step 3: Rewire `AnalysisService.traceStringUsage`**

Replace the `traceStringUsage` method body (keep its existing javadoc with the `unresolved_refs` note). Inside the `GhidraSwing.runRead`, build the matched `StringRef` list, paginate with `Page.slice`, and delegate per-string resolution to `StringUsageWalker`. The method now reads:

```java
    public Map<String, Object> traceStringUsage(Program program, String value, String match,
                                                int callerDepth, int offset, int limit,
                                                int maxStrings, int maxFunctions) {
        final Pattern pattern;
        if ("regex".equals(match)) {
            try {
                pattern = Pattern.compile(value);
            } catch (PatternSyntaxException e) {
                throw new BadRequestException("Invalid regex pattern: " + e.getMessage(), "INVALID_REGEX");
            }
        } else {
            pattern = null;
        }

        return GhidraSwing.runRead(() -> {
            List<StringUsageDto.StringRef> matched = new ArrayList<>();
            boolean[] truncated = {false};
            for (DataDto d : dataService.listStrings(program)) {
                String v = d.value();
                if (v == null) continue;
                boolean hit = pattern != null ? pattern.matcher(v).find() : v.contains(value);
                if (hit) {
                    matched.add(StringUsageDto.StringRef.from(d));
                    if (matched.size() >= maxStrings) { truncated[0] = true; break; }
                }
            }

            int total = matched.size();
            List<StringUsageDto.StringRef> page = Page.slice(matched, offset, limit);

            CallGraph graph = new GhidraCallGraph(program, functionService, xrefService);
            StringUsageWalker walker = new StringUsageWalker(graph);
            int[] fnBudget = {maxFunctions};
            int[] unresolvedRefs = {0};
            Set<String> globalVisited = new HashSet<>();
            List<StringUsageDto> matches = new ArrayList<>();
            for (StringUsageDto.StringRef ref : page) {
                matches.add(walker.resolve(ref, callerDepth, fnBudget, globalVisited, unresolvedRefs, truncated));
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("value", value);
            data.put("match", match);
            data.put("caller_depth", callerDepth);
            data.put("size", total);
            data.put("offset", offset);
            data.put("limit", limit);
            data.put("truncated", truncated[0]);
            data.put("unresolved_refs", unresolvedRefs[0]);
            data.put("matches", matches);
            return data;
        });
    }
```

Then **delete** the private `resolveStringUsage(...)` method in its entirety.

- [ ] **Step 4: Fix imports in `AnalysisService.java`**

At the top of `AnalysisService.java`, add the three new imports:

```java
import eu.starsong.ghidra.service.graph.CallGraph;
import eu.starsong.ghidra.service.graph.CallPathFinder;
import eu.starsong.ghidra.service.graph.GhidraCallGraph;
import eu.starsong.ghidra.service.graph.StringUsageWalker;
import eu.starsong.ghidra.util.Page;
```

Remove any import left unused by the deletions. After the rewire, verify by inspection that `Collections` is still used by `buildCallTree` (it is — `Collections.emptyList()`), and that `CallerRefDto` and `LinkedHashSet` are no longer referenced in this file; if an IDE/compiler flags them as unused, delete those two import lines. Do not remove `Pattern`, `PatternSyntaxException`, `DataDto`, `StringUsageDto`, `FunctionSummaryDto`, `CallPathDto`, `Address`, `GhidraUtil` — all still used.

- [ ] **Step 5: Compile the whole module**

Run: `mvn -o clean test-compile`
Expected: `BUILD SUCCESS` (pre-existing `EmulationService` deprecation warnings are fine; no errors).

- [ ] **Step 6: Run the full Java test suite to confirm behaviour is preserved**

Run: `mvn -o test`
Expected: `BUILD SUCCESS`. `CompoundReDtoTest`, `CallPathFinderTest`, `StringUsageWalkerTest`, `PageTest`, and all other existing tests pass; `Failures: 0, Errors: 0`.

- [ ] **Step 7: Confirm the Python tiers are unaffected**

Run: `python -m pytest -q`
Expected: PASS (the refactor is server-side only; the response shape is unchanged, so the offline bridge/formatter tests and `test_http_api.py` field assertions are unaffected). Expected: `191 passed` (or more).

- [ ] **Step 8: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/graph/GhidraCallGraph.java \
        src/main/java/eu/starsong/ghidra/service/AnalysisService.java
git commit -m "refactor: wire AnalysisService to CallGraph finder/walker, drop in-method traversal"
```

---

## Notes for the implementer

- **Why `length` stays a stored field, `null` means unresolved, cycles aren't counted:** these are spelled out in Global Constraints and the `CallGraph` javadoc — they are the invariants that keep the refactor byte-for-byte compatible with the merged behaviour. Do not "tidy" them away.
- **No version bump.** This is an internal refactor with no change to the API, the response shape, or any client. `API_VERSION`, `PLUGIN_VERSION`, and `BRIDGE_VERSION` stay as they are. (If a reviewer insists on tracking it, that is a separate decision — do not bump as part of these tasks.)
- **`GhidraCallGraph` has no unit test by design** — it is the thin adapter whose only logic is "one element per xref, null when unattributable," and it cannot run without Ghidra. Its behaviour is covered end-to-end by the live `test_http_api.py` integration tests; the interesting logic is now in the fake-backed `CallPathFinderTest`/`StringUsageWalkerTest`.
- **`DataService` is intentionally NOT part of `CallGraph`.** String enumeration + regex/substring matching stays in `AnalysisService.traceStringUsage` because it needs `DataDto`/`Program`; only the graph walk is abstracted.
