# Compound RE Operations (Call Paths + String Usage) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two read-only compound RE operations — call-path discovery between two functions and string-usage tracing — wired through the Java plugin, MCP bridge, and Python CLI.

**Architecture:** Extend the existing `/analysis/*` namespace (Approach A). Both operations are new methods on `AnalysisService` (reusing `FunctionService`/`XrefService`/`DataService`), exposed via two new `AnalysisResource` routes, then mirrored as `analysis_*` MCP tools and `ghydra analysis ...` CLI commands. All traversal runs on the EDT via `GhidraSwing.runRead` and is hard-bounded server-side.

**Tech Stack:** Java 21 + Javalin (Ghidra plugin), Maven; Python 3.11+ (MCP bridge `bridge_mcp_hydra.py`, Click+Rich CLI `ghydra/`); JUnit (offline Java) + `unittest`/`requests` integration tests.

## Global Constraints

- Endpoints live under `/analysis/*`; MCP tools are `analysis_find_call_paths` / `analysis_trace_string_usage`; CLI commands are `ghydra analysis call-paths` / `ghydra analysis string-usage`.
- Versioning (CLAUDE.md): bump `PLUGIN_VERSION` (`api/ApiConstants.java`, currently `"v3.1.0-rc.1"` → `"v3.2.0"`) and `BRIDGE_VERSION` (`bridge_mcp_hydra.py`, currently `"v3.2.0"` → `"v3.3.0"`). **Do NOT change** `API_VERSION` (`3000`) or `REQUIRED_API_VERSION` (`3000`) — the change is purely additive.
- All Ghidra reads run inside `GhidraSwing.runRead(...)` (reentrant; runs on the EDT).
- Call-paths caps: `max_depth` default 5 / cap 15 (edges); `max_paths` default 50 / cap 500; `max_visited_edges` default 10,000 / cap 100,000.
- String-usage params/caps: `match` ∈ {`substring` (default), `regex`}; `caller_depth` default 0 / clamp 0..5; `max_strings` default 200 / cap 1,000; `max_functions` default 500 / cap 5,000 (**global** across the page's caller expansion).
- `CallPathDto.length` = number of functions (nodes) in the path; `max_depth` bounds edges (a path may contain up to `max_depth + 1` functions).
- `callers` is a flat, globally-deduplicated list of `CallerRefDto{function, depth}`; a single global visited set spans the whole request page.
- Errors use the existing envelope: missing params / bad `match` → 400 (`IllegalArgumentException`); invalid regex → 400 `BadRequestException("Invalid regex pattern: …", "INVALID_REGEX")`; unresolvable function → 404 `NotFoundException`. "No results" returns an empty list, never an error.
- Exceptions `NotFoundException` / `BadRequestException` are nested in `eu.starsong.ghidra.server.GhydraServer` (`BadRequestException(String message, String code)`).
- Integration tests only (no offline Java harness — that is the separate §6.1 gap); they hit a live instance on port 8192 and skip gracefully if absent. DTO records get a true offline JUnit test.
- Conventional-commit messages; update `CHANGELOG.md`.

### Build & deploy (needed before every Java integration-test step)

The Java integration tests in `test_http_api.py` run against a **live** Ghidra with the rebuilt plugin loaded. After changing Java, rebuild and reload:

```bash
# From repo root; GHIDRA_HOME points at the install, version must match.
GHIDRA_HOME=/path/to/ghidra mvn clean package -P plugin-only -Dghidra.version=<version>
# Swap target/Ghydra-*.jar's lib/Ghydra.jar into the installed extension, then restart Ghidra
# (or reinstall the extension zip). See CLAUDE.md "Iterating on the installed extension".
```

Offline JUnit tests (Task 1) run with plain `mvn test` and need no Ghidra.

---

## File Structure

- **Create** `src/main/java/eu/starsong/ghidra/dto/CallPathDto.java` — one call path (length + ordered functions).
- **Create** `src/main/java/eu/starsong/ghidra/dto/CallerRefDto.java` — a caller with its BFS depth.
- **Create** `src/main/java/eu/starsong/ghidra/dto/StringUsageDto.java` — a matched string + direct users + flat callers.
- **Create** `src/test/java/eu/starsong/ghidra/dto/CompoundReDtoTest.java` — offline JUnit for the three DTOs.
- **Modify** `src/main/java/eu/starsong/ghidra/service/AnalysisService.java` — add `DataService` dependency + `findCallPaths` + `traceStringUsage` + private helpers.
- **Modify** `src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java` — register + handle `/analysis/callpaths` and `/analysis/strings/usage`.
- **Modify** `src/main/java/eu/starsong/ghidra/api/ApiConstants.java` — bump `PLUGIN_VERSION`.
- **Modify** `bridge_mcp_hydra.py` — two `@mcp.tool()` functions + bump `BRIDGE_VERSION`.
- **Modify** `ghydra/cli/analysis.py` — `call-paths` + `string-usage` commands.
- **Modify** `ghydra/formatters/table_formatter.py` + `ghydra/formatters/json_formatter.py` — `format_call_paths` + `format_string_usage`.
- **Modify** `test_http_api.py` — `test_callpaths_endpoint` + `test_string_usage_endpoint`.
- **Modify** `test_mcp_client.py` — call-paths + string-usage + invalid-regex tool tests.
- **Modify** `GHIDRA_HTTP_API.md`, `GHYDRA_CLI.md`, `README.md`, `CHANGELOG.md` — document the additions.

---

## Task 1: Java result DTOs (offline TDD)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/dto/CallPathDto.java`
- Create: `src/main/java/eu/starsong/ghidra/dto/CallerRefDto.java`
- Create: `src/main/java/eu/starsong/ghidra/dto/StringUsageDto.java`
- Test: `src/test/java/eu/starsong/ghidra/dto/CompoundReDtoTest.java`

**Interfaces:**
- Produces:
  - `record CallPathDto(int length, List<FunctionSummaryDto> functions)` + `static CallPathDto of(List<FunctionSummaryDto> functions)` (sets `length = functions.size()`).
  - `record CallerRefDto(FunctionSummaryDto function, int depth)`.
  - `record StringUsageDto(StringUsageDto.StringRef string, List<FunctionSummaryDto> directUsers, List<CallerRefDto> callers)` with nested `record StringRef(String address, String value)`.

- [ ] **Step 1: Write the failing test**

Create `src/test/java/eu/starsong/ghidra/dto/CompoundReDtoTest.java`:

```java
package eu.starsong.ghidra.dto;

import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

public class CompoundReDtoTest {

    private FunctionSummaryDto fn(String name, String addr) {
        return new FunctionSummaryDto(name, addr, name + "(void)", "void", false, false, 0);
    }

    @Test
    public void callPathOfSetsLengthToNodeCount() {
        CallPathDto p = CallPathDto.of(List.of(fn("a", "0x1000"), fn("b", "0x2000"), fn("c", "0x3000")));
        assertEquals(3, p.length());
        assertEquals(3, p.functions().size());
        assertEquals("a", p.functions().get(0).name());
    }

    @Test
    public void callerRefCarriesDepth() {
        CallerRefDto c = new CallerRefDto(fn("caller", "0x4000"), 2);
        assertEquals(2, c.depth());
        assertEquals("caller", c.function().name());
    }

    @Test
    public void stringUsageHoldsRefUsersAndCallers() {
        StringUsageDto u = new StringUsageDto(
            new StringUsageDto.StringRef("0x8000", "CreateFileW"),
            List.of(fn("user", "0x5000")),
            List.of(new CallerRefDto(fn("up", "0x6000"), 1)));
        assertEquals("0x8000", u.string().address());
        assertEquals("CreateFileW", u.string().value());
        assertEquals(1, u.directUsers().size());
        assertEquals(1, u.callers().get(0).depth());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=CompoundReDtoTest`
Expected: FAIL — compilation error, `CallPathDto` / `CallerRefDto` / `StringUsageDto` do not exist.

- [ ] **Step 3: Write minimal implementation**

`src/main/java/eu/starsong/ghidra/dto/CallPathDto.java`:

```java
package eu.starsong.ghidra.dto;

import java.util.List;

/** An ordered call path from one function to another. {@code length} is the node count. */
public record CallPathDto(int length, List<FunctionSummaryDto> functions) {
    public static CallPathDto of(List<FunctionSummaryDto> functions) {
        return new CallPathDto(functions.size(), List.copyOf(functions));
    }
}
```

`src/main/java/eu/starsong/ghidra/dto/CallerRefDto.java`:

```java
package eu.starsong.ghidra.dto;

/** A function that (transitively) calls a string user, with its BFS depth (1 = direct caller). */
public record CallerRefDto(FunctionSummaryDto function, int depth) {
}
```

`src/main/java/eu/starsong/ghidra/dto/StringUsageDto.java`:

```java
package eu.starsong.ghidra.dto;

import java.util.List;

/** A matched string, the functions that directly reference it, and a flat list of upstream callers. */
public record StringUsageDto(StringRef string, List<FunctionSummaryDto> directUsers, List<CallerRefDto> callers) {
    public record StringRef(String address, String value) {
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -Dtest=CompoundReDtoTest`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/dto/CallPathDto.java \
        src/main/java/eu/starsong/ghidra/dto/CallerRefDto.java \
        src/main/java/eu/starsong/ghidra/dto/StringUsageDto.java \
        src/test/java/eu/starsong/ghidra/dto/CompoundReDtoTest.java
git commit -m "feat: add compound-RE result DTOs (call paths, string usage)"
```

---

## Task 2: Call-path discovery — service + endpoint

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/AnalysisService.java`
- Modify: `src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java`
- Test: `test_http_api.py` (`test_callpaths_endpoint`)

**Interfaces:**
- Consumes: `CallPathDto.of(...)` (Task 1); `XrefService.getCallsFromFunction(program, fn)`; `FunctionService.findByAddress`, `requireFunctionByName`; `GhidraUtil.resolveAddress`.
- Produces: `AnalysisService.findCallPaths(Program program, String from, String to, int maxDepth, int maxPaths, int maxVisitedEdges) -> Map<String,Object>` with keys `from`, `to`, `max_depth`, `max_paths`, `truncated`, `paths` (`List<CallPathDto>`). Route: `GET /analysis/callpaths`.

- [ ] **Step 1: Write the failing test**

Add to the `GhydraMCPHttpApiTests` class in `test_http_api.py`:

```python
    def test_callpaths_endpoint(self):
        """Test the /analysis/callpaths endpoint."""
        response = requests.get(f"{BASE_URL}/functions?limit=1")
        if response.status_code == 404:
            return
        self.assertEqual(response.status_code, 200)
        result = response.json().get("result", [])
        if not result:
            self.skipTest("No functions available to test callpaths")
        func = result[0] if isinstance(result, list) else result
        addr = func.get("address")
        if not addr:
            self.skipTest("No address for callpaths test")

        # Trivial path: from a function to itself must succeed and contain one path.
        response = requests.get(f"{BASE_URL}/analysis/callpaths?from={addr}&to={addr}&max_depth=3")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertStandardSuccessResponse(data)
        result = data["result"]
        for key in ("from", "to", "max_depth", "max_paths", "truncated", "paths"):
            self.assertIn(key, result, f"callpaths result missing '{key}'")
        self.assertIsInstance(result["paths"], list)
        self.assertGreaterEqual(len(result["paths"]), 1, "self->self should yield a path")
        self.assertEqual(result["paths"][0]["length"], len(result["paths"][0]["functions"]))

        # Missing 'to' must be a 400.
        response = requests.get(f"{BASE_URL}/analysis/callpaths?from={addr}")
        self.assertEqual(response.status_code, 400)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_http_api.GhydraMCPHttpApiTests.test_callpaths_endpoint`
Expected: FAIL — the `/analysis/callpaths` request returns 404 (route not registered) so the status-code assertion fails. (If no Ghidra is running, the test returns early / skips — start Ghidra to get a real run.)

- [ ] **Step 3: Write minimal implementation (service)**

In `AnalysisService.java`, add imports near the top:

```java
import eu.starsong.ghidra.dto.CallPathDto;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.program.model.address.Address;
import java.util.LinkedHashSet;
```

Add a `DataService` field and update constructors (used in Task 3; add now to avoid touching twice):

```java
    private final DataService dataService;
```

Replace the two existing constructors with:

```java
    public AnalysisService() {
        this.functionService = new FunctionService();
        this.xrefService = new XrefService();
        this.dataService = new DataService();
    }

    public AnalysisService(FunctionService functionService, XrefService xrefService, DataService dataService) {
        this.functionService = functionService;
        this.xrefService = xrefService;
        this.dataService = dataService;
    }
```

Add the method and helpers (anywhere in the class body):

```java
    /**
     * Find bounded, simple (loop-free) call paths from one function to another.
     * Resolves {@code from}/{@code to} by address first, then by name.
     */
    public Map<String, Object> findCallPaths(Program program, String from, String to,
                                             int maxDepth, int maxPaths, int maxVisitedEdges) {
        return GhidraSwing.runRead(() -> {
            Function fromFn = resolveFunction(program, from);
            Function toFn = resolveFunction(program, to);
            String toAddr = toFn.getEntryPoint().toString();

            List<CallPathDto> paths = new ArrayList<>();
            int[] visitedEdges = {0};
            boolean[] truncated = {false};

            List<Function> current = new ArrayList<>();
            Set<String> onPath = new HashSet<>();
            current.add(fromFn);
            onPath.add(fromFn.getEntryPoint().toString());

            dfsCallPaths(program, fromFn, toAddr, maxDepth, maxPaths, maxVisitedEdges,
                current, onPath, paths, visitedEdges, truncated);

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("from", fromFn.getEntryPoint().toString());
            data.put("to", toAddr);
            data.put("max_depth", maxDepth);
            data.put("max_paths", maxPaths);
            data.put("truncated", truncated[0]);
            data.put("paths", paths);
            return data;
        });
    }

    private void dfsCallPaths(Program program, Function current, String toAddr,
                              int depth, int maxPaths, int maxVisitedEdges,
                              List<Function> path, Set<String> onPath,
                              List<CallPathDto> paths, int[] visitedEdges, boolean[] truncated) {
        if (current.getEntryPoint().toString().equals(toAddr)) {
            List<eu.starsong.ghidra.dto.FunctionSummaryDto> fns = new ArrayList<>();
            for (Function f : path) {
                fns.add(eu.starsong.ghidra.dto.FunctionSummaryDto.from(f));
            }
            paths.add(CallPathDto.of(fns));
            if (paths.size() >= maxPaths) truncated[0] = true;
            return;
        }
        if (depth <= 0) return;

        for (XrefDto xref : xrefService.getCallsFromFunction(program, current)) {
            if (paths.size() >= maxPaths) { truncated[0] = true; return; }
            if (visitedEdges[0] >= maxVisitedEdges) { truncated[0] = true; return; }
            visitedEdges[0]++;

            String calleeAddr = xref.toFunctionAddress();
            if (calleeAddr == null || onPath.contains(calleeAddr)) continue;
            Function callee = functionService.findByAddress(program, calleeAddr);
            if (callee == null) continue;

            onPath.add(calleeAddr);
            path.add(callee);
            dfsCallPaths(program, callee, toAddr, depth - 1, maxPaths, maxVisitedEdges,
                path, onPath, paths, visitedEdges, truncated);
            path.remove(path.size() - 1);
            onPath.remove(calleeAddr);
        }
    }

    /** Resolve a function by address (entry point) first, then fall back to name. */
    private Function resolveFunction(Program program, String lookup) {
        Address addr = GhidraUtil.resolveAddress(program, lookup);
        if (addr != null) {
            Function f = program.getFunctionManager().getFunctionAt(addr);
            if (f != null) return f;
        }
        return functionService.requireFunctionByName(program, lookup);
    }
```

- [ ] **Step 4: Write minimal implementation (resource)**

In `AnalysisResource.java`, register the route inside `register(...)` (after the `dataflow` line):

```java
        app.get("/analysis/callpaths", ctx -> callPaths(contextFactory.apply(ctx)));
```

Add the handler method:

```java
    private void callPaths(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String from = ctx.queryParam("from");
        String to = ctx.queryParam("to");
        if (from == null || from.isEmpty() || to == null || to.isEmpty()) {
            throw new IllegalArgumentException("Both 'from' and 'to' query parameters are required");
        }
        int maxDepth = Math.min(ctx.queryParamAsInt("max_depth", 5), 15);
        int maxPaths = Math.min(ctx.queryParamAsInt("max_paths", 50), 500);
        int maxVisitedEdges = Math.min(ctx.queryParamAsInt("max_visited_edges", 10000), 100000);

        Map<String, Object> result = analysisService.findCallPaths(program, from, to, maxDepth, maxPaths, maxVisitedEdges);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/analysis/callpaths?from={}&to={}", from, to)
            .link("from", "/functions/{}", String.valueOf(result.get("from")))
            .link("to", "/functions/{}", String.valueOf(result.get("to")))
            .build());
    }
```

- [ ] **Step 5: Rebuild, reload, run test**

Rebuild + reload per "Build & deploy" above, then:
Run: `python -m unittest test_http_api.GhydraMCPHttpApiTests.test_callpaths_endpoint`
Expected: PASS (with a program loaded in Ghidra).

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/AnalysisService.java \
        src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java \
        test_http_api.py
git commit -m "feat: add /analysis/callpaths call-path discovery endpoint"
```

---

## Task 3: String-usage tracing — service + endpoint

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/AnalysisService.java`
- Modify: `src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java`
- Test: `test_http_api.py` (`test_string_usage_endpoint`)

**Interfaces:**
- Consumes: `StringUsageDto` / `CallerRefDto` (Task 1); `DataService.listStrings`; `XrefService.getReferencesTo`, `getCallsTo`; `FunctionService.findContaining`; the `DataService` field added in Task 2.
- Produces: `AnalysisService.traceStringUsage(Program program, String value, String match, int callerDepth, int offset, int limit, int maxStrings, int maxFunctions) -> Map<String,Object>` with keys `value`, `match`, `caller_depth`, `size`, `offset`, `limit`, `truncated`, `matches` (`List<StringUsageDto>`). Route: `GET /analysis/strings/usage`.

- [ ] **Step 1: Write the failing test**

Add to `GhydraMCPHttpApiTests` in `test_http_api.py`:

```python
    def test_string_usage_endpoint(self):
        """Test the /analysis/strings/usage endpoint."""
        response = requests.get(f"{BASE_URL}/data/strings?limit=1")
        if response.status_code == 404:
            return
        if response.status_code != 200:
            self.skipTest("strings listing unavailable")
        result = response.json().get("result", [])
        if not result:
            self.skipTest("No strings available to test string-usage")
        sample = (result[0].get("value") or "")[:4]
        if not sample:
            self.skipTest("No usable string value")

        # Substring match, direct users only (caller_depth defaults to 0).
        response = requests.get(f"{BASE_URL}/analysis/strings/usage?value={sample}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertStandardSuccessResponse(data)
        result = data["result"]
        for key in ("value", "match", "caller_depth", "size", "offset", "limit", "truncated", "matches"):
            self.assertIn(key, result, f"string-usage result missing '{key}'")
        self.assertEqual(result["match"], "substring")
        self.assertEqual(result["caller_depth"], 0)
        self.assertIsInstance(result["matches"], list)

        # Invalid regex must be a 400 with a descriptive message.
        response = requests.get(f"{BASE_URL}/analysis/strings/usage?value=%5B&match=regex")
        self.assertEqual(response.status_code, 400)
        self.assertIn("regex", response.json().get("error", {}).get("message", "").lower())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest test_http_api.GhydraMCPHttpApiTests.test_string_usage_endpoint`
Expected: FAIL — `/analysis/strings/usage` returns 404 (route not registered).

- [ ] **Step 3: Write minimal implementation (service)**

In `AnalysisService.java` add imports:

```java
import eu.starsong.ghidra.dto.CallerRefDto;
import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;
import eu.starsong.ghidra.server.GhydraServer.BadRequestException;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
```

Add the method + helper:

```java
    /**
     * Trace which functions reference strings matching {@code value}, with an optional
     * bounded walk up the reverse call graph. Paginates the matched-strings list and
     * resolves users/callers only for the requested page; the {@code max_functions} cap
     * is global across that page.
     */
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
            List<DataDto> matched = new ArrayList<>();
            boolean[] truncated = {false};
            for (DataDto d : dataService.listStrings(program)) {
                String v = d.value();
                if (v == null) continue;
                boolean hit = pattern != null ? pattern.matcher(v).find() : v.contains(value);
                if (hit) {
                    matched.add(d);
                    if (matched.size() >= maxStrings) { truncated[0] = true; break; }
                }
            }

            int total = matched.size();
            int start = Math.max(0, Math.min(offset, total));
            int end = Math.min(total, start + limit);
            List<DataDto> page = start < end ? matched.subList(start, end) : Collections.emptyList();

            int[] fnBudget = {maxFunctions};
            Set<String> globalVisited = new HashSet<>();
            List<StringUsageDto> matches = new ArrayList<>();
            for (DataDto d : page) {
                matches.add(resolveStringUsage(program, d, callerDepth, fnBudget, globalVisited, truncated));
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("value", value);
            data.put("match", match);
            data.put("caller_depth", callerDepth);
            data.put("size", total);
            data.put("offset", offset);
            data.put("limit", limit);
            data.put("truncated", truncated[0]);
            data.put("matches", matches);
            return data;
        });
    }

    private StringUsageDto resolveStringUsage(Program program, DataDto str, int callerDepth,
                                              int[] fnBudget, Set<String> globalVisited, boolean[] truncated) {
        List<FunctionSummaryDto> directUsers = new ArrayList<>();
        Set<String> directAddrs = new LinkedHashSet<>();
        for (XrefDto x : xrefService.getReferencesTo(program, str.address())) {
            Function f = functionService.findContaining(program, x.fromAddress());
            if (f == null) continue;
            if (directAddrs.add(f.getEntryPoint().toString())) {
                directUsers.add(FunctionSummaryDto.from(f));
            }
        }

        List<CallerRefDto> callers = new ArrayList<>();
        if (callerDepth > 0) {
            Set<String> currentLevel = new LinkedHashSet<>(directAddrs);
            int depth = 1;
            while (depth <= callerDepth && !currentLevel.isEmpty()) {
                Set<String> nextLevel = new LinkedHashSet<>();
                for (String fnAddr : currentLevel) {
                    for (XrefDto x : xrefService.getCallsTo(program, fnAddr)) {
                        Function caller = functionService.findContaining(program, x.fromAddress());
                        if (caller == null) continue;
                        String ca = caller.getEntryPoint().toString();
                        if (directAddrs.contains(ca) || globalVisited.contains(ca)) continue;
                        if (fnBudget[0] <= 0) { truncated[0] = true; return new StringUsageDto(
                            new StringUsageDto.StringRef(str.address(), str.value()), directUsers, callers); }
                        globalVisited.add(ca);
                        callers.add(new CallerRefDto(FunctionSummaryDto.from(caller), depth));
                        fnBudget[0]--;
                        nextLevel.add(ca);
                    }
                }
                currentLevel = nextLevel;
                depth++;
            }
        }

        return new StringUsageDto(new StringUsageDto.StringRef(str.address(), str.value()), directUsers, callers);
    }
```

- [ ] **Step 4: Write minimal implementation (resource)**

In `AnalysisResource.java`, add imports:

```java
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
```

Register the route inside `register(...)`:

```java
        app.get("/analysis/strings/usage", ctx -> stringUsage(contextFactory.apply(ctx)));
```

Add the handler:

```java
    private void stringUsage(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String value = ctx.queryParam("value");
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("'value' query parameter is required");
        }
        String match = ctx.queryParam("match", "substring");
        if (!"substring".equals(match) && !"regex".equals(match)) {
            throw new IllegalArgumentException("match must be 'substring' or 'regex'");
        }
        int callerDepth = Math.min(Math.max(ctx.queryParamAsInt("caller_depth", 0), 0), 5);
        int maxStrings = Math.min(ctx.queryParamAsInt("max_strings", 200), 1000);
        int maxFunctions = Math.min(ctx.queryParamAsInt("max_functions", 500), 5000);
        var pg = ctx.pagination();

        Map<String, Object> result = analysisService.traceStringUsage(
            program, value, match, callerDepth, pg.offset(), pg.limit(), maxStrings, maxFunctions);

        int total = (int) result.get("size");
        int offset = (int) result.get("offset");
        int limit = (int) result.get("limit");
        String enc = URLEncoder.encode(value, StandardCharsets.UTF_8);
        String base = String.format("/analysis/strings/usage?value=%s&match=%s&caller_depth=%d", enc, match, callerDepth);

        Response resp = Response.ok(ctx.ctx(), ctx.port(), result)
            .self(base + "&offset=" + offset + "&limit=" + limit)
            .link("program", "/program");
        if (offset + limit < total) {
            resp.link("next", base + "&offset=" + (offset + limit) + "&limit=" + limit);
        }
        if (offset > 0) {
            resp.link("prev", base + "&offset=" + Math.max(0, offset - limit) + "&limit=" + limit);
        }
        ctx.json(resp.build());
    }
```

Note: `AnalysisResource` already imports `java.util.*`, so `Map` is available. The `dataflow` handler already throws `IllegalArgumentException` for bad params and the middleware maps it to 400, so the invalid-`match` / missing-`value` cases need no extra wiring.

- [ ] **Step 5: Rebuild, reload, run test**

Rebuild + reload, then:
Run: `python -m unittest test_http_api.GhydraMCPHttpApiTests.test_string_usage_endpoint`
Expected: PASS (with a program loaded).

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/AnalysisService.java \
        src/main/java/eu/starsong/ghidra/resource/AnalysisResource.java \
        test_http_api.py
git commit -m "feat: add /analysis/strings/usage string-usage tracing endpoint"
```

---

## Task 4: MCP bridge tools + version bump

**Files:**
- Modify: `bridge_mcp_hydra.py`
- Test: `test_mcp_client.py`

**Interfaces:**
- Consumes: the two endpoints from Tasks 2–3; `_get_instance_port`, `safe_get`, `simplify_response`, `time`, `@mcp.tool()`, `@text_output` (all already imported/defined in the bridge).
- Produces:
  - `analysis_find_call_paths(from_fn: str, to_fn: str, max_depth: int = 5, max_paths: int = 50, port: int | None = None) -> dict`
  - `analysis_trace_string_usage(value: str, match: str = "substring", caller_depth: int = 0, offset: int = 0, limit: int = 50, port: int | None = None) -> dict`

- [ ] **Step 1: Write the failing test**

Add two coroutine tests in `test_mcp_client.py` (module level, mirroring `test_bridge`'s session usage). Append before the `if __name__` block:

```python
async def test_compound_re_tools():
    """call-paths + string-usage tools, including invalid-regex error passthrough."""
    server_parameters = StdioServerParameters(command=sys.executable, args=["bridge_mcp_hydra.py"])
    async with stdio_client(server_parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools = {t.name for t in (await session.list_tools()).tools}
            assert "analysis_find_call_paths" in tools, "analysis_find_call_paths tool missing"
            assert "analysis_trace_string_usage" in tools, "analysis_trace_string_usage tool missing"

            # Invalid regex must surface the specific message, not a generic failure.
            res = await session.call_tool("analysis_trace_string_usage",
                                          {"value": "[", "match": "regex"})
            text = res.content[0].text if res.content else ""
            data = json.loads(text)
            if data.get("success") is False:
                assert "regex" in json.dumps(data.get("error", {})).lower(), \
                    f"expected regex error message, got: {data.get('error')}"
            # If success is True, no Ghidra program is loaded — acceptable (tool reachable).

    logger.info("compound RE tools OK")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -c "import anyio, test_mcp_client as t; anyio.run(t.test_compound_re_tools)"`
Expected: FAIL — `AssertionError: analysis_find_call_paths tool missing`.

- [ ] **Step 3: Write minimal implementation**

In `bridge_mcp_hydra.py`, bump the version (line ~36):

```python
BRIDGE_VERSION = "v3.3.0"
```

Add both tools immediately after `analysis_get_dataflow` (after its `return simplify_response(response)`, ~line 4124):

```python
@mcp.tool()
@text_output
def analysis_find_call_paths(from_fn: str, to_fn: str, max_depth: int = 5,
                             max_paths: int = 50, port: int | None = None) -> dict:
    """Find bounded simple call paths from one function to another.

    Args:
        from_fn: Source function — fully-qualified name or address.
        to_fn: Target function — fully-qualified name or address.
        max_depth: Max path length in call edges (default 5, capped at 15 server-side).
        max_paths: Max number of paths returned (default 50, capped at 500 server-side).
        port: Specific Ghidra instance port (optional).

    Returns:
        dict: {from, to, max_depth, max_paths, truncated, paths:[{length, functions:[...]}]}
    """
    if not from_fn or not to_fn:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "Both from_fn and to_fn are required"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    params = {"from": from_fn, "to": to_fn, "max_depth": max_depth, "max_paths": max_paths}
    response = safe_get(port, "analysis/callpaths", params)
    return simplify_response(response)


@mcp.tool()
@text_output
def analysis_trace_string_usage(value: str, match: str = "substring", caller_depth: int = 0,
                                offset: int = 0, limit: int = 50, port: int | None = None) -> dict:
    """Trace which functions use a string, optionally walking the reverse call graph.

    Args:
        value: The string to search for.
        match: "substring" (default, case-sensitive) or "regex".
        caller_depth: 0 = direct users only (default); >0 walks callers upward (capped at 5).
        offset: Pagination offset over matched strings (default 0).
        limit: Pagination limit over matched strings (default 50).
        port: Specific Ghidra instance port (optional).

    Returns:
        dict: {value, match, caller_depth, size, offset, limit, truncated,
               matches:[{string:{address,value}, directUsers:[...], callers:[{function,depth}]}]}
    """
    if not value:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "value is required"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    params = {"value": value, "match": match, "caller_depth": caller_depth,
              "offset": offset, "limit": limit}
    response = safe_get(port, "analysis/strings/usage", params)
    return simplify_response(response)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -c "import anyio, test_mcp_client as t; anyio.run(t.test_compound_re_tools)"`
Expected: PASS (tools are listed; invalid-regex assertion holds whether or not Ghidra is loaded).

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py test_mcp_client.py
git commit -m "feat: add analysis_find_call_paths and analysis_trace_string_usage MCP tools"
```

---

## Task 5: Python CLI commands + formatters

**Files:**
- Modify: `ghydra/cli/analysis.py`
- Modify: `ghydra/formatters/table_formatter.py`
- Modify: `ghydra/formatters/json_formatter.py`

**Interfaces:**
- Consumes: the two endpoints; `client.get`, `formatter`, `should_page`, `page_output`, `rich_echo`, `validate_address`, `GhidraError` (already imported in `analysis.py`); `Table` (already imported in `table_formatter.py`).
- Produces: CLI commands `ghydra analysis call-paths` and `ghydra analysis string-usage`; formatter methods `format_call_paths(data)` and `format_string_usage(data)` on `TableFormatter` and `JSONFormatter`. (Follows the existing `format_callgraph` precedent — defined on table+json, the CLI uses a `hasattr` fallback to `format_simple_result`; `base.py` is not changed because `format_callgraph` is likewise not declared there.)

- [ ] **Step 1: Add the JSON formatter methods**

In `ghydra/formatters/json_formatter.py`, after `format_dataflow` (~line 123):

```python
    def format_call_paths(self, data: Dict[str, Any]) -> str:
        """Format call paths as JSON."""
        return self._format_json(data)

    def format_string_usage(self, data: Dict[str, Any]) -> str:
        """Format string usage as JSON."""
        return self._format_json(data)
```

- [ ] **Step 2: Add the table formatter methods**

In `ghydra/formatters/table_formatter.py`, after `format_dataflow` (~line 682):

```python
    def format_call_paths(self, data: Dict[str, Any]) -> str:
        """Format call paths as a table (one row per path, arrow chain of functions)."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No call path data available[/yellow]")

        paths = result.get("paths", []) or []
        header = self._capture(
            f"[cyan]Call paths[/cyan] {result.get('from', '?')} -> {result.get('to', '?')} "
            f"({len(paths)} found"
            + (", truncated" if result.get("truncated") else "") + ")"
        )
        if not paths:
            return f"{header}\n" + self._capture("[yellow]No paths found[/yellow]")

        table = Table(show_lines=False)
        table.add_column("#", style="cyan", justify="right")
        table.add_column("Len", style="dim", justify="right")
        table.add_column("Path", style="green", overflow="fold")
        for i, p in enumerate(paths, start=1):
            fns = p.get("functions", []) if isinstance(p, dict) else []
            chain = " -> ".join(f"{f.get('name', '?')}" for f in fns)
            table.add_row(str(i), str(p.get("length", len(fns))), chain)
        return f"{header}\n" + self._capture(table)

    def format_string_usage(self, data: Dict[str, Any]) -> str:
        """Format string usage: matched strings, direct users, and flat callers with depth."""
        result = data.get("result", {})
        if not isinstance(result, dict):
            return self._capture("[yellow]No string usage data available[/yellow]")

        matches = result.get("matches", []) or []
        header = self._capture(
            f"[cyan]String usage[/cyan] value={result.get('value', '?')} "
            f"match={result.get('match', '?')} caller_depth={result.get('caller_depth', 0)} "
            f"(size={result.get('size', 0)}"
            + (", truncated" if result.get("truncated") else "") + ")"
        )
        if not matches:
            return f"{header}\n" + self._capture("[yellow]No matches[/yellow]")

        table = Table(show_lines=True)
        table.add_column("String @", style="green", no_wrap=True)
        table.add_column("Value", style="white", overflow="fold")
        table.add_column("Direct users", style="cyan", overflow="fold")
        table.add_column("Callers (depth)", style="yellow", overflow="fold")
        for m in matches:
            if not isinstance(m, dict):
                continue
            s = m.get("string", {})
            users = ", ".join(f.get("name", "?") for f in m.get("directUsers", []))
            callers = ", ".join(
                f"{c.get('function', {}).get('name', '?')}({c.get('depth', '?')})"
                for c in m.get("callers", [])
            )
            table.add_row(str(s.get("address", "?")), str(s.get("value", "")),
                          users or "-", callers or "-")
        return f"{header}\n" + self._capture(table)
```

- [ ] **Step 3: Add the CLI commands**

In `ghydra/cli/analysis.py`, add after `get_dataflow` (before `status`):

```python
@analysis.command('call-paths')
@click.option('--from', 'from_fn', required=True, help='Source function (name or address)')
@click.option('--to', 'to_fn', required=True, help='Target function (name or address)')
@click.option('--max-depth', type=int, default=5, help='Max path length in edges (default 5, cap 15)')
@click.option('--max-paths', type=int, default=50, help='Max number of paths (default 50, cap 500)')
@click.pass_context
def call_paths(ctx, from_fn, to_fn, max_depth, max_paths):
    """Find bounded call paths between two functions.

    \b
    Examples:
        ghydra analysis call-paths --from main --to fopen
        ghydra analysis call-paths --from 0x401000 --to 0x405abc --max-depth 8
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'from': from_fn, 'to': to_fn, 'max_depth': max_depth, 'max_paths': max_paths}
        response = client.get('analysis/callpaths', params=params)
        if hasattr(formatter, "format_call_paths"):
            output = formatter.format_call_paths(response)
        else:
            output = formatter.format_simple_result(response)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)


@analysis.command('string-usage')
@click.argument('value')
@click.option('--match', type=click.Choice(['substring', 'regex']), default='substring',
              help='Match mode (default substring)')
@click.option('--caller-depth', type=int, default=0, help='Reverse-call-graph depth (default 0, cap 5)')
@click.option('--limit', type=int, default=50, help='Page size over matched strings')
@click.option('--offset', type=int, default=0, help='Page offset over matched strings')
@click.pass_context
def string_usage(ctx, value, match, caller_depth, limit, offset):
    """Trace which functions use a string (and optionally their callers).

    \b
    Examples:
        ghydra analysis string-usage CreateFileW
        ghydra analysis string-usage "error: %s" --match regex --caller-depth 2
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'value': value, 'match': match, 'caller_depth': caller_depth,
                  'limit': limit, 'offset': offset}
        response = client.get('analysis/strings/usage', params=params)
        if hasattr(formatter, "format_string_usage"):
            output = formatter.format_string_usage(response)
        else:
            output = formatter.format_simple_result(response)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)
```

- [ ] **Step 4: Verify the CLI loads and commands are registered**

Run: `ghydra analysis --help`
Expected: output lists `call-paths` and `string-usage` among the commands.

Run: `ghydra analysis call-paths --help`
Expected: shows `--from`, `--to`, `--max-depth`, `--max-paths` options (exit 0).

- [ ] **Step 5: Commit**

```bash
git add ghydra/cli/analysis.py ghydra/formatters/table_formatter.py ghydra/formatters/json_formatter.py
git commit -m "feat: add 'analysis call-paths' and 'analysis string-usage' CLI commands"
```

---

## Task 6: Docs + plugin version bump + changelog

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`
- Modify: `GHIDRA_HTTP_API.md`
- Modify: `GHYDRA_CLI.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: everything from Tasks 1–5 (final names/params).
- Produces: bumped `PLUGIN_VERSION`; documentation entries for both endpoints, both CLI commands, both MCP tools.

- [ ] **Step 1: Bump the plugin version**

In `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`:

```java
    public static final String PLUGIN_VERSION = "v3.2.0";
```

(Leave `API_VERSION = 3000` unchanged.)

- [ ] **Step 2: Document the HTTP endpoints**

In `GHIDRA_HTTP_API.md`, under the analysis section, add entries for:
- `GET /analysis/callpaths` — params `from`, `to` (name or address, required), `max_depth` (default 5, cap 15), `max_paths` (default 50, cap 500), `max_visited_edges` (default 10000, cap 100000). Response keys `from, to, max_depth, max_paths, truncated, paths[]` where each path is `{length, functions[]}`. Errors: 400 missing param, 404 unknown function.
- `GET /analysis/strings/usage` — params `value` (required), `match` (`substring`|`regex`, default `substring`), `caller_depth` (default 0, cap 5), `max_strings` (default 200, cap 1000), `max_functions` (default 500, cap 5000), plus `offset`/`limit`. Response keys `value, match, caller_depth, size, offset, limit, truncated, matches[]` where each match is `{string:{address,value}, directUsers[], callers[{function,depth}]}`. Errors: 400 missing `value` / bad `match` / invalid regex.

- [ ] **Step 3: Document the CLI commands**

In `GHYDRA_CLI.md`, under the `analysis` group, add `call-paths` and `string-usage` with the option lists and the example invocations from Task 5.

- [ ] **Step 4: Document the MCP tools**

In `README.md`, in the analysis tool catalog, add `analysis_find_call_paths` and `analysis_trace_string_usage` with one-line descriptions matching their docstrings.

- [ ] **Step 5: Update the changelog**

In `CHANGELOG.md`, add under an unreleased/next section:

```markdown
### Added
- `GET /analysis/callpaths` + `analysis_find_call_paths` tool + `ghydra analysis call-paths`: bounded call-path discovery between two functions.
- `GET /analysis/strings/usage` + `analysis_trace_string_usage` tool + `ghydra analysis string-usage`: string-usage tracing with an optional reverse-call-graph walk.
```

- [ ] **Step 6: Build to confirm version compiles, then commit**

Run: `mvn -q -DskipTests package -P plugin-only -Dghidra.version=<version>` (or `mvn compile`)
Expected: BUILD SUCCESS.

```bash
git add src/main/java/eu/starsong/ghidra/api/ApiConstants.java \
        GHIDRA_HTTP_API.md GHYDRA_CLI.md README.md CHANGELOG.md
git commit -m "docs: document compound-RE call-paths and string-usage; bump plugin version"
```

---

## Self-Review

**Spec coverage:**
- §3 Architecture / Approach A → Task 2/3 (extend `AnalysisService` + `/analysis/*`). ✓
- §4 findCallPaths (params, DFS, `max_visited_edges`, response, errors) → Task 2. ✓
- §5 traceStringUsage (match modes, `caller_depth`, flat deduped callers, global `max_functions`, pagination, invalid-regex 400) → Task 3. ✓
- §6 DTOs (`CallPathDto`, `CallerRefDto`, `StringUsageDto`) → Task 1. ✓
- §7 client wiring (bridge tools, CLI commands, all formatters per the callgraph precedent) → Tasks 4–5. ✓
- §8 error bubbling (plugin emits `error.message`; bridge passes through `simplify_response`) → Task 3 (400 message) + Task 4 (passthrough test). ✓
- §9 versioning (bump PLUGIN_VERSION + BRIDGE_VERSION, keep API_VERSION) → Task 4 (bridge) + Task 6 (plugin). ✓
- §10 testing (HTTP + MCP integration, offline DTO unit test) → Tasks 1–4. ✓
- §11 non-goals (other §3.5 ops, offline harness, subagent chunking) → not implemented. ✓

**Placeholder scan:** No TBD/“add error handling”/“similar to Task N” — all steps contain concrete code or exact commands. ✓

**Type consistency:** `findCallPaths` / `traceStringUsage` signatures, `CallPathDto.of`, `StringUsageDto.StringRef`, `CallerRefDto(function, depth)`, query params (`from`/`to`/`value`/`match`/`caller_depth`), and bridge param names (`from_fn`/`to_fn`) match across tasks. The `DataService` field + 3-arg DI constructor are introduced in Task 2 and consumed in Task 3. ✓
