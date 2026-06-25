package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.CallPathDto;
import eu.starsong.ghidra.dto.CallerRefDto;
import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.server.GhydraServer.BadRequestException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Service for advanced analysis operations (call graphs, callers, callees).
 * Contains the call-graph traversal business logic extracted from AnalysisResource.
 *
 * <p>The DB-reading traversals are wrapped in {@link GhidraSwing#runRead} so the whole
 * read+build runs on the EDT. {@code runRead} is reentrant, so the nested
 * {@link XrefService} calls (which run their own reads) execute inline.
 */
public class AnalysisService {

    private final FunctionService functionService;
    private final XrefService xrefService;
    private final DataService dataService;

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

    /**
     * Result of a call-graph traversal: the built data map plus the resolved entry point.
     */
    public record CallGraphResult(Map<String, Object> data, String entryPoint) {
    }

    /**
     * Build the call graph for a function, resolving the start function by address or name.
     *
     * @param byAddress if true, {@code lookup} is an address; otherwise a function name
     * @param lookup    the address or name to resolve the start function
     */
    public CallGraphResult callGraph(Program program, boolean byAddress, String lookup, int depth, String direction) {
        // The traversal dereferences live Function objects (FunctionSummaryDto.from,
        // getEntryPoint, recursive xref walks). Run the whole read+build on the EDT.
        return GhidraSwing.runRead(() -> {
            Function startFn = byAddress
                ? functionService.requireFunctionByAddress(program, lookup)
                : functionService.requireFunctionByName(program, lookup);

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("root", FunctionSummaryDto.from(startFn));
            data.put("depth", depth);
            data.put("direction", direction);

            String entryPoint = startFn.getEntryPoint().toString();
            Set<String> visited = new HashSet<>();
            visited.add(entryPoint);

            if ("callers".equals(direction) || "both".equals(direction)) {
                List<Map<String, Object>> callers = buildCallTree(program, startFn, depth, true, visited);
                data.put("callers", callers);
            }

            if ("callees".equals(direction) || "both".equals(direction)) {
                visited.clear();
                visited.add(entryPoint);
                List<Map<String, Object>> callees = buildCallTree(program, startFn, depth, false, visited);
                data.put("callees", callees);
            }

            return new CallGraphResult(data, entryPoint);
        });
    }

    /**
     * Get the functions that call the function at the given address.
     */
    public List<FunctionSummaryDto> callers(Program program, String address) {
        return GhidraSwing.runRead(() -> {
            functionService.requireFunctionByAddress(program, address);

            List<XrefDto> callXrefs = xrefService.getCallsTo(program, address);

            Set<String> seen = new HashSet<>();
            List<FunctionSummaryDto> list = new ArrayList<>();

            for (XrefDto xref : callXrefs) {
                if (xref.fromFunctionAddress() != null && !seen.contains(xref.fromFunctionAddress())) {
                    seen.add(xref.fromFunctionAddress());
                    Function callerFn = functionService.findByAddress(program, xref.fromFunctionAddress());
                    if (callerFn != null) {
                        list.add(FunctionSummaryDto.from(callerFn));
                    }
                }
            }
            return list;
        });
    }

    /**
     * Get the functions called by the function at the given address.
     */
    public List<FunctionSummaryDto> callees(Program program, String address) {
        return GhidraSwing.runRead(() -> {
            Function fn = functionService.requireFunctionByAddress(program, address);

            // Calls are made from instructions inside the body, not the entry address.
            List<XrefDto> callXrefs = xrefService.getCallsFromFunction(program, fn);

            Set<String> seen = new HashSet<>();
            List<FunctionSummaryDto> list = new ArrayList<>();

            for (XrefDto xref : callXrefs) {
                if (xref.toFunctionAddress() != null && !seen.contains(xref.toFunctionAddress())) {
                    seen.add(xref.toFunctionAddress());
                    Function calleeFn = functionService.findByAddress(program, xref.toFunctionAddress());
                    if (calleeFn != null) {
                        list.add(FunctionSummaryDto.from(calleeFn));
                    }
                }
            }
            return list;
        });
    }

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
            List<FunctionSummaryDto> fns = new ArrayList<>();
            for (Function f : path) {
                fns.add(FunctionSummaryDto.from(f));
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
                        if (fnBudget[0] <= 0) {
                            truncated[0] = true;
                            return new StringUsageDto(
                                new StringUsageDto.StringRef(str.address(), str.value()), directUsers, callers);
                        }
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

    private List<Map<String, Object>> buildCallTree(Program program, Function fn, int depth, boolean callers, Set<String> visited) {
        if (depth <= 0) {
            return Collections.emptyList();
        }

        List<Map<String, Object>> result = new ArrayList<>();
        String addr = fn.getEntryPoint().toString();

        // Callers: refs TO the entry address. Callees: CALL refs from anywhere
        // inside the body (the entry address itself almost never makes a call).
        List<XrefDto> xrefs = callers
            ? xrefService.getCallsTo(program, addr)
            : xrefService.getCallsFromFunction(program, fn);

        for (XrefDto xref : xrefs) {
            String targetAddr = callers ? xref.fromFunctionAddress() : xref.toFunctionAddress();
            if (targetAddr == null || visited.contains(targetAddr)) {
                continue;
            }

            Function targetFn = functionService.findByAddress(program, targetAddr);
            if (targetFn == null) {
                continue;
            }

            visited.add(targetAddr);

            Map<String, Object> node = new LinkedHashMap<>();
            node.put("function", FunctionSummaryDto.from(targetFn));

            if (depth > 1) {
                List<Map<String, Object>> children = buildCallTree(program, targetFn, depth - 1, callers, visited);
                if (!children.isEmpty()) {
                    node.put(callers ? "callers" : "callees", children);
                }
            }

            result.add(node);
        }

        return result;
    }
}
