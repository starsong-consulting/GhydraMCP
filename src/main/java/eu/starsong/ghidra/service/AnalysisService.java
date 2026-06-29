package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.CallPathDto;
import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.server.GhydraServer.BadRequestException;
import eu.starsong.ghidra.service.graph.CallGraph;
import eu.starsong.ghidra.service.graph.CallPathFinder;
import eu.starsong.ghidra.service.graph.GhidraCallGraph;
import eu.starsong.ghidra.service.graph.StringUsageWalker;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.Page;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
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
     *
     * <p>{@code unresolved_edges} counts call edges the walk could not traverse — targets
     * outside a defined function (thunks/PLT stubs, indirect/computed calls) or non-entry-point
     * targets. A non-zero value means the search was lossy: an empty {@code paths} with
     * {@code unresolved_edges > 0} does not prove {@code from} cannot reach {@code to}. Cycle
     * skips (revisiting a node already on the current path) are expected and are NOT counted.
     */
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
     *
     * <p>{@code unresolved_refs} counts references (direct or caller) whose source address
     * is not inside a defined function (data-region references, undisassembled code, jump
     * tables) and so could not be attributed to a function. A non-zero value means
     * {@code directUsers}/{@code callers} under-report who touches the string.
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
            StringUsageWalker.WalkState state = new StringUsageWalker.WalkState(maxFunctions);
            List<StringUsageDto> matches = new ArrayList<>();
            for (StringUsageDto.StringRef ref : page) {
                matches.add(walker.resolve(ref, callerDepth, state));
            }

            Map<String, Object> data = new LinkedHashMap<>();
            data.put("value", value);
            data.put("match", match);
            data.put("caller_depth", callerDepth);
            data.put("size", total);
            data.put("offset", offset);
            data.put("limit", limit);
            data.put("truncated", truncated[0] || state.truncated());
            data.put("unresolved_refs", state.unresolvedRefs());
            data.put("matches", matches);
            return data;
        });
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
