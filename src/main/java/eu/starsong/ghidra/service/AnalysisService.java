package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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

    public AnalysisService() {
        this.functionService = new FunctionService();
        this.xrefService = new XrefService();
    }

    public AnalysisService(FunctionService functionService, XrefService xrefService) {
        this.functionService = functionService;
        this.xrefService = xrefService;
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
            functionService.requireFunctionByAddress(program, address);

            List<XrefDto> callXrefs = xrefService.getCallsFrom(program, address);

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

    private List<Map<String, Object>> buildCallTree(Program program, Function fn, int depth, boolean callers, Set<String> visited) {
        if (depth <= 0) {
            return Collections.emptyList();
        }

        List<Map<String, Object>> result = new ArrayList<>();
        String addr = fn.getEntryPoint().toString();

        List<XrefDto> xrefs = callers
            ? xrefService.getCallsTo(program, addr)
            : xrefService.getCallsFrom(program, addr);

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
