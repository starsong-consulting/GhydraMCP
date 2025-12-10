package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.DecompilerService;
import eu.starsong.ghidra.service.FunctionService;
import eu.starsong.ghidra.service.XrefService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.*;

/**
 * REST resource for /analysis endpoints.
 * Provides advanced analysis features like call graphs.
 */
public class AnalysisResource implements Resource {

    private final FunctionService functionService;
    private final XrefService xrefService;
    private final DecompilerService decompilerService;

    public AnalysisResource() {
        this.functionService = new FunctionService();
        this.xrefService = new XrefService();
        this.decompilerService = new DecompilerService(functionService);
    }

    @Override
    public void register(Javalin app, java.util.function.Function<Context, GhidraContext> contextFactory) {
        app.get("/analysis/callgraph", ctx -> callGraph(contextFactory.apply(ctx)));
        app.get("/analysis/callers/{address}", ctx -> callers(contextFactory.apply(ctx)));
        app.get("/analysis/callees/{address}", ctx -> callees(contextFactory.apply(ctx)));
    }

    /**
     * GET /analysis/callgraph - Get call graph for a function
     */
    private void callGraph(GhidraContext ctx) {
        var program = ctx.requireProgram();

        String address = ctx.queryParam("address");
        String name = ctx.queryParam("name");
        int depth = ctx.queryParamAsInt("depth", 2);
        String direction = ctx.queryParam("direction", "both");

        if ((address == null || address.isEmpty()) && (name == null || name.isEmpty())) {
            throw new IllegalArgumentException("Either address or name query parameter is required");
        }

        Function startFn;
        if (address != null && !address.isEmpty()) {
            startFn = functionService.requireFunctionByAddress(program, address);
        } else {
            startFn = functionService.requireFunctionByName(program, name);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("root", FunctionSummaryDto.from(startFn));
        result.put("depth", depth);
        result.put("direction", direction);

        Set<String> visited = new HashSet<>();
        visited.add(startFn.getEntryPoint().toString());

        if ("callers".equals(direction) || "both".equals(direction)) {
            List<Map<String, Object>> callers = buildCallTree(program, startFn, depth, true, visited);
            result.put("callers", callers);
        }

        if ("callees".equals(direction) || "both".equals(direction)) {
            visited.clear();
            visited.add(startFn.getEntryPoint().toString());
            List<Map<String, Object>> callees = buildCallTree(program, startFn, depth, false, visited);
            result.put("callees", callees);
        }

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/analysis/callgraph?address={}", startFn.getEntryPoint())
            .link("function", "/functions/{}", startFn.getEntryPoint())
            .link("callers", "/analysis/callers/{}", startFn.getEntryPoint())
            .link("callees", "/analysis/callees/{}", startFn.getEntryPoint())
            .build());
    }

    /**
     * GET /analysis/callers/{address} - Get functions that call this function
     */
    private void callers(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        Function fn = functionService.requireFunctionByAddress(program, address);

        List<XrefDto> callXrefs = xrefService.getCallsTo(program, address);

        Set<String> seen = new HashSet<>();
        List<FunctionSummaryDto> callers = new ArrayList<>();

        for (XrefDto xref : callXrefs) {
            if (xref.fromFunctionAddress() != null && !seen.contains(xref.fromFunctionAddress())) {
                seen.add(xref.fromFunctionAddress());
                Function callerFn = functionService.findByAddress(program, xref.fromFunctionAddress());
                if (callerFn != null) {
                    callers.add(FunctionSummaryDto.from(callerFn));
                }
            }
        }

        var result = Paginator.paginate(callers, ctx.pagination(), "/analysis/callers/" + address)
            .withItemLinks(f -> Links.builder()
                .self("/functions/{}", f.address())
                .link("callers", "/analysis/callers/{}", f.address())
                .link("callees", "/analysis/callees/{}", f.address())
                .build());

        ctx.json(result.toResponse()
            .link("function", "/functions/{}", address)
            .link("callgraph", "/analysis/callgraph?address={}", address)
            .build());
    }

    /**
     * GET /analysis/callees/{address} - Get functions called by this function
     */
    private void callees(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        Function fn = functionService.requireFunctionByAddress(program, address);

        List<XrefDto> callXrefs = xrefService.getCallsFrom(program, address);

        Set<String> seen = new HashSet<>();
        List<FunctionSummaryDto> callees = new ArrayList<>();

        for (XrefDto xref : callXrefs) {
            if (xref.toFunctionAddress() != null && !seen.contains(xref.toFunctionAddress())) {
                seen.add(xref.toFunctionAddress());
                Function calleeFn = functionService.findByAddress(program, xref.toFunctionAddress());
                if (calleeFn != null) {
                    callees.add(FunctionSummaryDto.from(calleeFn));
                }
            }
        }

        var result = Paginator.paginate(callees, ctx.pagination(), "/analysis/callees/" + address)
            .withItemLinks(f -> Links.builder()
                .self("/functions/{}", f.address())
                .link("callers", "/analysis/callers/{}", f.address())
                .link("callees", "/analysis/callees/{}", f.address())
                .build());

        ctx.json(result.toResponse()
            .link("function", "/functions/{}", address)
            .link("callgraph", "/analysis/callgraph?address={}", address)
            .build());
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
