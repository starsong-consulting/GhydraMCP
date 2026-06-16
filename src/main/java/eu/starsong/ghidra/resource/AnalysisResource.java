package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.AnalysisService;
import eu.starsong.ghidra.util.DataFlowUtil;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.*;

/**
 * REST resource for /analysis endpoints.
 * Provides advanced analysis features like call graphs.
 */
public class AnalysisResource implements Resource {

    private final AnalysisService analysisService;

    public AnalysisResource() {
        this.analysisService = new AnalysisService();
    }

    public AnalysisResource(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

    @Override
    public void register(Javalin app, java.util.function.Function<Context, GhidraContext> contextFactory) {
        app.get("/analysis/callgraph", ctx -> callGraph(contextFactory.apply(ctx)));
        app.get("/analysis/callers/{address}", ctx -> callers(contextFactory.apply(ctx)));
        app.get("/analysis/callees/{address}", ctx -> callees(contextFactory.apply(ctx)));
        app.get("/analysis/status", ctx -> status(contextFactory.apply(ctx)));
        app.post("/analysis/run", ctx -> run(contextFactory.apply(ctx)));
        app.get("/analysis/dataflow", ctx -> dataflow(contextFactory.apply(ctx)));
    }

    private void status(GhidraContext ctx) {
        var program = ctx.requireProgram();
        AutoAnalysisManager am = AutoAnalysisManager.getAnalysisManager(program);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("programName", program.getName());
        result.put("isAnalyzing", am.isAnalyzing());
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/analysis/status")
            .link("run", "/analysis/run", "POST")
            .link("program", "/program")
            .build());
    }

    private void run(GhidraContext ctx) {
        var program = ctx.requireProgram();
        AutoAnalysisManager am = AutoAnalysisManager.getAnalysisManager(program);
        if (am.isAnalyzing()) {
            ctx.status(409);
            ctx.json(Response.error(ctx.ctx(), ctx.port(), "ANALYSIS_RUNNING", "Analysis is already running").build());
            return;
        }
        RunRequest req;
        try { req = ctx.bodyAsClass(RunRequest.class); } catch (Exception e) { req = new RunRequest(); }
        boolean background = req.background == null ? true : req.background;
        am.reAnalyzeAll(null);
        am.startAnalysis(TaskMonitor.DUMMY, background);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of(
                "started", true,
                "background", background,
                "message", "Analysis started on program: " + program.getName()))
            .self("/analysis/run")
            .link("status", "/analysis/status")
            .build());
    }

    private void dataflow(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String addressStr = ctx.queryParam("address");
        if (addressStr == null || addressStr.isEmpty()) {
            throw new IllegalArgumentException("address query parameter is required");
        }
        String direction = ctx.queryParam("direction", "forward");
        if (!"forward".equals(direction) && !"backward".equals(direction)) {
            throw new IllegalArgumentException("direction must be 'forward' or 'backward'");
        }
        int maxSteps = ctx.queryParamAsInt("max_steps", 50);
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        Map<String, Object> result = DataFlowUtil.analyzeReferenceFlow(program, address, direction, maxSteps);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/analysis/dataflow?address={}&direction={}&max_steps={}", addressStr, direction, maxSteps)
            .link("program", "/program")
            .build());
    }

    private static class RunRequest {
        public Boolean background;
    }

    /**
     * GET /analysis/callgraph - Get call graph for a function
     */
    private void callGraph(GhidraContext ctx) {
        var program = ctx.requireProgram();

        String address = ctx.queryParam("address");
        String name = ctx.queryParam("name");
        // `depth` is canonical; `max_depth` accepted for bridge/CLI compatibility.
        int depth = ctx.queryParamAsInt("depth", ctx.queryParamAsInt("max_depth", 2));
        String direction = ctx.queryParam("direction", "both");

        if ((address == null || address.isEmpty()) && (name == null || name.isEmpty())) {
            throw new IllegalArgumentException("Either address or name query parameter is required");
        }

        final boolean byAddress = address != null && !address.isEmpty();
        final String lookup = byAddress ? address : name;

        AnalysisService.CallGraphResult cg = analysisService.callGraph(program, byAddress, lookup, depth, direction);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), cg.data())
            .self("/analysis/callgraph?address={}", cg.entryPoint())
            .link("function", "/functions/{}", cg.entryPoint())
            .link("callers", "/analysis/callers/{}", cg.entryPoint())
            .link("callees", "/analysis/callees/{}", cg.entryPoint())
            .build());
    }

    /**
     * GET /analysis/callers/{address} - Get functions that call this function
     */
    private void callers(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        List<FunctionSummaryDto> callers = analysisService.callers(program, address);

        var result = Paginator.paginate(callers, ctx.pagination(), "/analysis/callers/" + address)
            .withItemLinks(f -> Links.builder()
                .self("/functions/{}", f.address())
                .link("callers", "/analysis/callers/{}", f.address())
                .link("callees", "/analysis/callees/{}", f.address())
                .build());

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
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

        List<FunctionSummaryDto> callees = analysisService.callees(program, address);

        var result = Paginator.paginate(callees, ctx.pagination(), "/analysis/callees/" + address)
            .withItemLinks(f -> Links.builder()
                .self("/functions/{}", f.address())
                .link("callers", "/analysis/callers/{}", f.address())
                .link("callees", "/analysis/callees/{}", f.address())
                .build());

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("function", "/functions/{}", address)
            .link("callgraph", "/analysis/callgraph?address={}", address)
            .build());
    }
}
