package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.VariableService;
import io.javalin.Javalin;
import io.javalin.http.Context;

public class VariableResource implements Resource {

    private final VariableService service;

    public VariableResource() {
        this.service = new VariableService();
    }

    public VariableResource(VariableService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, java.util.function.Function<Context, GhidraContext> contextFactory) {
        app.get("/variables", ctx -> list(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();
        String search = ctx.queryParam("search");
        boolean globalOnly = Boolean.parseBoolean(ctx.queryParam("global_only", "false"));

        VariableService.Page page = service.list(program, search, globalOnly, pagination.offset(), pagination.limit());

        String basePath = "/variables";
        StringBuilder qs = new StringBuilder();
        if (search != null && !search.isEmpty()) qs.append("search=").append(search);
        if (globalOnly) {
            if (qs.length() > 0) qs.append("&");
            qs.append("global_only=true");
        }
        String prefix = qs.length() > 0 ? basePath + "?" + qs + "&" : basePath + "?";

        Response response = Response.ok(ctx.ctx(), ctx.port(), page.results())
            .meta("offset", pagination.offset())
            .meta("limit", pagination.limit())
            .meta("total_estimate", page.totalEstimate())
            .self(prefix + "offset=" + pagination.offset() + "&limit=" + pagination.limit())
            .link("program", "/program");

        if (page.hasMore()) {
            response.link("next", prefix + "offset=" + (pagination.offset() + pagination.limit())
                + "&limit=" + pagination.limit());
        }
        if (pagination.offset() > 0) {
            int prevOffset = Math.max(0, pagination.offset() - pagination.limit());
            response.link("prev", prefix + "offset=" + prevOffset + "&limit=" + pagination.limit());
        }

        ctx.json(response.build());
    }
}
