package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.DecompileResultDto;
import eu.starsong.ghidra.dto.FunctionDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.middleware.GhidraContextHandler;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.DecompilerService;
import eu.starsong.ghidra.service.FunctionService;
import eu.starsong.ghidra.service.FunctionService.FunctionFilter;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * REST resource for /functions endpoints.
 */
public class FunctionResource implements Resource {

    private final FunctionService functionService;
    private final DecompilerService decompilerService;

    public FunctionResource() {
        this.functionService = new FunctionService();
        this.decompilerService = new DecompilerService(functionService);
    }

    public FunctionResource(FunctionService functionService, DecompilerService decompilerService) {
        this.functionService = functionService;
        this.decompilerService = decompilerService;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/functions", ctx -> list(contextFactory.apply(ctx)));
        app.get("/functions/{address}", ctx -> getByAddress(contextFactory.apply(ctx)));
        app.get("/functions/{address}/decompile", ctx -> decompile(contextFactory.apply(ctx)));
        app.patch("/functions/{address}", ctx -> update(contextFactory.apply(ctx)));
        app.delete("/functions/{address}", ctx -> delete(contextFactory.apply(ctx)));
        app.post("/functions", ctx -> create(contextFactory.apply(ctx)));
    }

    /**
     * GET /functions - List all functions with pagination
     */
    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        FunctionFilter filter = FunctionFilter.fromQueryParams(
            ctx.queryParam("name"),
            ctx.queryParam("name_contains"),
            ctx.queryParam("name_matches_regex"),
            ctx.queryParam("is_external"),
            ctx.queryParam("is_thunk")
        );

        List<FunctionSummaryDto> functions = functionService.list(program, filter);

        var result = Paginator.paginate(functions, pagination, "/functions")
            .withItemLinks(fn -> Links.builder()
                .self("/functions/{}", fn.address())
                .link("decompile", "/functions/{}/decompile", fn.address())
                .build());

        ctx.json(result.toResponse()
            .link("program", "/program")
            .link("create", "/functions", "POST")
            .build());
    }

    /**
     * GET /functions/{address} - Get function by address
     */
    private void getByAddress(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        FunctionDto fn = functionService.requireByAddress(program, address);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), fn)
            .self("/functions/{}", address)
            .link("program", "/program")
            .link("decompile", "/functions/{}/decompile", address)
            .link("xrefs_to", "/xrefs?to_addr={}", address)
            .link("xrefs_from", "/xrefs?from_addr={}", address)
            .link("update", "/functions/{}", address)
            .link("delete", "/functions/{}", address)
            .build());
    }

    /**
     * GET /functions/{address}/decompile - Decompile function
     */
    private void decompile(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        int timeout = ctx.queryParamAsInt("timeout", 60);

        DecompileResultDto result = decompilerService.decompile(program, address, timeout);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/functions/{}/decompile", address)
            .link("function", "/functions/{}", address)
            .build());
    }

    /**
     * PATCH /functions/{address} - Update function (rename, set comment, etc.)
     */
    private void update(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        UpdateRequest request = ctx.bodyAsClass(UpdateRequest.class);

        try {
            FunctionDto fn;
            if (request.name != null && !request.name.isEmpty()) {
                fn = functionService.rename(program, address, request.name);
            } else if (request.comment != null) {
                fn = functionService.setComment(program, address, request.comment);
            } else {
                fn = functionService.requireByAddress(program, address);
            }

            ctx.json(Response.ok(ctx.ctx(), ctx.port(), fn)
                .self("/functions/{}", address)
                .link("program", "/program")
                .link("decompile", "/functions/{}/decompile", address)
                .build());

        } catch (Exception e) {
            throw new RuntimeException("Failed to update function: " + e.getMessage(), e);
        }
    }

    /**
     * DELETE /functions/{address} - Delete function
     */
    private void delete(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        try {
            functionService.delete(program, address);

            ctx.status(204);

        } catch (Exception e) {
            throw new RuntimeException("Failed to delete function: " + e.getMessage(), e);
        }
    }

    /**
     * POST /functions - Create function
     */
    private void create(GhidraContext ctx) {
        var program = ctx.requireProgram();

        CreateRequest request = ctx.bodyAsClass(CreateRequest.class);

        if (request.address == null || request.address.isEmpty()) {
            throw new IllegalArgumentException("Address is required");
        }

        try {
            FunctionDto fn = functionService.create(
                program,
                request.address,
                request.name != null ? request.name : "FUN_" + request.address
            );

            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), fn)
                .self("/functions/{}", fn.address())
                .link("program", "/program")
                .link("decompile", "/functions/{}/decompile", fn.address())
                .build());

        } catch (Exception e) {
            throw new RuntimeException("Failed to create function: " + e.getMessage(), e);
        }
    }

    // Request DTOs
    private static class UpdateRequest {
        public String name;
        public String comment;
        public String signature;
    }

    private static class CreateRequest {
        public String address;
        public String name;
    }
}
