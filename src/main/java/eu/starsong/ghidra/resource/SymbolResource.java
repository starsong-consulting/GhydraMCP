package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.SymbolDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.SymbolService;
import eu.starsong.ghidra.service.SymbolService.SymbolFilter;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.function.Function;

/**
 * REST resource for /symbols endpoints.
 */
public class SymbolResource implements Resource {

    private final SymbolService symbolService;

    public SymbolResource() {
        this.symbolService = new SymbolService();
    }

    public SymbolResource(SymbolService symbolService) {
        this.symbolService = symbolService;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/symbols", ctx -> list(contextFactory.apply(ctx)));
        app.get("/symbols/imports", ctx -> listImports(contextFactory.apply(ctx)));
        app.get("/symbols/exports", ctx -> listExports(contextFactory.apply(ctx)));
        app.get("/symbols/{address}", ctx -> getByAddress(contextFactory.apply(ctx)));
        app.patch("/symbols/{address}", ctx -> update(contextFactory.apply(ctx)));
        app.delete("/symbols/{address}", ctx -> delete(contextFactory.apply(ctx)));
        app.post("/symbols", ctx -> create(contextFactory.apply(ctx)));
    }

    /**
     * GET /symbols - List all symbols with pagination
     */
    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        SymbolFilter filter = SymbolFilter.fromQueryParams(
            ctx.queryParam("name"),
            ctx.queryParam("name_contains"),
            ctx.queryParam("name_matches_regex"),
            ctx.queryParam("type"),
            ctx.queryParam("is_external"),
            ctx.queryParam("is_global")
        );

        List<SymbolDto> symbols = symbolService.list(program, filter);

        var result = Paginator.paginate(symbols, pagination, "/symbols")
            .withItemLinks(sym -> Links.builder()
                .self("/symbols/{}", sym.address())
                .build());

        ctx.json(result.toResponse()
            .link("program", "/program")
            .link("imports", "/symbols/imports")
            .link("exports", "/symbols/exports")
            .link("create", "/symbols", "POST")
            .build());
    }

    /**
     * GET /symbols/imports - List imported symbols
     */
    private void listImports(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        List<SymbolDto> symbols = symbolService.listImports(program);

        var result = Paginator.paginate(symbols, pagination, "/symbols/imports")
            .withItemLinks(sym -> Links.builder()
                .self("/symbols/{}", sym.address())
                .build());

        ctx.json(result.toResponse()
            .link("symbols", "/symbols")
            .link("exports", "/symbols/exports")
            .build());
    }

    /**
     * GET /symbols/exports - List exported symbols
     */
    private void listExports(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        List<SymbolDto> symbols = symbolService.listExports(program);

        var result = Paginator.paginate(symbols, pagination, "/symbols/exports")
            .withItemLinks(sym -> Links.builder()
                .self("/symbols/{}", sym.address())
                .build());

        ctx.json(result.toResponse()
            .link("symbols", "/symbols")
            .link("imports", "/symbols/imports")
            .build());
    }

    /**
     * GET /symbols/{address} - Get symbol by address
     */
    private void getByAddress(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        SymbolDto symbol = symbolService.getByAddress(program, address)
            .orElseThrow(() -> new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "Symbol not found at address: " + address, "SYMBOL_NOT_FOUND"));

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), symbol)
            .self("/symbols/{}", address)
            .link("program", "/program")
            .link("symbols", "/symbols")
            .build());
    }

    /**
     * PATCH /symbols/{address} - Rename symbol
     */
    private void update(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        UpdateRequest request = ctx.bodyAsClass(UpdateRequest.class);

        try {
            SymbolDto symbol = symbolService.rename(program, address, request.name);

            ctx.json(Response.ok(ctx.ctx(), ctx.port(), symbol)
                .self("/symbols/{}", address)
                .link("symbols", "/symbols")
                .build());

        } catch (Exception e) {
            throw new RuntimeException("Failed to update symbol: " + e.getMessage(), e);
        }
    }

    /**
     * DELETE /symbols/{address} - Delete symbol
     */
    private void delete(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        try {
            symbolService.delete(program, address);
            ctx.status(204);

        } catch (Exception e) {
            throw new RuntimeException("Failed to delete symbol: " + e.getMessage(), e);
        }
    }

    /**
     * POST /symbols - Create a label
     */
    private void create(GhidraContext ctx) {
        var program = ctx.requireProgram();

        CreateRequest request = ctx.bodyAsClass(CreateRequest.class);

        if (request.address == null || request.address.isEmpty()) {
            throw new IllegalArgumentException("Address is required");
        }
        if (request.name == null || request.name.isEmpty()) {
            throw new IllegalArgumentException("Name is required");
        }

        try {
            SymbolDto symbol = symbolService.createLabel(program, request.address, request.name);

            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), symbol)
                .self("/symbols/{}", symbol.address())
                .link("symbols", "/symbols")
                .build());

        } catch (Exception e) {
            throw new RuntimeException("Failed to create symbol: " + e.getMessage(), e);
        }
    }

    private static class UpdateRequest {
        public String name;
    }

    private static class CreateRequest {
        public String address;
        public String name;
    }
}
