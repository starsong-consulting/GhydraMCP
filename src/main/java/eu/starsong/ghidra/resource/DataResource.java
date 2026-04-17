package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.DataService;
import eu.starsong.ghidra.service.DataService.DataFilter;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.function.Function;

/**
 * REST resource for /data endpoints.
 */
public class DataResource implements Resource {

    private final DataService dataService;

    public DataResource() {
        this.dataService = new DataService();
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/data", ctx -> list(contextFactory.apply(ctx)));
        app.get("/strings", ctx -> listStrings(contextFactory.apply(ctx)));
        app.get("/data/{address}", ctx -> getByAddress(contextFactory.apply(ctx)));
        app.put("/data/{address}", ctx -> setDataType(contextFactory.apply(ctx)));
        app.delete("/data/{address}", ctx -> clearData(contextFactory.apply(ctx)));
    }

    /**
     * GET /data - List defined data
     */
    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        DataFilter filter = DataFilter.fromQueryParams(
            ctx.queryParam("label"),
            ctx.queryParam("label_contains"),
            ctx.queryParam("type")
        );

        List<DataDto> data = dataService.list(program, filter);

        var result = Paginator.paginate(data, pagination, "/data")
            .withItemLinks(d -> Links.builder()
                .self("/data/{}", d.address())
                .link("memory", "/memory/{}", d.address())
                .build());

        ctx.json(result.toResponse()
            .link("program", "/program")
            .link("strings", "/strings")
            .build());
    }

    /**
     * GET /strings - List string data
     */
    private void listStrings(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        List<DataDto> strings = dataService.listStrings(program);

        var result = Paginator.paginate(strings, pagination, "/strings")
            .withItemLinks(d -> Links.builder()
                .self("/data/{}", d.address())
                .build());

        ctx.json(result.toResponse()
            .link("data", "/data")
            .link("program", "/program")
            .build());
    }

    /**
     * GET /data/{address} - Get data at address
     */
    private void getByAddress(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        DataDto data = dataService.requireByAddress(program, address);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/data/{}", address)
            .link("data", "/data")
            .link("memory", "/memory/{}", address)
            .link("xrefs_to", "/xrefs?to_addr={}", address)
            .build());
    }

    /**
     * PUT /data/{address} - Set data type at address
     */
    private void setDataType(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        SetTypeRequest request = ctx.bodyAsClass(SetTypeRequest.class);
        if (request.type == null || request.type.isEmpty()) {
            throw new IllegalArgumentException("type field is required");
        }

        try {
            DataDto data = dataService.setDataType(program, address, request.type);

            ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
                .self("/data/{}", address)
                .link("data", "/data")
                .build());

        } catch (Exception e) {
            throw new RuntimeException("Failed to set data type: " + e.getMessage(), e);
        }
    }

    /**
     * DELETE /data/{address} - Clear data at address
     */
    private void clearData(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");

        try {
            dataService.clearData(program, address);
            ctx.status(204);

        } catch (Exception e) {
            throw new RuntimeException("Failed to clear data: " + e.getMessage(), e);
        }
    }

    private static class SetTypeRequest {
        public String type;
    }
}
