package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.DataTypeSummaryDto;
import eu.starsong.ghidra.dto.EnumDto;
import eu.starsong.ghidra.dto.StructDto;
import eu.starsong.ghidra.dto.UnionDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.DataTypeService;
import eu.starsong.ghidra.service.DataTypeService.FieldSpec;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class DataTypeResource implements Resource {

    private final DataTypeService service;

    public DataTypeResource() {
        this.service = new DataTypeService();
    }

    public DataTypeResource(DataTypeService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/datatypes", ctx -> list(contextFactory.apply(ctx)));
        app.post("/datatypes/struct", ctx -> createStruct(contextFactory.apply(ctx)));
        app.post("/datatypes/enum", ctx -> createEnum(contextFactory.apply(ctx)));
        app.post("/datatypes/union", ctx -> createUnion(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();
        String category = ctx.queryParam("category");
        String kind = ctx.queryParam("kind");
        String name = ctx.queryParam("name");

        List<DataTypeSummaryDto> dataTypes = service.list(program, category, kind, name);

        var result = Paginator.paginate(dataTypes, pagination, "/datatypes")
            .withItemLinks(dt -> Links.builder()
                .self("/datatypes?name={}", dt.name())
                .build());

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("create_struct", "/datatypes/struct", "POST")
            .link("create_enum", "/datatypes/enum", "POST")
            .link("create_union", "/datatypes/union", "POST")
            .build());
    }

    private void createStruct(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CreateStructRequest req = ctx.bodyAsClass(CreateStructRequest.class);
        try {
            StructDto struct = service.createStruct(program, req.name, req.category, req.fields);
            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
                .self("/datatypes/struct")
                .link("structs", "/structs")
                .link("datatypes", "/datatypes")
                .link("struct", "/structs/{}", struct.name())
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create struct: " + e.getMessage(), e);
        }
    }

    private void createEnum(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CreateEnumRequest req = ctx.bodyAsClass(CreateEnumRequest.class);
        int size = req.size != null ? req.size : 4;
        try {
            EnumDto enumDto = service.createEnum(program, req.name, size, req.category, req.values);
            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), enumDto)
                .self("/datatypes/enum")
                .link("datatypes", "/datatypes")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create enum: " + e.getMessage(), e);
        }
    }

    private void createUnion(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CreateUnionRequest req = ctx.bodyAsClass(CreateUnionRequest.class);
        try {
            UnionDto union = service.createUnion(program, req.name, req.category, req.fields);
            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), union)
                .self("/datatypes/union")
                .link("datatypes", "/datatypes")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create union: " + e.getMessage(), e);
        }
    }

    private static class CreateStructRequest {
        public String name;
        public String category;
        public List<FieldSpec> fields;
    }

    private static class CreateEnumRequest {
        public String name;
        public Integer size;
        public String category;
        public Map<String, Long> values;
    }

    private static class CreateUnionRequest {
        public String name;
        public String category;
        public List<FieldSpec> fields;
    }
}
