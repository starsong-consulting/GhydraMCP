package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.StructDto;
import eu.starsong.ghidra.dto.StructSummaryDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.StructService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.function.Function;

public class StructResource implements Resource {

    private final StructService service;

    public StructResource() {
        this.service = new StructService();
    }

    public StructResource(StructService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/structs", ctx -> list(contextFactory.apply(ctx)));
        app.post("/structs", ctx -> create(contextFactory.apply(ctx)));
        app.get("/structs/{name}", ctx -> getByName(contextFactory.apply(ctx)));
        app.delete("/structs/{name}", ctx -> delete(contextFactory.apply(ctx)));
        app.post("/structs/{name}/fields", ctx -> addField(contextFactory.apply(ctx)));
        app.patch("/structs/{name}/fields/{fieldId}", ctx -> updateField(contextFactory.apply(ctx)));

        // Legacy POST routes (bridge compatibility)
        app.post("/structs/create", ctx -> create(contextFactory.apply(ctx)));
        app.post("/structs/delete", ctx -> deleteLegacy(contextFactory.apply(ctx)));
        app.post("/structs/addfield", ctx -> addFieldLegacy(contextFactory.apply(ctx)));
        app.post("/structs/updatefield", ctx -> updateFieldLegacy(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();
        String nameQuery = ctx.queryParam("name");

        // If name query param present, return single struct (legacy behavior)
        if (nameQuery != null && !nameQuery.isEmpty()) {
            StructDto fullStruct = service.requireByName(program, nameQuery);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), fullStruct)
                .self("/structs/{}", fullStruct.name())
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
            return;
        }

        String categoryFilter = ctx.queryParam("category");
        List<StructSummaryDto> structs = service.list(program, categoryFilter);

        var result = Paginator.paginate(structs, pagination, "/structs")
            .withItemLinks(s -> Links.builder()
                .self("/structs/{}", s.name())
                .link("delete", "/structs/{}", "DELETE", s.name())
                .link("fields", "/structs/{}/fields", s.name())
                .build());

        ctx.json(result.toResponse()
            .link("program", "/program")
            .link("create", "/structs", "POST")
            .build());
    }

    private void getByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        StructDto struct = service.requireByName(program, name);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
            .self("/structs/{}", name)
            .link("structs", "/structs")
            .link("delete", "/structs/{}", "DELETE", name)
            .link("add_field", "/structs/{}/fields", "POST", name)
            .link("program", "/program")
            .build());
    }

    private void create(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CreateRequest req = ctx.bodyAsClass(CreateRequest.class);

        try {
            StructDto struct = service.create(program, req.name, req.category, req.size, req.description);
            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
                .self("/structs/{}", struct.name())
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create struct: " + e.getMessage(), e);
        }
    }

    private void delete(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        try {
            service.delete(program, name);
            ctx.status(204);
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete struct: " + e.getMessage(), e);
        }
    }

    private void deleteLegacy(GhidraContext ctx) {
        var program = ctx.requireProgram();
        DeleteRequest req = ctx.bodyAsClass(DeleteRequest.class);
        if (req.name == null || req.name.isEmpty()) {
            throw new IllegalArgumentException("name is required");
        }
        try {
            service.delete(program, req.name);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), java.util.Map.of("name", req.name))
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete struct: " + e.getMessage(), e);
        }
    }

    private void addField(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String structName = ctx.pathParam("name");
        AddFieldRequest req = ctx.bodyAsClass(AddFieldRequest.class);
        String fieldName = req.name != null ? req.name : req.fieldName;
        String fieldType = req.type != null ? req.type : req.fieldType;

        try {
            StructDto struct = service.addField(program, structName, fieldName, fieldType, req.offset, req.comment);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
                .self("/structs/{}", structName)
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to add field: " + e.getMessage(), e);
        }
    }

    private void addFieldLegacy(GhidraContext ctx) {
        var program = ctx.requireProgram();
        AddFieldRequest req = ctx.bodyAsClass(AddFieldRequest.class);
        String structName = req.struct;
        String fieldName = req.fieldName != null ? req.fieldName : req.name;
        String fieldType = req.fieldType != null ? req.fieldType : req.type;
        try {
            StructDto struct = service.addField(program, structName, fieldName, fieldType, req.offset, req.comment);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
                .self("/structs/{}", structName)
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to add field: " + e.getMessage(), e);
        }
    }

    private void updateField(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String structName = ctx.pathParam("name");
        String fieldId = ctx.pathParam("fieldId");
        UpdateFieldRequest req = ctx.bodyAsClass(UpdateFieldRequest.class);

        Integer fieldOffset = null;
        String fieldName = null;
        try {
            fieldOffset = Integer.decode(fieldId);
        } catch (NumberFormatException e) {
            fieldName = fieldId;
        }

        String newName = req.newName != null ? req.newName : req.name;
        String newType = req.newType != null ? req.newType : req.type;
        String newComment = req.newComment != null ? req.newComment : req.comment;

        try {
            StructDto struct = service.updateField(program, structName, fieldOffset, fieldName,
                newName, newType, newComment);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
                .self("/structs/{}", structName)
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to update field: " + e.getMessage(), e);
        }
    }

    private void updateFieldLegacy(GhidraContext ctx) {
        var program = ctx.requireProgram();
        UpdateFieldRequest req = ctx.bodyAsClass(UpdateFieldRequest.class);
        String structName = req.struct;

        Integer fieldOffset = null;
        if (req.fieldOffset != null && !req.fieldOffset.isEmpty()) {
            try {
                fieldOffset = Integer.decode(req.fieldOffset);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("fieldOffset must be an integer");
            }
        }
        String fieldName = req.fieldName;
        String newName = req.newName != null ? req.newName : req.name;
        String newType = req.newType != null ? req.newType : req.type;
        String newComment = req.newComment != null ? req.newComment : req.comment;

        try {
            StructDto struct = service.updateField(program, structName, fieldOffset, fieldName,
                newName, newType, newComment);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), struct)
                .self("/structs/{}", structName)
                .link("structs", "/structs")
                .link("program", "/program")
                .build());
        } catch (Exception e) {
            throw new RuntimeException("Failed to update field: " + e.getMessage(), e);
        }
    }

    // Request DTOs
    private static class CreateRequest {
        public String name;
        public String category;
        public Integer size;
        public String description;
    }

    private static class DeleteRequest {
        public String name;
    }

    private static class AddFieldRequest {
        public String struct;    // legacy
        public String name;      // RESTful field name
        public String fieldName; // legacy field name
        public String type;      // RESTful field type
        public String fieldType; // legacy field type
        public Integer offset;
        public String comment;
    }

    private static class UpdateFieldRequest {
        public String struct;       // legacy
        public String fieldOffset;  // legacy (string-encoded, int/hex)
        public String fieldName;    // legacy
        public String name;         // RESTful new name
        public String newName;      // legacy new name
        public String type;         // RESTful new type
        public String newType;      // legacy new type
        public String comment;      // RESTful new comment
        public String newComment;   // legacy new comment
    }
}
