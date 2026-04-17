package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.ClassDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.NamespaceService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.function.Function;

public class ClassResource implements Resource {

    private final NamespaceService service;

    public ClassResource() {
        this.service = new NamespaceService();
    }

    public ClassResource(NamespaceService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/classes", ctx -> list(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();
        List<ClassDto> classes = service.listClasses(program);

        var result = Paginator.paginate(classes, pagination, "/classes")
            .withItemLinks(c -> Links.builder()
                .self("/classes/{}", c.name())
                .build());

        ctx.json(result.toResponse()
            .link("program", "/program")
            .build());
    }
}
