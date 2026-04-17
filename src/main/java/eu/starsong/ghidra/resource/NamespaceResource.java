package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.NamespaceService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.function.Function;

public class NamespaceResource implements Resource {

    private final NamespaceService service;

    public NamespaceResource() {
        this.service = new NamespaceService();
    }

    public NamespaceResource(NamespaceService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/namespaces", ctx -> list(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();
        List<String> namespaces = service.listNamespaces(program);

        var result = Paginator.paginate(namespaces, pagination, "/namespaces");

        ctx.json(result.toResponse()
            .link("program", "/program")
            .build());
    }
}
