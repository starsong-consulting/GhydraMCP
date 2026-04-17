package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.ProjectDto;
import eu.starsong.ghidra.dto.ProjectFileDto;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.ProjectService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

public class ProjectResource implements Resource {

    private final ProjectService service;

    public ProjectResource() {
        this.service = new ProjectService();
    }

    public ProjectResource(ProjectService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/project", ctx -> current(contextFactory.apply(ctx)));
        app.get("/project/files", ctx -> files(contextFactory.apply(ctx)));
        app.post("/project/open", ctx -> openFile(contextFactory.apply(ctx)));
        app.get("/projects", ctx -> listAll(contextFactory.apply(ctx)));
        app.get("/projects/{name}", ctx -> getByName(contextFactory.apply(ctx)));
    }

    private void listAll(GhidraContext ctx) {
        List<ProjectDto> projects = service.listAll(ctx.tool());
        ctx.json(eu.starsong.ghidra.hateoas.Response.ok(ctx.ctx(), ctx.port(), projects)
            .self("/projects")
            .link("project", "/project")
            .build());
    }

    private void getByName(GhidraContext ctx) {
        String name = ctx.pathParam("name");
        ProjectDto project = service.getByName(ctx.tool(), name);
        ctx.json(eu.starsong.ghidra.hateoas.Response.ok(ctx.ctx(), ctx.port(), project)
            .self("/projects/{}", name)
            .link("projects", "/projects")
            .link("project", "/project")
            .build());
    }

    private void current(GhidraContext ctx) {
        ProjectDto project = service.getCurrent(ctx.tool());
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), project)
            .self("/project")
            .link("files", "/project/files")
            .link("programs", "/programs")
            .build());
    }

    private void files(GhidraContext ctx) {
        var pagination = ctx.pagination();
        String folder = ctx.queryParam("folder", "/");
        boolean recursive = Boolean.parseBoolean(ctx.queryParam("recursive", "true"));

        List<ProjectFileDto> items = service.listFiles(ctx.tool(), folder, recursive);

        String basePath = "/project/files?folder=" + folder + "&recursive=" + recursive;
        var result = Paginator.paginate(items, pagination, basePath);
        ctx.json(result.toResponse()
            .meta("project", ctx.tool().getProject().getName())
            .meta("folder", folder)
            .meta("recursive", recursive)
            .link("project", "/project")
            .build());
    }

    private void openFile(GhidraContext ctx) {
        OpenRequest req = ctx.bodyAsClass(OpenRequest.class);
        if (req.path == null || req.path.isEmpty()) {
            throw new IllegalArgumentException("path is required");
        }
        ProjectService.OpenResult result = service.openFile(ctx.tool(), req.path);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of(
                "path", result.path(),
                "name", result.name(),
                "opened", result.opened(),
                "message", "File opened in CodeBrowser. Use instances_discover to find the new instance."))
            .self("/project/open")
            .link("files", "/project/files")
            .link("instances", "/instances")
            .build());
    }

    private static class OpenRequest {
        public String path;
    }
}
