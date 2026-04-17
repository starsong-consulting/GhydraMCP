package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * REST resource for /instances endpoints.
 * Manages multi-instance coordination.
 */
public class InstanceResource implements Resource {

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/instances", ctx -> list(contextFactory.apply(ctx)));
        app.get("/instances/{port}", ctx -> getByPort(contextFactory.apply(ctx)));
    }

    /**
     * GET /instances - List all active instances
     */
    private void list(GhidraContext ctx) {
        Map<Integer, ?> instances = ctx.activeInstances();

        List<Map<String, Object>> instanceList = new ArrayList<>();
        for (Integer port : instances.keySet()) {
            Map<String, Object> instance = new LinkedHashMap<>();
            instance.put("port", port);
            instance.put("url", "http://localhost:" + port);
            instance.put("isCurrent", port == ctx.port());

            Map<String, Object> links = new LinkedHashMap<>();
            links.put("self", Links.href("/instances/{}", port));
            links.put("connect", Links.href("http://localhost:{}", port));
            links.put("info", Links.href("http://localhost:{}/info", port));
            instance.put("_links", links);

            instanceList.add(instance);
        }

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), instanceList)
            .self("/instances")
            .link("root", "/")
            .meta("count", instanceList.size())
            .meta("currentPort", ctx.port())
            .build());
    }

    /**
     * GET /instances/{port} - Get info about a specific instance
     */
    private void getByPort(GhidraContext ctx) {
        int port = Integer.parseInt(ctx.pathParam("port"));
        Map<Integer, ?> instances = ctx.activeInstances();

        if (!instances.containsKey(port)) {
            throw new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "Instance not found on port: " + port, "INSTANCE_NOT_FOUND");
        }

        Map<String, Object> instance = new LinkedHashMap<>();
        instance.put("port", port);
        instance.put("url", "http://localhost:" + port);
        instance.put("isCurrent", port == ctx.port());
        instance.put("active", true);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), instance)
            .self("/instances/{}", port)
            .link("instances", "/instances")
            .link("connect", "http://localhost:" + port)
            .link("info", "http://localhost:" + port + "/info")
            .build());
    }
}
