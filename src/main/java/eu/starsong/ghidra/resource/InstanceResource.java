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
        app.post("/registerInstance", ctx -> registerInstance(contextFactory.apply(ctx)));
        app.post("/unregisterInstance", ctx -> unregisterInstance(contextFactory.apply(ctx)));
    }

    private void registerInstance(GhidraContext ctx) {
        PortRequest req = ctx.bodyAsClass(PortRequest.class);
        if (req.port == null || req.port <= 0) {
            throw new IllegalArgumentException("Invalid or missing port number");
        }
        // Matches main's behaviour: acknowledge the request. Actual registration
        // happens when the plugin on that port starts and inserts itself into
        // the activeInstances map.
        ctx.json(Response.ok(ctx.ctx(), ctx.port(),
                Map.of("message", "Instance registration acknowledged for port " + req.port))
            .self("/registerInstance")
            .link("instances", "/instances")
            .build());
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void unregisterInstance(GhidraContext ctx) {
        PortRequest req = ctx.bodyAsClass(PortRequest.class);
        if (req.port == null || req.port <= 0) {
            throw new IllegalArgumentException("Invalid or missing port number");
        }
        Map instances = (Map) ctx.activeInstances();
        if (!instances.containsKey(req.port)) {
            throw new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "No instance found on port " + req.port, "RESOURCE_NOT_FOUND");
        }
        instances.remove(req.port);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(),
                Map.of("message", "Instance unregistered for port " + req.port))
            .self("/unregisterInstance")
            .link("instances", "/instances")
            .build());
    }

    private static class PortRequest {
        public Integer port;
    }

    /**
     * GET /instances - list every active instance with its loaded program / project / tool.
     */
    private void list(GhidraContext ctx) {
        Map<Integer, ?> instances = ctx.activeInstances();

        List<Map<String, Object>> instanceList = new ArrayList<>();
        for (Integer port : instances.keySet()) {
            Map<String, Object> instance = snapshotFor(port, instances);
            instance.put("isCurrent", port == ctx.port());

            Map<String, Object> links = new LinkedHashMap<>();
            links.put("self", Links.href("/instances/{}", port));
            links.put("connect", Links.href("http://localhost:{}", port));
            links.put("info", Links.href("http://localhost:{}/info", port));
            if (instance.get("file") != null) {
                links.put("program", Links.href("http://localhost:{}/program", port));
            }
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

    private void getByPort(GhidraContext ctx) {
        int port = Integer.parseInt(ctx.pathParam("port"));
        Map<Integer, ?> instances = ctx.activeInstances();

        if (!instances.containsKey(port)) {
            throw new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "Instance not found on port: " + port, "INSTANCE_NOT_FOUND");
        }

        Map<String, Object> instance = snapshotFor(port, instances);
        instance.put("isCurrent", port == ctx.port());
        instance.put("active", true);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), instance)
            .self("/instances/{}", port)
            .link("instances", "/instances")
            .link("connect", "http://localhost:" + port)
            .link("info", "http://localhost:" + port + "/info")
            .build());
    }

    /**
     * Query the live plugin on that port for its project/program snapshot.
     * Falls back to the bare port/url pair if the map entry isn't a GhydraPlugin
     * (shouldn't happen in practice but keeps the route honest).
     */
    private Map<String, Object> snapshotFor(Integer port, Map<Integer, ?> instances) {
        Object pluginInstance = instances.get(port);
        if (pluginInstance instanceof eu.starsong.ghidra.GhydraPlugin p) {
            return new LinkedHashMap<>(p.getInstanceSnapshot());
        }
        Map<String, Object> fallback = new LinkedHashMap<>();
        fallback.put("port", port);
        fallback.put("url", "http://localhost:" + port);
        return fallback;
    }
}
