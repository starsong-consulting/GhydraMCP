package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * REST resource for root endpoint and API discovery.
 */
public class RootResource implements Resource {

    private final boolean isBaseInstance;

    public RootResource(boolean isBaseInstance) {
        this.isBaseInstance = isBaseInstance;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/", ctx -> root(contextFactory.apply(ctx)));
        app.get("/info", ctx -> info(contextFactory.apply(ctx)));
        app.get("/plugin-version", ctx -> version(contextFactory.apply(ctx)));
    }

    /**
     * GET / - API root with discovery links
     */
    private void root(GhidraContext ctx) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("message", "GhydraMCP API " + ApiConstants.API_VERSION);
        data.put("documentation", "See GHIDRA_HTTP_API.md for full API documentation");
        data.put("isBaseInstance", isBaseInstance);

        Response response = Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/")
            .link("info", "/info")
            .link("plugin-version", "/plugin-version")
            .link("instances", "/instances")
            .link("projects", "/projects")
            .link("programs", "/programs");

        if (ctx.program() != null) {
            response.link("program", "/program")
                .link("functions", "/functions")
                .link("symbols", "/symbols")
                .link("data", "/data")
                .link("strings", "/strings")
                .link("segments", "/segments")
                .link("structs", "/structs")
                .link("memory", "/memory")
                .link("xrefs", "/xrefs")
                .link("analysis", "/analysis");
        }

        ctx.json(response.build());
    }

    /**
     * GET /info - Detailed server and program info
     */
    private void info(GhidraContext ctx) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("isBaseInstance", isBaseInstance);
        data.put("serverPort", ctx.port());
        data.put("instanceCount", ctx.activeInstances().size());

        var program = ctx.program();
        if (program != null) {
            data.put("file", program.getName());
            data.put("architecture", program.getLanguage().getLanguageID().getIdAsString());
            data.put("processor", program.getLanguage().getProcessor().toString());
            data.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
            data.put("creationDate", program.getCreationDate().toString());
            data.put("executable", program.getExecutablePath());
        }

        var project = ctx.project();
        if (project != null) {
            data.put("project", project.getName());
            data.put("projectLocation", project.getProjectLocator().toString());
        }

        Response response = Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/info")
            .link("root", "/")
            .link("instances", "/instances");

        if (program != null) {
            response.link("program", "/program");
        }

        ctx.json(response.build());
    }

    /**
     * GET /plugin-version - Plugin and API version
     */
    private void version(GhidraContext ctx) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("plugin_version", ApiConstants.PLUGIN_VERSION);
        data.put("api_version", ApiConstants.API_VERSION);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/plugin-version")
            .link("root", "/")
            .build());
    }
}
