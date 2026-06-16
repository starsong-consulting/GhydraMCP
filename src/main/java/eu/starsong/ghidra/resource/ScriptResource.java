package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.ScriptService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.function.Function;

/**
 * List and run Ghidra scripts: GET /scripts and POST /scripts/run.
 *
 * <p>Running a script is arbitrary code execution, so the endpoints are DISABLED by default.
 * Enable with {@code -Dghydra.dev.allowScripts=true} (or env {@code GHYDRA_ALLOW_SCRIPTS=1}).
 * When disabled both return 403. Once enabled, anyone who can reach the port can run code, so
 * only enable it in a trusted/dev environment.
 */
public class ScriptResource implements Resource {

    private final ScriptService service = new ScriptService();

    /** Whether script endpoints are enabled (off unless explicitly opted in). */
    public static boolean scriptsEnabled() {
        String prop = System.getProperty("ghydra.dev.allowScripts");
        if (prop != null) {
            return prop.equalsIgnoreCase("true") || prop.equals("1");
        }
        String env = System.getenv("GHYDRA_ALLOW_SCRIPTS");
        return env != null && (env.equalsIgnoreCase("true") || env.equals("1"));
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/scripts", ctx -> list(contextFactory.apply(ctx)));
        app.post("/scripts/run", ctx -> run(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        if (forbidden(ctx)) {
            return;
        }
        List<ScriptService.ScriptInfo> scripts = service.list();
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), scripts)
            .self("/scripts")
            .meta("count", scripts.size())
            .link("run", "/scripts/run")
            .build());
    }

    private void run(GhidraContext ctx) {
        if (forbidden(ctx)) {
            return;
        }
        RunRequest req = ctx.bodyAsClass(RunRequest.class);
        String[] args = req.args != null ? req.args : new String[0];

        ScriptService.RunResult result;
        if (req.name != null && !req.name.isEmpty()) {
            result = service.runByName(ctx.tool(), ctx.program(), req.name, args);
        } else if (req.source != null && !req.source.isEmpty()) {
            result = service.runSource(ctx.tool(), ctx.program(), req.source, args);
        } else {
            throw new IllegalArgumentException(
                "Provide 'name' (an existing script) or 'source' (ad-hoc GhidraScript source)");
        }
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/scripts/run")
            .link("scripts", "/scripts")
            .build());
    }

    /** Returns true (and writes a 403) when script execution is disabled. */
    private boolean forbidden(GhidraContext ctx) {
        if (scriptsEnabled()) {
            return false;
        }
        ctx.status(403);
        ctx.json(Response.error(ctx.ctx(), ctx.port(), "SCRIPTS_DISABLED",
            "Script execution is disabled. Start Ghidra with -Dghydra.dev.allowScripts=true "
                + "(or GHYDRA_ALLOW_SCRIPTS=1) to enable. Warning: this allows arbitrary code "
                + "execution via the API; only enable it in a trusted environment.").build());
        return true;
    }

    private static class RunRequest {
        public String name;
        public String source;
        public String[] args;
    }
}
