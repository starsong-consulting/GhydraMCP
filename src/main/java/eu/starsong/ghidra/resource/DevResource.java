package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.SaveService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Dev-only endpoint that shuts Ghidra down so the build/deploy/restart loop can be
 * automated (no manual cmd.exe step). DISABLED by default.
 *
 * <p>Enable with {@code -Dghydra.dev.allowShutdown=true} (or env {@code GHYDRA_DEV_SHUTDOWN=1}).
 * When disabled, POST /dev/shutdown returns 403 and does nothing. With unsaved changes the call
 * refuses (409) unless {@code ?save=true} (save all changed programs, then exit) or
 * {@code ?force=true} (discard and exit) is given, so an accidental call cannot silently lose
 * analysis.
 *
 * <p>Note: the gate is the opt-in flag, not the request origin. The server already binds all
 * interfaces by default and exposes equally-destructive write endpoints (rename, memory write,
 * delete) to any reachable host, and the bridge typically calls in from another host (WSL ->
 * Windows), so a loopback-only restriction would block the very automation this enables without
 * adding meaningful protection. Only enable the flag in a dev environment.
 */
public class DevResource implements Resource {

    private final int port;

    public DevResource(int port) {
        this.port = port;
    }

    /** Whether the dev shutdown endpoint is enabled (off unless explicitly opted in). */
    public static boolean shutdownEnabled() {
        String prop = System.getProperty("ghydra.dev.allowShutdown");
        if (prop != null) {
            return prop.equalsIgnoreCase("true") || prop.equals("1");
        }
        String env = System.getenv("GHYDRA_DEV_SHUTDOWN");
        return env != null && (env.equalsIgnoreCase("true") || env.equals("1"));
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.post("/dev/shutdown", ctx -> shutdown(contextFactory.apply(ctx)));
    }

    private void shutdown(GhidraContext ctx) {
        if (!shutdownEnabled()) {
            ctx.status(403);
            ctx.json(Response.error(ctx.ctx(), port, "SHUTDOWN_DISABLED",
                "Dev shutdown is disabled. Start Ghidra with -Dghydra.dev.allowShutdown=true "
                    + "(or GHYDRA_DEV_SHUTDOWN=1) to enable.").build());
            return;
        }

        boolean force = "true".equalsIgnoreCase(ctx.queryParam("force"));
        boolean save = "true".equalsIgnoreCase(ctx.queryParam("save"));

        int savedCount = 0;
        if (save) {
            try {
                savedCount = new SaveService().saveAllChanged(ctx.tool()).size();
                Msg.info(this, "dev shutdown: saved " + savedCount + " changed program(s) before exit");
            } catch (Exception e) {
                // Saving failed: do NOT exit, or the unsaved work would be lost anyway.
                ctx.status(500);
                ctx.json(Response.error(ctx.ctx(), port, "SAVE_FAILED",
                    "Save before shutdown failed (not shutting down): " + e.getMessage()).build());
                return;
            }
        } else {
            String unsaved = unsavedSummary(ctx);
            if (unsaved != null && !force) {
                ctx.status(409);
                ctx.json(Response.error(ctx.ctx(), port, "UNSAVED_CHANGES",
                    "Refusing to shut down: " + unsaved + ". Save first (?save=true), or retry with "
                        + "?force=true to discard.").build());
                return;
            }
        }

        Msg.warn(this, "GhydraMCP dev shutdown requested on port " + port
            + " (force=" + force + ", save=" + save + "); exiting JVM shortly.");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "shutting down");
        result.put("force", force);
        result.put("saved", savedCount);
        ctx.json(Response.ok(ctx.ctx(), port, result).build());

        // Exit after the response flushes so the caller gets a clean 200. Non-daemon so the
        // sleep cannot be cut short by the JVM winding down.
        Thread exit = new Thread(() -> {
            try {
                Thread.sleep(300);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            System.exit(0);
        }, "ghydra-dev-shutdown");
        exit.setDaemon(false);
        exit.start();
    }

    /** Best-effort count of open programs with unsaved changes; null if none/unknown. */
    private String unsavedSummary(GhidraContext ctx) {
        try {
            PluginTool tool = ctx.tool();
            if (tool == null) {
                return null;
            }
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) {
                return null;
            }
            int changed = 0;
            for (Program p : pm.getAllOpenPrograms()) {
                if (p.isChanged()) {
                    changed++;
                }
            }
            if (changed > 0) {
                return changed + " open program(s) have unsaved changes";
            }
        } catch (Exception e) {
            // Never block the gating decision on a best-effort probe.
            Msg.debug(this, "unsaved-changes probe failed: " + e.getMessage());
        }
        return null;
    }
}
