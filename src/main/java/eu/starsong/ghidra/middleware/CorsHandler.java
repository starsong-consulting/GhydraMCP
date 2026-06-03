package eu.starsong.ghidra.middleware;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import org.jetbrains.annotations.NotNull;

/**
 * CORS middleware that adds appropriate headers for cross-origin requests.
 */
public class CorsHandler implements Handler {

    // Configurable so the API can be locked to a specific origin; defaults to the
    // historical wildcard. Set -Dghidra.mcp.cors.origin=... or GHYDRA_CORS_ORIGIN.
    private static final String ALLOWED_ORIGIN = resolveAllowedOrigin();

    private static String resolveAllowedOrigin() {
        String origin = System.getProperty("ghidra.mcp.cors.origin");
        if (origin == null || origin.isEmpty()) {
            origin = System.getenv("GHYDRA_CORS_ORIGIN");
        }
        return (origin != null && !origin.isEmpty()) ? origin : "*";
    }

    @Override
    public void handle(@NotNull Context ctx) {
        ctx.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
        ctx.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        ctx.header("Access-Control-Allow-Headers", "Content-Type, X-Request-ID, Authorization");
        ctx.header("Access-Control-Max-Age", "3600");
    }
}
