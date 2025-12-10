package eu.starsong.ghidra.middleware;

import io.javalin.http.Context;
import io.javalin.http.Handler;
import org.jetbrains.annotations.NotNull;

/**
 * CORS middleware that adds appropriate headers for cross-origin requests.
 */
public class CorsHandler implements Handler {

    @Override
    public void handle(@NotNull Context ctx) {
        ctx.header("Access-Control-Allow-Origin", "*");
        ctx.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        ctx.header("Access-Control-Allow-Headers", "Content-Type, X-Request-ID, Authorization");
        ctx.header("Access-Control-Max-Age", "3600");
    }
}
