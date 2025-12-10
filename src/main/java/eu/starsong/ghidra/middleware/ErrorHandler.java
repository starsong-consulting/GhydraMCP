package eu.starsong.ghidra.middleware;

import eu.starsong.ghidra.hateoas.Response;
import ghidra.util.Msg;
import io.javalin.http.Context;
import io.javalin.http.ExceptionHandler;
import io.javalin.http.HttpStatus;
import org.jetbrains.annotations.NotNull;

/**
 * Global error handler that catches unhandled exceptions and returns
 * a standardized error response.
 */
public class ErrorHandler implements ExceptionHandler<Exception> {

    private final int port;

    public ErrorHandler(int port) {
        this.port = port;
    }

    @Override
    public void handle(@NotNull Exception e, @NotNull Context ctx) {
        Msg.error(this, "Unhandled exception in " + ctx.path(), e);

        ctx.status(HttpStatus.INTERNAL_SERVER_ERROR);
        ctx.json(Response.error(ctx, port, "INTERNAL_ERROR", "Internal server error: " + e.getMessage()));
    }
}
