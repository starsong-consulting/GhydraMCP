package eu.starsong.ghidra.server;

import io.javalin.Javalin;

import java.util.function.Function;

/**
 * Interface for REST resources that register routes with the Javalin server.
 */
@FunctionalInterface
public interface Resource {

    /**
     * Register routes with the Javalin application.
     *
     * @param app The Javalin application
     * @param contextFactory Factory function to create GhidraContext from Javalin Context
     */
    void register(Javalin app, Function<io.javalin.http.Context, GhidraContext> contextFactory);
}
