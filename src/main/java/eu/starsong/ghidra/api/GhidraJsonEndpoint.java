package eu.starsong.ghidra.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public interface GhidraJsonEndpoint extends HttpHandler {
    void registerEndpoints(com.sun.net.httpserver.HttpServer server);
}
