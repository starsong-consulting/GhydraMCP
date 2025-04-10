package eu.starsong.ghidra.api;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import java.util.UUID;

/**
 * Builder for standardized API responses (following GHIDRA_HTTP_API.md v1).
 * This should be used by endpoint handlers to construct responses.
 */
public class ResponseBuilder {
    private final HttpExchange exchange;
    private final int port; // Port of the current Ghidra instance handling the request
    private JsonObject response;
    private JsonObject links; // For HATEOAS links
    private final Gson gson = new Gson(); // Gson instance for serialization

    public ResponseBuilder(HttpExchange exchange, int port) {
        this.exchange = exchange;
        this.port = port;
        this.response = new JsonObject();
        this.links = new JsonObject();

        // Add standard fields
        String requestId = exchange.getRequestHeaders().getFirst("X-Request-ID");
        response.addProperty("id", requestId != null ? requestId : UUID.randomUUID().toString());
        response.addProperty("instance", "http://localhost:" + port); // URL of this instance
    }

    public ResponseBuilder success(boolean success) {
        response.addProperty("success", success);
        return this;
    }

    public ResponseBuilder result(Object data) {
        response.add("result", gson.toJsonTree(data));
        return this;
    }

    public ResponseBuilder error(String message, String code) {
        JsonObject error = new JsonObject();
        error.addProperty("message", message);
        if (code != null) {
            error.addProperty("code", code);
        }
        response.add("error", error);
        return this;
    }

    public ResponseBuilder addLink(String rel, String href) {
        JsonObject link = new JsonObject();
        link.addProperty("href", href);
        links.add(rel, link);
        return this;
    }
    
    // Overload to add link with method
    public ResponseBuilder addLink(String rel, String href, String method) {
        JsonObject link = new JsonObject();
        link.addProperty("href", href);
        link.addProperty("method", method);
        links.add(rel, link);
        return this;
    }

    public JsonObject build() {
        if (links.size() > 0) {
            response.add("_links", links);
        }
        return response;
    }
}
