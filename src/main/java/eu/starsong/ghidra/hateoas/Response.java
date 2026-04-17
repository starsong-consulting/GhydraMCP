package eu.starsong.ghidra.hateoas;

import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Standardized HATEOAS response builder.
 * Provides a fluent API for constructing API responses with links.
 */
public class Response {

    private final Map<String, Object> response = new LinkedHashMap<>();
    private final Map<String, Object> links = new LinkedHashMap<>();
    private final Map<String, Object> meta = new LinkedHashMap<>();

    private Response() {
    }

    // -------------------------------------------------------------------------
    // Static factory methods
    // -------------------------------------------------------------------------

    /**
     * Create a successful response with data.
     */
    public static Response ok(Object data) {
        Response r = new Response();
        r.response.put("success", true);
        r.response.put("result", data);
        return r;
    }

    /**
     * Create a successful response with data, context, and port for HATEOAS.
     */
    public static Response ok(Context ctx, int port, Object data) {
        Response r = ok(data);
        r.addMeta(ctx, port);
        return r;
    }

    /**
     * Create a successful empty response.
     */
    public static Response ok() {
        Response r = new Response();
        r.response.put("success", true);
        return r;
    }

    /**
     * Create an error response.
     */
    public static Response error(String errorCode, String message) {
        Response r = new Response();
        r.response.put("success", false);
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("code", errorCode);
        error.put("message", message);
        r.response.put("error", error);
        return r;
    }

    /**
     * Create an error response with context for HATEOAS.
     */
    public static Response error(Context ctx, int port, String errorCode, String message) {
        Response r = error(errorCode, message);
        r.addMeta(ctx, port);
        return r;
    }

    // -------------------------------------------------------------------------
    // Fluent builder methods
    // -------------------------------------------------------------------------

    /**
     * Add a self link.
     */
    public Response self(String href, Object... args) {
        return link("self", format(href, args));
    }

    /**
     * Add a named link.
     */
    public Response link(String rel, String href, Object... args) {
        Map<String, Object> linkObj = new LinkedHashMap<>();
        linkObj.put("href", format(href, args));
        links.put(rel, linkObj);
        return this;
    }

    /**
     * Add a named link with HTTP method.
     */
    public Response link(String rel, String href, String method) {
        Map<String, Object> linkObj = new LinkedHashMap<>();
        linkObj.put("href", href);
        linkObj.put("method", method);
        links.put(rel, linkObj);
        return this;
    }

    /**
     * Add metadata.
     */
    public Response meta(String key, Object value) {
        meta.put(key, value);
        return this;
    }

    /**
     * Add pagination metadata and links.
     */
    public Response pagination(int offset, int limit, int total, String basePath) {
        meta.put("offset", offset);
        meta.put("limit", limit);
        meta.put("total", total);

        self(basePath + "?offset=" + offset + "&limit=" + limit);

        if (offset + limit < total) {
            link("next", basePath + "?offset=" + (offset + limit) + "&limit=" + limit);
        }

        if (offset > 0) {
            int prevOffset = Math.max(0, offset - limit);
            link("prev", basePath + "?offset=" + prevOffset + "&limit=" + limit);
        }

        return this;
    }

    // -------------------------------------------------------------------------
    // Build method
    // -------------------------------------------------------------------------

    /**
     * Build the final response map.
     */
    public Map<String, Object> build() {
        Map<String, Object> result = new LinkedHashMap<>(response);

        if (!meta.isEmpty()) {
            result.put("meta", meta);
        }

        if (!links.isEmpty()) {
            result.put("_links", links);
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // Private helper methods
    // -------------------------------------------------------------------------

    private void addMeta(Context ctx, int port) {
        String requestId = ctx.header("X-Request-ID");
        if (requestId == null) {
            requestId = UUID.randomUUID().toString();
        }
        meta.put("id", requestId);
        meta.put("instance", "http://localhost:" + port);
    }

    private static String format(String template, Object... args) {
        if (args == null || args.length == 0) {
            return template;
        }

        StringBuilder result = new StringBuilder();
        int argIndex = 0;
        int i = 0;

        while (i < template.length()) {
            if (i < template.length() - 1 && template.charAt(i) == '{' && template.charAt(i + 1) == '}') {
                if (argIndex < args.length) {
                    result.append(args[argIndex++]);
                } else {
                    result.append("{}");
                }
                i += 2;
            } else if (template.charAt(i) == '{') {
                int end = template.indexOf('}', i);
                if (end != -1 && argIndex < args.length) {
                    result.append(args[argIndex++]);
                    i = end + 1;
                } else {
                    result.append(template.charAt(i));
                    i++;
                }
            } else {
                result.append(template.charAt(i));
                i++;
            }
        }

        return result.toString();
    }
}
