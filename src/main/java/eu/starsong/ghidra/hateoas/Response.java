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
        return link("self", LinkFormat.format(href, args));
    }

    /**
     * Add a named link.
     */
    public Response link(String rel, String href, Object... args) {
        Map<String, Object> linkObj = new LinkedHashMap<>();
        linkObj.put("href", LinkFormat.format(href, args));
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
     *
     * <p>Without an explicit page item count, the count is inferred from
     * {@code offset}, {@code limit} and {@code total} so the "next" link is
     * decided by the same {@code offset + pageCount < total} rule as
     * {@link #pagination(int, int, int, int, String)}.
     */
    public Response pagination(int offset, int limit, int total, String basePath) {
        int pageCount = Math.max(0, Math.min(limit, total - offset));
        return pagination(offset, limit, total, pageCount, basePath);
    }

    /**
     * Add pagination metadata and links. Single canonical implementation of the
     * self/next/prev link and offset/limit/total metadata building, shared with
     * {@link PaginatedResult}.
     *
     * @param pageCount the number of items actually on this page; the "next"
     *                  link is emitted when {@code offset + pageCount < total},
     *                  which is correct for a short final page.
     */
    Response pagination(int offset, int limit, int total, int pageCount, String basePath) {
        meta.put("offset", offset);
        meta.put("limit", limit);
        meta.put("total", total);

        self(basePath + "?offset=" + offset + "&limit=" + limit);

        if (offset + pageCount < total) {
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

        // id, instance, and timestamp live at the top level to match main's
        // shape; the bridge's simplify_response strips them from there.
        // Pagination and custom meta keys stay nested under "meta".
        Map<String, Object> nestedMeta = null;
        for (Map.Entry<String, Object> e : meta.entrySet()) {
            if ("id".equals(e.getKey()) || "instance".equals(e.getKey()) || "timestamp".equals(e.getKey())) {
                result.put(e.getKey(), e.getValue());
            } else {
                if (nestedMeta == null) nestedMeta = new LinkedHashMap<>();
                nestedMeta.put(e.getKey(), e.getValue());
            }
        }
        if (nestedMeta != null) {
            result.put("meta", nestedMeta);
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
        meta.put("timestamp", System.currentTimeMillis());
    }
}
