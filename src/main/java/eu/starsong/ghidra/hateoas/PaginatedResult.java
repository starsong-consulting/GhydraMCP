package eu.starsong.ghidra.hateoas;

import com.google.gson.Gson;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Represents a paginated collection of items with HATEOAS metadata.
 *
 * @param <T> The type of items in the result
 */
public class PaginatedResult<T> {

    private final List<T> items;
    private final int total;
    private final int offset;
    private final int limit;
    private final String basePath;
    private Function<T, Map<String, Object>> itemLinksBuilder;

    public PaginatedResult(List<T> items, int total, int offset, int limit, String basePath) {
        this.items = items;
        this.total = total;
        this.offset = offset;
        this.limit = limit;
        this.basePath = basePath;
    }

    /**
     * Get the paginated items.
     */
    public List<T> items() {
        return items;
    }

    /**
     * Get the total count of items (before pagination).
     */
    public int total() {
        return total;
    }

    /**
     * Get the offset used.
     */
    public int offset() {
        return offset;
    }

    /**
     * Get the limit used.
     */
    public int limit() {
        return limit;
    }

    /**
     * Check if there is a next page.
     */
    public boolean hasNext() {
        return offset + items.size() < total;
    }

    /**
     * Check if there is a previous page.
     */
    public boolean hasPrev() {
        return offset > 0;
    }

    /**
     * Set a function to build links for each item.
     */
    public PaginatedResult<T> withItemLinks(Function<T, Map<String, Object>> linksBuilder) {
        this.itemLinksBuilder = linksBuilder;
        return this;
    }

    /**
     * Build a Response with pagination metadata and links.
     */
    public Response toResponse() {
        return toResponse(null, 0);
    }

    /**
     * Build a Response with pagination metadata and links, including the
     * top-level id/instance/timestamp meta fields for HATEOAS compliance.
     */
    public Response toResponse(Context ctx, int port) {
        List<?> resultItems = itemLinksBuilder != null
            ? items.stream().map(this::wrapWithLinks).toList()
            : items;

        Response r = ctx != null
            ? Response.ok(ctx, port, resultItems)
            : Response.ok(resultItems);
        return r.pagination(offset, limit, total, basePath);
    }

    /**
     * Build metadata map for embedding in custom responses.
     */
    public Map<String, Object> metadata() {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("total", total);
        meta.put("offset", offset);
        meta.put("limit", limit);
        meta.put("count", items.size());
        return meta;
    }

    /**
     * Build pagination links map.
     */
    public Map<String, Object> links() {
        Map<String, Object> links = new LinkedHashMap<>();

        links.put("self", linkHref(basePath + "?offset=" + offset + "&limit=" + limit));

        if (hasNext()) {
            links.put("next", linkHref(basePath + "?offset=" + (offset + limit) + "&limit=" + limit));
        }

        if (hasPrev()) {
            int prevOffset = Math.max(0, offset - limit);
            links.put("prev", linkHref(basePath + "?offset=" + prevOffset + "&limit=" + limit));
        }

        return links;
    }

    private Map<String, Object> linkHref(String href) {
        Map<String, Object> link = new LinkedHashMap<>();
        link.put("href", href);
        return link;
    }

    @SuppressWarnings("unchecked")
    private Object wrapWithLinks(T item) {
        if (itemLinksBuilder == null) {
            return item;
        }

        Map<String, Object> itemLinks = itemLinksBuilder.apply(item);
        if (itemLinks == null || itemLinks.isEmpty()) {
            return item;
        }

        if (item instanceof Map) {
            Map<String, Object> result = new LinkedHashMap<>((Map<String, Object>) item);
            result.put("_links", itemLinks);
            return result;
        }

        // Flatten: convert record/POJO to a Map via Gson, then embed _links
        // directly at the top level so the JSON shape is
        //   {"name": ..., "address": ..., "_links": {...}}
        // rather than {"data": {...}, "_links": {...}}. This matches main's
        // shape and what the bridge/CLI/tests expect.
        Gson gson = GSON;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> asMap = gson.fromJson(gson.toJson(item), Map.class);
            if (asMap == null) {
                return item;
            }
            Map<String, Object> result = new LinkedHashMap<>(asMap);
            result.put("_links", itemLinks);
            return result;
        } catch (Exception e) {
            // Fallback: if the item doesn't serialize to a JSON object,
            // leave it alone rather than fabricate a wrapper.
            return item;
        }
    }

    private static final Gson GSON = new Gson();
}
