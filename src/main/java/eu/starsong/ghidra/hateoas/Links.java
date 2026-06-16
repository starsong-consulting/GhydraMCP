package eu.starsong.ghidra.hateoas;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fluent builder for HATEOAS links.
 * Used for building _links objects for individual items in collections.
 */
public class Links {

    private final Map<String, Object> links = new LinkedHashMap<>();

    private Links() {
    }

    /**
     * Create a new Links builder.
     */
    public static Links builder() {
        return new Links();
    }

    /**
     * Add a self link.
     */
    public Links self(String href, Object... args) {
        return link("self", href, args);
    }

    /**
     * Add a named link.
     */
    public Links link(String rel, String href, Object... args) {
        Map<String, Object> linkObj = new LinkedHashMap<>();
        linkObj.put("href", LinkFormat.format(href, args));
        links.put(rel, linkObj);
        return this;
    }

    /**
     * Add a named link with HTTP method.
     */
    public Links link(String rel, String href, String method, Object... args) {
        Map<String, Object> linkObj = new LinkedHashMap<>();
        linkObj.put("href", LinkFormat.format(href, args));
        linkObj.put("method", method);
        links.put(rel, linkObj);
        return this;
    }

    /**
     * Conditionally add a link.
     */
    public Links linkIf(boolean condition, String rel, String href, Object... args) {
        if (condition) {
            return link(rel, href, args);
        }
        return this;
    }

    /**
     * Build the links map.
     */
    public Map<String, Object> build() {
        return new LinkedHashMap<>(links);
    }

    // -------------------------------------------------------------------------
    // Static helper for simple cases
    // -------------------------------------------------------------------------

    /**
     * Create a simple link map with just href.
     */
    public static Map<String, Object> href(String href, Object... args) {
        Map<String, Object> link = new LinkedHashMap<>();
        link.put("href", LinkFormat.format(href, args));
        return link;
    }
}
