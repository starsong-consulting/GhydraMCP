package eu.starsong.ghidra.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Standardized response object for API responses.
 * This class follows the common response structure used throughout the API.
 */
public class JsonResponse {
    private boolean success;
    private Object result;
    private Map<String, Object> error;
    private Map<String, Object> links;
    private String id;
    private String instance;

    // Private constructor for builder pattern
    private JsonResponse() {
        this.links = new HashMap<>();
    }

    /**
     * @return Whether the request was successful
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * @return The result data for successful requests
     */
    public Object getResult() {
        return result;
    }

    /**
     * @return Error information for failed requests
     */
    public Map<String, Object> getError() {
        return error;
    }

    /**
     * @return HATEOAS links
     */
    public Map<String, Object> getLinks() {
        return links;
    }

    /**
     * @return Request ID
     */
    public String getId() {
        return id;
    }

    /**
     * @return Server instance information
     */
    public String getInstance() {
        return instance;
    }

    /**
     * Creates a new builder for constructing a JsonResponse
     * @return A new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for JsonResponse
     */
    public static class Builder {
        private final JsonResponse response;

        private Builder() {
            response = new JsonResponse();
        }

        /**
         * Set the success status
         * @param success Whether the request was successful
         * @return This builder
         */
        public Builder success(boolean success) {
            response.success = success;
            return this;
        }

        /**
         * Set the result data
         * @param result The result data
         * @return This builder
         */
        public Builder result(Object result) {
            response.result = result;
            return this;
        }

        /**
         * Set error information
         * @param message Error message
         * @param code Error code
         * @return This builder
         */
        public Builder error(String message, String code) {
            Map<String, Object> error = new HashMap<>();
            error.put("message", message);
            if (code != null && !code.isEmpty()) {
                error.put("code", code);
            }
            response.error = error;
            return this;
        }

        /**
         * Add a link
         * @param rel Relation name
         * @param href Link URL
         * @return This builder
         */
        public Builder addLink(String rel, String href) {
            Map<String, String> link = new HashMap<>();
            link.put("href", href);
            response.links.put(rel, link);
            return this;
        }

        /**
         * Add a link with method
         * @param rel Relation name
         * @param href Link URL
         * @param method HTTP method
         * @return This builder
         */
        public Builder addLink(String rel, String href, String method) {
            Map<String, String> link = new HashMap<>();
            link.put("href", href);
            link.put("method", method);
            response.links.put(rel, link);
            return this;
        }

        /**
         * Set request ID
         * @param id Request ID
         * @return This builder
         */
        public Builder id(String id) {
            response.id = id;
            return this;
        }

        /**
         * Set instance information
         * @param instance Instance information
         * @return This builder
         */
        public Builder instance(String instance) {
            response.instance = instance;
            return this;
        }

        /**
         * Build the JsonResponse
         * @return The constructed JsonResponse
         */
        public JsonResponse build() {
            return response;
        }
    }
}
