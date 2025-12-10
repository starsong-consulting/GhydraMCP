package eu.starsong.ghidra.util;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.Headers;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class HttpUtil {

    private static final Gson gson = new Gson();

    /**
     * Sends a JSON response with the given status code.
     * Uses the ResponseBuilder internally.
     */
    /**
     * Add CORS headers to the response
     */
    public static void addCorsHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Access-Control-Allow-Origin", "http://localhost");
        headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type, X-Request-ID");
        headers.set("Access-Control-Max-Age", "3600");
    }
    
    /**
     * Handle OPTIONS requests for CORS preflight
     * @return true if the request was handled (OPTIONS request), false otherwise
     */
    public static boolean handleOptionsRequest(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(204, -1);
            return true;
        }
        return false;
    }
    
    public static void sendJsonResponse(HttpExchange exchange, JsonObject jsonObj, int statusCode, int port) throws IOException {
         try {
            // Handle OPTIONS requests for CORS preflight
            if (handleOptionsRequest(exchange)) {
                return;
            }
            
            String json = gson.toJson(jsonObj);
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            addCorsHeaders(exchange);
            
            long responseLength = (statusCode == 204) ? -1 : bytes.length; 
            exchange.sendResponseHeaders(statusCode, responseLength); 
            
            if (responseLength != -1) {
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } else {
                 exchange.getResponseBody().close(); // Important for 204
            }
        } catch (Exception e) {
            Msg.error(HttpUtil.class, "Error sending JSON response: " + e.getMessage(), e);
            // Avoid sending another error response here to prevent potential loops
            if (!exchange.getResponseHeaders().containsKey("Content-Type")) {
                 byte[] errorBytes = ("Internal Server Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8);
                 exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
                 exchange.sendResponseHeaders(500, errorBytes.length);
                 try (OutputStream os = exchange.getResponseBody()) {
                    os.write(errorBytes);
                 } catch (IOException writeErr) {
                     Msg.error(HttpUtil.class, "Failed to send even plain text error response", writeErr);
                 }
            }
            throw new IOException("Failed to send JSON response", e); 
        }
    }
    
    /**
     * Sends a standardized error response using ResponseBuilder.
     */
     public static void sendErrorResponse(HttpExchange exchange, int statusCode, String message, String errorCode, int port) throws IOException {
        ResponseBuilder builder = new ResponseBuilder(exchange, port)
            .success(false)
            .error(message, errorCode);
        sendJsonResponse(exchange, builder.build(), statusCode, port);
    }

    /**
     * Parses query parameters from the URL.
     */
     public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); 
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    try {
                         result.put(kv[0], java.net.URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                    } catch (Exception e) { 
                         Msg.warn(HttpUtil.class, "Failed to decode query parameter: " + kv[0]);
                         result.put(kv[0], kv[1]); 
                    }
                } else if (kv.length == 1 && !kv[0].isEmpty()) {
                     result.put(kv[0], ""); 
                }
            }
        }
        return result;
    }

    /**
     * Parses POST body parameters strictly as JSON.
     */
    public static Map<String, String> parseJsonPostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        
        // Debug - log request details
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        Msg.info(HttpUtil.class, "DEBUG " + method + " " + path + " body: " + bodyStr);
        
        Map<String, String> params = new HashMap<>();

        try {
            JsonObject json = gson.fromJson(bodyStr, JsonObject.class);
            if (json == null) { 
                 return params;
            }
            for (Map.Entry<String, JsonElement> entry : json.entrySet()) {
                String key = entry.getKey();
                JsonElement value = entry.getValue();
                if (value.isJsonPrimitive()) {
                    params.put(key, value.getAsString());
                } else {
                    params.put(key, value.toString()); // Stringify non-primitives
                }
            }
        } catch (Exception e) {
            Msg.error(HttpUtil.class, "Failed to parse JSON request body: " + bodyStr, e);
            throw new IOException("Invalid JSON request body: " + e.getMessage(), e);
        }
        return params;
    }

    /**
     * Functional interface for handlers that may throw any exception or error.
     */
    @FunctionalInterface
    public interface ThrowingHandler {
        void handle(HttpExchange exchange) throws Throwable;
    }

    /**
     * Wraps an HTTP handler to safely catch all Throwable types including
     * Error (StackOverflowError, OutOfMemoryError, etc.) that would otherwise
     * crash the CodeBrowser.
     *
     * @param handler the handler to wrap
     * @param port the port number for error responses
     * @return a safe HttpHandler that catches all throwables
     */
    public static HttpHandler safeHandler(ThrowingHandler handler, int port) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (StackOverflowError e) {
                Msg.error(HttpUtil.class, "StackOverflowError in HTTP handler - likely circular reference in Ghidra data", e);
                sendCriticalErrorResponse(exchange, port,
                    "Stack overflow - possible circular reference in data structure",
                    "STACK_OVERFLOW");
            } catch (OutOfMemoryError e) {
                Msg.error(HttpUtil.class, "OutOfMemoryError in HTTP handler", e);
                sendCriticalErrorResponse(exchange, port,
                    "Out of memory - request too large or memory exhausted",
                    "OUT_OF_MEMORY");
            } catch (Error e) {
                Msg.error(HttpUtil.class, "Critical error in HTTP handler: " + e.getClass().getSimpleName(), e);
                sendCriticalErrorResponse(exchange, port,
                    "Critical error: " + e.getClass().getSimpleName() + " - " + e.getMessage(),
                    "CRITICAL_ERROR");
            } catch (Exception e) {
                Msg.error(HttpUtil.class, "Exception in HTTP handler", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR", port);
            } catch (Throwable t) {
                // Catch any other Throwable types (should rarely happen)
                Msg.error(HttpUtil.class, "Unexpected throwable in HTTP handler: " + t.getClass().getSimpleName(), t);
                sendCriticalErrorResponse(exchange, port,
                    "Unexpected error: " + t.getClass().getSimpleName() + " - " + t.getMessage(),
                    "UNEXPECTED_ERROR");
            }
        };
    }

    /**
     * Sends an error response for critical errors (Error types) without throwing.
     * This method is designed to be as safe as possible to avoid further errors.
     */
    private static void sendCriticalErrorResponse(HttpExchange exchange, int port, String message, String errorCode) {
        try {
            ResponseBuilder builder = new ResponseBuilder(exchange, port)
                .success(false)
                .error(message, errorCode);

            String json = gson.toJson(builder.build());
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            addCorsHeaders(exchange);
            exchange.sendResponseHeaders(500, bytes.length);

            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (Throwable t) {
            Msg.error(HttpUtil.class, "Failed to send critical error response", t);
            try {
                exchange.getResponseBody().close();
            } catch (Throwable ignored) {
                // Best effort cleanup
            }
        }
    }
}
