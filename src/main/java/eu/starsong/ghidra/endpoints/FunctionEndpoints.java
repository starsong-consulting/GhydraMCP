package eu.starsong.ghidra.endpoints;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.IOException; // Add IOException import

public class FunctionEndpoints extends AbstractEndpoint {

    // Updated constructor to accept port
    public FunctionEndpoints(Program program, int port) {
        super(program, port); // Call super constructor
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/functions", this::handleFunctions);
        server.createContext("/functions/", this::handleFunction);
    }

    private void handleFunctions(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> params = parseQueryParams(exchange);
                int offset = parseIntOrDefault(params.get("offset"), 0);
                int limit = parseIntOrDefault(params.get("limit"), 100);
                
                List<Map<String, String>> functions = new ArrayList<>();
                for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                    Map<String, String> func = new HashMap<>();
                    func.put("name", f.getName());
                    func.put("address", f.getEntryPoint().toString());
                    functions.add(func);
                }
                
                // Use sendSuccessResponse helper from AbstractEndpoint
                sendSuccessResponse(exchange, functions.subList(
                    Math.max(0, offset), 
                    Math.min(functions.size(), offset + limit)
                ));
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed"); // Uses helper from AbstractEndpoint
            }
        } catch (Exception e) {
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage()); // Uses helper from AbstractEndpoint
        }
    }

    private void handleFunction(HttpExchange exchange) throws IOException {
        try {
            String path = exchange.getRequestURI().getPath();
            String functionName = path.substring("/functions/".length());
            
            if ("GET".equals(exchange.getRequestMethod())) {
                Function function = findFunctionByName(functionName);
                if (function == null) {
                    sendErrorResponse(exchange, 404, "Function not found");
                    return;
                }
                
                Map<String, Object> result = new HashMap<>();
                result.put("name", function.getName());
                result.put("address", function.getEntryPoint().toString());
                result.put("signature", function.getSignature().getPrototypeString());
                
                // Use sendSuccessResponse helper
                sendSuccessResponse(exchange, result);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage());
        }
    }

    private Function findFunctionByName(String name) {
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    // parseIntOrDefault is now inherited from AbstractEndpoint
}
