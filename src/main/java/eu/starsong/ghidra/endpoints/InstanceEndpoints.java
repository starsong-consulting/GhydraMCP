package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.GhydraMCPPlugin; // Need access to activeInstances
    import ghidra.program.model.listing.Program;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class InstanceEndpoints extends AbstractEndpoint {

        // Need a way to access the static activeInstances map from GhydraMCPPlugin
        // This is a bit awkward and suggests the instance management might need
        // a different design, perhaps a dedicated manager class.
        // For now, we pass the map or use a static accessor if made public.
        private final Map<Integer, GhydraMCPPlugin> activeInstances; 
        // Note: Passing currentProgram might be null here if no program is open.
        // The constructor in AbstractEndpoint handles null program.

        // Updated constructor to accept port
        public InstanceEndpoints(Program program, int port, Map<Integer, GhydraMCPPlugin> instances) {
             super(program, port); // Call super constructor
             this.activeInstances = instances;
        }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/instances", this::handleInstances);
        server.createContext("/registerInstance", this::handleRegisterInstance);
        server.createContext("/unregisterInstance", this::handleUnregisterInstance);
    }
    
    @Override
    protected boolean requiresProgram() {
        // This endpoint doesn't require a program to function
        return false;
    }

        private void handleInstances(HttpExchange exchange) throws IOException {
             try {
                 List<Map<String, Object>> instanceData = new ArrayList<>();
                 // Accessing the static map directly - requires it to be accessible
                 // or passed in constructor.
                 for (Map.Entry<Integer, GhydraMCPPlugin> entry : activeInstances.entrySet()) {
                    Map<String, Object> instance = new HashMap<>();
                    // Need a way to get isBaseInstance from the plugin instance - requires getter in GhydraMCPPlugin
                    // instance.put("type", entry.getValue().isBaseInstance() ? "base" : "secondary"); // Placeholder access
                    instance.put("type", "unknown"); // Placeholder until isBaseInstance is accessible
                    instanceData.add(instance);
                }
                sendSuccessResponse(exchange, instanceData); // Use helper from AbstractEndpoint
            } catch (Exception e) {
                 Msg.error(this, "Error in /instances endpoint", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage()); // Use helper
            }
        }

        private void handleRegisterInstance(HttpExchange exchange) throws IOException {
             try {
                Map<String, String> params = parseJsonPostParams(exchange);
                int regPort = parseIntOrDefault(params.get("port"), 0);
                if (regPort > 0) {
                     // Logic to actually register/track the instance should happen elsewhere (e.g., main plugin or dedicated manager)
                     sendSuccessResponse(exchange, Map.of("message", "Instance registration request received for port " + regPort)); // Use helper
                } else {
                     sendErrorResponse(exchange, 400, "Invalid or missing port number"); // Use helper
                }
            } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for registerInstance", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST"); // Use helper
            } catch (Exception e) {
                Msg.error(this, "Error in /registerInstance", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR"); // Use helper
            }
        }

        private void handleUnregisterInstance(HttpExchange exchange) throws IOException {
            try {
                Map<String, String> params = parseJsonPostParams(exchange);
                int unregPort = parseIntOrDefault(params.get("port"), 0);
                if (unregPort > 0 && activeInstances.containsKey(unregPort)) {
                    // Actual removal should likely happen in the main plugin's map or dedicated manager
                    activeInstances.remove(unregPort); // Potential ConcurrentModificationException if map is iterated elsewhere
                     sendSuccessResponse(exchange, Map.of("message", "Instance unregistered for port " + unregPort)); // Use helper
                } else {
                     sendErrorResponse(exchange, 404, "No instance found on port " + unregPort, "RESOURCE_NOT_FOUND"); // Use helper
                }
             } catch (IOException e) {
                 Msg.error(this, "Error parsing POST params for unregisterInstance", e);
                 sendErrorResponse(exchange, 400, "Invalid request body: " + e.getMessage(), "INVALID_REQUEST"); // Use helper
            } catch (Exception e) {
                Msg.error(this, "Error in /unregisterInstance", e);
                 sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR"); // Use helper
            }
        }


        // --- Helper Methods Removed (Inherited or internal logic adjusted) ---
        
        // parseIntOrDefault is inherited from AbstractEndpoint
    }
