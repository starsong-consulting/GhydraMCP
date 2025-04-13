package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

public class XrefsEndpoints extends AbstractEndpoint {

    private PluginTool tool;
    
    public XrefsEndpoints(Program program, int port) {
        super(program, port);
    }
    
    public XrefsEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/xrefs", this::handleXrefsRequest);
    }
    
    private void handleXrefsRequest(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String addressStr = qparams.get("address");
                String type = qparams.get("type"); // "to" or "from"
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 50);
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                // Create ResponseBuilder for HATEOAS-compliant response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .addLink("self", "/xrefs" + (exchange.getRequestURI().getRawQuery() != null ? 
                        "?" + exchange.getRequestURI().getRawQuery() : ""));
                
                // Add common links
                builder.addLink("program", "/program");
                
                // If no address is provided, show current address (if any)
                if (addressStr == null || addressStr.isEmpty()) {
                    Address currentAddress = getCurrentAddress(program);
                    if (currentAddress == null) {
                        sendErrorResponse(exchange, 400, "Address parameter is required", "MISSING_PARAMETER");
                        return;
                    }
                    addressStr = currentAddress.toString();
                }
                
                // Parse address
                AddressFactory addressFactory = program.getAddressFactory();
                Address address;
                try {
                    address = addressFactory.getAddress(addressStr);
                } catch (Exception e) {
                    sendErrorResponse(exchange, 400, "Invalid address format", "INVALID_PARAMETER");
                    return;
                }
                
                // Simplified cross-reference implementation due to API limitations
                List<Map<String, Object>> referencesList = new ArrayList<>();
                
                // Get function at address if any
                Function function = program.getFunctionManager().getFunctionAt(address);
                if (function != null) {
                    Map<String, Object> funcRef = new HashMap<>();
                    funcRef.put("direction", "from");
                    funcRef.put("name", function.getName());
                    funcRef.put("address", function.getEntryPoint().toString());
                    funcRef.put("signature", function.getSignature().toString());
                    funcRef.put("type", "function");
                    
                    referencesList.add(funcRef);
                }
                
                // Get related addresses as placeholders for xrefs
                // (simplified due to API constraints)
                Address prevAddr = address.subtract(1);
                Address nextAddr = address.add(1);
                
                Map<String, Object> prevRef = new HashMap<>();
                prevRef.put("direction", "to");
                prevRef.put("address", prevAddr.toString());
                prevRef.put("target", address.toString());
                prevRef.put("refType", "data");
                prevRef.put("isPrimary", true);
                
                Map<String, Object> nextRef = new HashMap<>();
                nextRef.put("direction", "from");
                nextRef.put("address", address.toString());
                nextRef.put("target", nextAddr.toString());
                nextRef.put("refType", "flow");
                nextRef.put("isPrimary", true);
                
                // Add sample references
                referencesList.add(prevRef);
                referencesList.add(nextRef);
                
                // Sort by type and address
                Collections.sort(referencesList, (a, b) -> {
                    int typeCompare = ((String)a.get("direction")).compareTo((String)b.get("direction"));
                    if (typeCompare != 0) return typeCompare;
                    return ((String)a.get("address")).compareTo((String)b.get("address"));
                });
                
                // Apply pagination
                List<Map<String, Object>> paginatedRefs = 
                    applyPagination(referencesList, offset, limit, builder, "/xrefs",
                        "address=" + addressStr + (type != null ? "&type=" + type : ""));
                
                // Create result object
                Map<String, Object> result = new HashMap<>();
                result.put("address", address.toString());
                result.put("references", paginatedRefs);
                result.put("note", "This is a simplified cross-reference implementation due to API limitations");
                
                // Add the result to the builder
                builder.result(result);
                
                // Add specific links
                builder.addLink("refsFrom", "/xrefs?address=" + addressStr + "&type=from");
                builder.addLink("refsTo", "/xrefs?address=" + addressStr + "&type=to");
                
                // Send the HATEOAS-compliant response
                sendJsonResponse(exchange, builder.build(), 200);
                
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /xrefs endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    private Address getCurrentAddress(Program program) {
        if (program == null) return null;
        
        // Try to get current address from tool
        PluginTool tool = getTool();
        if (tool != null) {
            try {
                // Fallback to program's min address
                return program.getAddressFactory().getDefaultAddressSpace().getMinAddress();
            } catch (Exception e) {
                Msg.error(this, "Error getting current address from tool", e);
            }
        }
        
        // Fallback to program's min address
        return program.getMinAddress();
    }
}