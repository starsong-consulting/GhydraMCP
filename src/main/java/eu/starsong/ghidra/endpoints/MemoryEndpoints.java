package eu.starsong.ghidra.endpoints;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.io.IOException;
import java.util.*;

public class MemoryEndpoints extends AbstractEndpoint {

    private static final int DEFAULT_MEMORY_LENGTH = 16;
    private static final int MAX_MEMORY_LENGTH = 4096;
    private PluginTool tool;
    
    public MemoryEndpoints(Program program, int port) {
        super(program, port);
    }
    
    public MemoryEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }
    
    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/memory", this::handleMemoryRequest);
        server.createContext("/memory/blocks", this::handleMemoryBlocksRequest);
    }
    
    private void handleMemoryRequest(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String addressStr = qparams.get("address");
                String lengthStr = qparams.get("length");
                
                // Create ResponseBuilder for HATEOAS-compliant response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .addLink("self", "/memory" + (exchange.getRequestURI().getRawQuery() != null ? 
                        "?" + exchange.getRequestURI().getRawQuery() : ""));
                
                // Add common links
                builder.addLink("program", "/program");
                builder.addLink("blocks", "/memory/blocks");
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                if (addressStr == null || addressStr.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Address parameter is required", "MISSING_PARAMETER");
                    return;
                }
                
                // Parse length parameter
                int length = DEFAULT_MEMORY_LENGTH;
                if (lengthStr != null && !lengthStr.isEmpty()) {
                    try {
                        length = Integer.parseInt(lengthStr);
                        if (length <= 0) {
                            sendErrorResponse(exchange, 400, "Length must be positive", "INVALID_PARAMETER");
                            return;
                        }
                        if (length > MAX_MEMORY_LENGTH) {
                            length = MAX_MEMORY_LENGTH;
                        }
                    } catch (NumberFormatException e) {
                        sendErrorResponse(exchange, 400, "Invalid length parameter", "INVALID_PARAMETER");
                        return;
                    }
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
                
                // Read memory
                Memory memory = program.getMemory();
                if (!memory.contains(address)) {
                    sendErrorResponse(exchange, 404, "Address not in memory", "ADDRESS_NOT_FOUND");
                    return;
                }
                
                try {
                    // Read bytes
                    byte[] bytes = new byte[length];
                    int bytesRead = memory.getBytes(address, bytes, 0, length);
                    
                    // Format as hex string
                    StringBuilder hexString = new StringBuilder();
                    for (int i = 0; i < bytesRead; i++) {
                        String hex = Integer.toHexString(bytes[i] & 0xFF).toUpperCase();
                        if (hex.length() == 1) {
                            hexString.append('0');
                        }
                        hexString.append(hex);
                        if (i < bytesRead - 1) {
                            hexString.append(' ');
                        }
                    }
                    
                    // Build result object
                    Map<String, Object> result = new HashMap<>();
                    result.put("address", address.toString());
                    result.put("bytesRead", bytesRead);
                    result.put("hexBytes", hexString.toString());
                    result.put("rawBytes", Base64.getEncoder().encodeToString(bytes));
                    
                    // Add next/prev links
                    builder.addLink("next", "/memory?address=" + address.add(length) + "&length=" + length);
                    if (address.getOffset() >= length) {
                        builder.addLink("prev", "/memory?address=" + address.subtract(length) + "&length=" + length);
                    }
                    
                    // Add result and send response
                    builder.result(result);
                    sendJsonResponse(exchange, builder.build(), 200);
                    
                } catch (MemoryAccessException e) {
                    sendErrorResponse(exchange, 404, "Cannot read memory at address: " + e.getMessage(), "MEMORY_ACCESS_ERROR");
                }
                
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /memory endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    private void handleMemoryBlocksRequest(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);
                
                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }
                
                // Create ResponseBuilder for HATEOAS-compliant response
                ResponseBuilder builder = new ResponseBuilder(exchange, port)
                    .success(true)
                    .addLink("self", "/memory/blocks" + (exchange.getRequestURI().getRawQuery() != null ? 
                        "?" + exchange.getRequestURI().getRawQuery() : ""));
                
                // Add common links
                builder.addLink("program", "/program");
                builder.addLink("memory", "/memory");
                
                // Get memory blocks
                Memory memory = program.getMemory();
                List<Map<String, Object>> blocks = new ArrayList<>();
                
                for (MemoryBlock block : memory.getBlocks()) {
                    Map<String, Object> blockInfo = new HashMap<>();
                    blockInfo.put("name", block.getName());
                    blockInfo.put("start", block.getStart().toString());
                    blockInfo.put("end", block.getEnd().toString());
                    blockInfo.put("size", block.getSize());
                    blockInfo.put("permissions", getPermissionString(block));
                    blockInfo.put("isInitialized", block.isInitialized());
                    blockInfo.put("isLoaded", block.isLoaded());
                    blockInfo.put("isMapped", block.isMapped());
                    blocks.add(blockInfo);
                }
                
                // Apply pagination and add it to result
                List<Map<String, Object>> paginatedBlocks = 
                    applyPagination(blocks, offset, limit, builder, "/memory/blocks");
                
                // Add the result to the builder
                builder.result(paginatedBlocks);
                
                // Send the HATEOAS-compliant response
                sendJsonResponse(exchange, builder.build(), 200);
                
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /memory/blocks endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage());
        }
    }
    
    private String getPermissionString(MemoryBlock block) {
        StringBuilder perms = new StringBuilder();
        perms.append(block.isRead() ? "r" : "-");
        perms.append(block.isWrite() ? "w" : "-");
        perms.append(block.isExecute() ? "x" : "-");
        perms.append(block.isVolatile() ? "v" : "-");
        return perms.toString();
    }
}