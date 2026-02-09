package eu.starsong.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.starsong.ghidra.api.ResponseBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
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
    
    /**
     * Helper method to convert ReferenceIterator to an iterable collection
     */
    private List<Reference> collectReferences(ReferenceIterator iterator) {
        List<Reference> references = new ArrayList<>();
        while (iterator.hasNext()) {
            references.add(iterator.next());
        }
        return references;
    }
    
    /**
     * Helper method to convert Reference[] to a list
     */
    private List<Reference> collectReferences(Reference[] refs) {
        return Arrays.asList(refs);
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/xrefs", this::handleXrefsRequest);
    }
    
    private void handleXrefsRequest(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                String toAddrStr = qparams.get("to_addr");
                String fromAddrStr = qparams.get("from_addr");
                String refTypeStr = qparams.get("type");
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
                
                // At least one of to_addr or from_addr must be provided
                if ((toAddrStr == null || toAddrStr.isEmpty()) && 
                    (fromAddrStr == null || fromAddrStr.isEmpty())) {
                    sendErrorResponse(exchange, 400, "Either to_addr or from_addr parameter is required", "MISSING_PARAMETER");
                    return;
                }
                
                // Parse addresses
                AddressFactory addressFactory = program.getAddressFactory();
                Address toAddr = null;
                Address fromAddr = null;
                
                if (toAddrStr != null && !toAddrStr.isEmpty()) {
                    try {
                        toAddr = addressFactory.getAddress(toAddrStr);
                    } catch (Exception e) {
                        sendErrorResponse(exchange, 400, "Invalid to_addr format: " + toAddrStr, "INVALID_PARAMETER");
                        return;
                    }
                }
                
                if (fromAddrStr != null && !fromAddrStr.isEmpty()) {
                    try {
                        fromAddr = addressFactory.getAddress(fromAddrStr);
                    } catch (Exception e) {
                        sendErrorResponse(exchange, 400, "Invalid from_addr format: " + fromAddrStr, "INVALID_PARAMETER");
                        return;
                    }
                }
                
                // Get reference manager
                ReferenceManager refManager = program.getReferenceManager();
                List<Map<String, Object>> referencesList = new ArrayList<>();
                
                // Get references to this address
                if (toAddr != null) {
                    // Get references to this address - must manually convert array
                    for (Reference ref : collectReferences(refManager.getReferencesTo(toAddr))) {
                        if (refTypeStr != null && !ref.getReferenceType().getName().equalsIgnoreCase(refTypeStr)) {
                            continue; // Skip if type filter doesn't match
                        }
                        
                        Map<String, Object> refMap = createReferenceMap(program, ref, "to");
                        referencesList.add(refMap);
                    }
                }
                
                // Get references from this address
                if (fromAddr != null) {
                    // Get references from this address - must manually convert array
                    for (Reference ref : collectReferences(refManager.getReferencesFrom(fromAddr))) {
                        if (refTypeStr != null && !ref.getReferenceType().getName().equalsIgnoreCase(refTypeStr)) {
                            continue; // Skip if type filter doesn't match
                        }
                        
                        Map<String, Object> refMap = createReferenceMap(program, ref, "from");
                        referencesList.add(refMap);
                    }
                }
                
                // Sort by type and address
                Collections.sort(referencesList, (a, b) -> {
                    // First sort by direction
                    int directionCompare = ((String)a.get("direction")).compareTo((String)b.get("direction"));
                    if (directionCompare != 0) return directionCompare;
                    
                    // Then by reference type
                    int typeCompare = ((String)a.get("refType")).compareTo((String)b.get("refType"));
                    if (typeCompare != 0) return typeCompare;
                    
                    // Finally by from_address
                    return ((String)a.get("from_addr")).compareTo((String)b.get("from_addr"));
                });
                
                // Apply pagination
                List<Map<String, Object>> paginatedRefs = 
                    applyPagination(referencesList, offset, limit, builder, "/xrefs",
                        buildQueryString(toAddrStr, fromAddrStr, refTypeStr));
                
                // Create result object
                Map<String, Object> result = new HashMap<>();
                if (toAddr != null) {
                    result.put("to_addr", toAddrStr);
                }
                if (fromAddr != null) {
                    result.put("from_addr", fromAddrStr);
                }
                result.put("references", paginatedRefs);
                
                // Add the result to the builder
                builder.result(result);
                
                // Add specific links
                if (toAddr != null) {
                    builder.addLink("to_function", "/functions/" + toAddrStr);
                }
                if (fromAddr != null) {
                    builder.addLink("from_function", "/functions/" + fromAddrStr);
                }
                
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
    
    private Map<String, Object> createReferenceMap(Program program, Reference ref, String direction) {
        Map<String, Object> refMap = new HashMap<>();
        
        // Basic reference information
        refMap.put("direction", direction);
        refMap.put("from_addr", ref.getFromAddress().toString());
        refMap.put("to_addr", ref.getToAddress().toString());
        refMap.put("refType", ref.getReferenceType().getName());
        refMap.put("isPrimary", ref.isPrimary());
        
        // Get source function (if any)
        Function fromFunc = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        if (fromFunc != null) {
            Map<String, Object> fromFuncMap = new HashMap<>();
            fromFuncMap.put("name", fromFunc.getName());
            fromFuncMap.put("address", fromFunc.getEntryPoint().toString());
            fromFuncMap.put("offset", ref.getFromAddress().subtract(fromFunc.getEntryPoint()));
            refMap.put("from_function", fromFuncMap);
        }

        // Get target function (if any)
        Function toFunc = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
        if (toFunc != null) {
            Map<String, Object> toFuncMap = new HashMap<>();
            toFuncMap.put("name", toFunc.getName());
            toFuncMap.put("address", toFunc.getEntryPoint().toString());
            toFuncMap.put("offset", ref.getToAddress().subtract(toFunc.getEntryPoint()));
            refMap.put("to_function", toFuncMap);
        }

        // Get source symbol (if any)
        SymbolTable symbolTable = program.getSymbolTable();
        Symbol[] fromSymbols = symbolTable.getSymbols(ref.getFromAddress());
        if (fromSymbols != null && fromSymbols.length > 0) {
            refMap.put("from_symbol", safeGetSymbolName(fromSymbols[0], program));
        }

        // Get target symbol (if any)
        Symbol[] toSymbols = symbolTable.getSymbols(ref.getToAddress());
        if (toSymbols != null && toSymbols.length > 0) {
            refMap.put("to_symbol", safeGetSymbolName(toSymbols[0], program));
        }
        
        // Get the instruction/data at the from address (if applicable)
        try {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(ref.getFromAddress());
            if (codeUnit != null) {
                refMap.put("from_instruction", codeUnit.toString());
            }
        } catch (Exception e) {
            // Ignore exceptions when getting code units
        }
        
        // Get the instruction/data at the to address (if applicable)
        try {
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(ref.getToAddress());
            if (codeUnit != null) {
                refMap.put("to_instruction", codeUnit.toString());
            }
        } catch (Exception e) {
            // Ignore exceptions when getting code units
        }
        
        return refMap;
    }
    
    private String buildQueryString(String toAddr, String fromAddr, String refType) {
        StringBuilder query = new StringBuilder();
        
        if (toAddr != null && !toAddr.isEmpty()) {
            query.append("to_addr=").append(toAddr);
        }
        
        if (fromAddr != null && !fromAddr.isEmpty()) {
            if (query.length() > 0) query.append("&");
            query.append("from_addr=").append(fromAddr);
        }
        
        if (refType != null && !refType.isEmpty()) {
            if (query.length() > 0) query.append("&");
            query.append("type=").append(refType);
        }
        
        return query.toString();
    }
    
    private Address getCurrentAddress(Program program) {
        if (program == null) return null;
        
        // Try to get current address from tool
        PluginTool tool = getTool();
        if (tool != null) {
            try {
                // Try to get the address from the code browser service (most reliable in Ghidra 11+)
                ghidra.app.services.CodeViewerService codeViewerService = 
                    tool.getService(ghidra.app.services.CodeViewerService.class);
                if (codeViewerService != null) {
                    ghidra.app.nav.Navigatable navigatable = codeViewerService.getNavigatable();
                    if (navigatable != null && navigatable.getProgram() == program) {
                        Address addr = navigatable.getLocation().getAddress();
                        if (addr != null) {
                            return addr;
                        }
                    }
                }
                
                // Try to get the address from the current listing using LocationService
                ghidra.app.services.ProgramManager programManager = 
                    tool.getService(ghidra.app.services.ProgramManager.class);
                if (programManager != null && programManager.getCurrentProgram() == program) {
                        // Try to get the current location using CurrentLocation service
                    try {
                        // Try to find the current location from the program manager
                        java.lang.reflect.Method getCurrentLocationMethod = 
                            programManager.getClass().getMethod("getCurrentLocation");
                        if (getCurrentLocationMethod != null) {
                            ghidra.program.util.ProgramLocation location = 
                                (ghidra.program.util.ProgramLocation)getCurrentLocationMethod.invoke(programManager);
                            if (location != null && location.getProgram() == program) {
                                return location.getAddress();
                            }
                        }
                    } catch (Exception e) {
                        // Method doesn't exist, ignore and continue with other approaches
                    }
                    
                    // If program is selected, use its memory address as a fallback
                    if (program.equals(programManager.getCurrentProgram())) {
                        ghidra.program.model.listing.Listing listing = program.getListing();
                        if (listing != null) {
                            // Return the first instruction or defined data we can find
                            ghidra.program.model.listing.InstructionIterator instructions = 
                                listing.getInstructions(true);
                            if (instructions.hasNext()) {
                                return instructions.next().getAddress();
                            }
                            
                            // Or try defined data
                            ghidra.program.model.listing.DataIterator data = 
                                listing.getDefinedData(true);
                            if (data.hasNext()) {
                                return data.next().getAddress();
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Msg.error(this, "Error getting current address from tool", e);
            }
        }
        
        // Fallback to program's min address
        return program.getMinAddress();
    }
}