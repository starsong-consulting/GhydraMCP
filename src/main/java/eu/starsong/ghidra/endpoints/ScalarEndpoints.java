package eu.starsong.ghidra.endpoints;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

import eu.starsong.ghidra.model.ScalarInfo;

import java.io.IOException;
import java.util.*;

/**
 * Endpoints for searching scalar (constant) values in the binary.
 * Similar to Ghidra's "Search For Scalar" functionality.
 */
public class ScalarEndpoints extends AbstractEndpoint {

    private PluginTool tool;

    public ScalarEndpoints(Program program, int port) {
        super(program, port);
    }

    public ScalarEndpoints(Program program, int port, PluginTool tool) {
        super(program, port);
        this.tool = tool;
    }

    @Override
    protected PluginTool getTool() {
        return tool;
    }

    @Override
    public void registerEndpoints(HttpServer server) {
        server.createContext("/scalars", this::handleScalars);
    }

    /**
     * Handle GET /scalars?value=X - Search for occurrences of a specific scalar
     * value
     *
     * Query parameters:
     * - value: The scalar value to search for (required, hex 0x... or decimal)
     * - in_function: Filter to only include results in functions whose name contains this substring (case-insensitive)
     * - offset: Pagination offset (default: 0)
     * - limit: Maximum items to return (default: 100)
     */
    public void handleScalars(HttpExchange exchange) throws IOException {
        try {
            if ("GET".equals(exchange.getRequestMethod())) {
                Map<String, String> qparams = parseQueryParams(exchange);
                int offset = parseIntOrDefault(qparams.get("offset"), 0);
                int limit = parseIntOrDefault(qparams.get("limit"), 100);

                // Value is required
                String valueParam = qparams.get("value");
                if (valueParam == null || valueParam.isEmpty()) {
                    sendErrorResponse(exchange, 400, "Missing required parameter: value", "MISSING_PARAMETER");
                    return;
                }

                // Optional function filter (filters by the containing function's name)
                String inFunction = qparams.get("in_function");

                Long targetValue = parseScalarValue(valueParam);
                if (targetValue == null) {
                    sendErrorResponse(exchange, 400, "Invalid value format: " + valueParam, "INVALID_PARAMETER");
                    return;
                }

                Program program = getCurrentProgram();
                if (program == null) {
                    sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                    return;
                }

                // Find scalars with early termination (skip offset, collect limit + 1 to check
                // hasMore)
                FindScalarResult findResult = findScalar(program, targetValue, inFunction, offset, limit);

                // Build response with HATEOAS links
                eu.starsong.ghidra.api.ResponseBuilder builder = new eu.starsong.ghidra.api.ResponseBuilder(exchange,
                        port)
                        .success(true);

                // Set the result
                builder.result(findResult.results);

                // Add pagination metadata
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("offset", offset);
                metadata.put("limit", limit);
                metadata.put("returned", findResult.results.size());
                builder.metadata(metadata);

                // Add pagination links
                String baseParams = "value=" + valueParam;
                if (inFunction != null && !inFunction.isEmpty()) {
                    baseParams += "&in_function=" + inFunction;
                }
                builder.addLink("self", "/scalars?" + baseParams + "&offset=" + offset + "&limit=" + limit);

                if (findResult.hasMore) {
                    builder.addLink("next",
                            "/scalars?" + baseParams + "&offset=" + (offset + limit) + "&limit=" + limit);
                }

                if (offset > 0) {
                    int prevOffset = Math.max(0, offset - limit);
                    builder.addLink("prev", "/scalars?" + baseParams + "&offset=" + prevOffset + "&limit=" + limit);
                }

                // Add useful links
                builder.addLink("program", "/program");

                sendJsonResponse(exchange, builder.build(), 200);
            } else {
                sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
            }
        } catch (Exception e) {
            Msg.error(this, "Error in /scalars endpoint", e);
            sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
        }
    }

    /**
     * Result container for findScalar with pagination info
     */
    private static class FindScalarResult {
        List<ScalarInfo> results;
        boolean hasMore;

        FindScalarResult(List<ScalarInfo> results, boolean hasMore) {
            this.results = results;
            this.hasMore = hasMore;
        }
    }

    /**
     * Find occurrences of a scalar value with offset/limit for pagination.
     * Uses early termination for performance.
     *
     * @param program          The program to search
     * @param targetValue      The scalar value to find
     * @param inFunction       Filter to only include results in functions whose name contains this substring (case-insensitive), or null for no filter
     * @param offset           Number of results to skip
     * @param limit            Maximum results to return
     * @return FindScalarResult containing results and hasMore flag
     */
    private FindScalarResult findScalar(Program program, long targetValue, String inFunction, int offset, int limit) {
        List<ScalarInfo> results = new ArrayList<>();
        Listing listing = program.getListing();
        int skipped = 0;
        int collected = 0;
        boolean hasMore = false;
        String functionFilter = (inFunction != null && !inFunction.isEmpty())
            ? inFunction.toLowerCase() : null;

        // Iterate through all memory blocks
        outerLoop: for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized())
                continue;

            // Iterate through all instructions in the block
            InstructionIterator instructions = listing.getInstructions(block.getStart(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                Address instrAddr = instruction.getAddress();

                // Stop if we're past the current block
                if (!block.contains(instrAddr))
                    break;

                // Check all operands for the target scalar
                int numOperands = instruction.getNumOperands();
                for (int opIndex = 0; opIndex < numOperands; opIndex++) {
                    Object[] opObjects = instruction.getOpObjects(opIndex);
                    for (Object opObj : opObjects) {
                        if (opObj instanceof Scalar) {
                            Scalar scalar = (Scalar) opObj;
                            if (scalar.getValue() == targetValue) {
                                ghidra.program.model.listing.Function func = listing.getFunctionContaining(instrAddr);

                                // Filter scalar usage according to the function using it.
                                if (functionFilter != null) {
                                    if (func == null) continue;
                                    if (!func.getName(true).toLowerCase().contains(functionFilter)) {
                                        continue;
                                    }
                                }

                                // Skip until we reach offset
                                if (skipped < offset) {
                                    skipped++;
                                    continue;
                                }

                                // Check if we've collected enough (collect one extra to detect hasMore)
                                if (collected >= limit) {
                                    hasMore = true;
                                    break outerLoop;
                                }

                                // Build the result using ScalarInfo model
                                ScalarInfo.Builder builder = ScalarInfo.builder()
                                    .address(instrAddr.toString())
                                    .value(targetValue)
                                    .bitLength(scalar.bitLength())
                                    .signed(scalar.isSigned())
                                    .operandIndex(opIndex)
                                    .instruction(instruction.toString());

                                // Add function context if available
                                if (func != null) {
                                    builder.function(func.getName(true))
                                           .functionAddress(func.getEntryPoint().toString());
                                }

                                results.add(builder.build());
                                collected++;
                            }
                        }
                    }
                }
            }
        }

        return new FindScalarResult(results, hasMore);
    }

    /**
     * Parse a scalar value string that can be hex (0x...) or decimal
     */
    private Long parseScalarValue(String valueStr) {
        if (valueStr == null || valueStr.isEmpty()) {
            return null;
        }

        try {
            valueStr = valueStr.trim();
            if (valueStr.toLowerCase().startsWith("0x")) {
                return Long.parseLong(valueStr.substring(2), 16);
            } else if (valueStr.toLowerCase().startsWith("-0x")) {
                return -Long.parseLong(valueStr.substring(3), 16);
            } else {
                return Long.parseLong(valueStr);
            }
        } catch (NumberFormatException e) {
            Msg.warn(this, "Failed to parse scalar value: " + valueStr);
            return null;
        }
    }
}
