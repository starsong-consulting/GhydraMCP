package eu.starsong.ghidra.endpoints;

    import com.google.gson.JsonObject;
    import com.sun.net.httpserver.HttpExchange;
    import com.sun.net.httpserver.HttpServer;
    import eu.starsong.ghidra.api.ResponseBuilder;
    import ghidra.framework.plugintool.PluginTool;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.mem.MemoryBlock;
    import ghidra.util.Msg;

    import java.io.IOException;
    import java.util.*;

    public class SegmentEndpoints extends AbstractEndpoint {

        private PluginTool tool;

        // Updated constructor to accept port
        public SegmentEndpoints(Program program, int port) {
            super(program, port); // Call super constructor
        }

        public SegmentEndpoints(Program program, int port, PluginTool tool) {
            super(program, port);
            this.tool = tool;
        }

        @Override
        protected PluginTool getTool() {
            return tool;
        }

        @Override
        public void registerEndpoints(HttpServer server) {
            server.createContext("/segments", this::handleSegments);
        }

        public void handleSegments(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equals(exchange.getRequestMethod())) {
                    Map<String, String> qparams = parseQueryParams(exchange);
                    int offset = parseIntOrDefault(qparams.get("offset"), 0);
                    int limit = parseIntOrDefault(qparams.get("limit"), 100);
                    String nameFilter = qparams.get("name");

                    Program program = getCurrentProgram();
                    if (program == null) {
                        sendErrorResponse(exchange, 400, "No program loaded", "NO_PROGRAM_LOADED");
                        return;
                    }

                    List<Map<String, Object>> segments = new ArrayList<>();
                    for (MemoryBlock block : program.getMemory().getBlocks()) {
                        // Apply name filter if present
                        if (nameFilter != null && !block.getName().contains(nameFilter)) {
                            continue;
                        }

                        Map<String, Object> segment = new HashMap<>();
                        segment.put("name", block.getName());
                        segment.put("start", block.getStart().toString());
                        segment.put("end", block.getEnd().toString());
                        segment.put("size", block.getSize());

                        // Add permissions
                        segment.put("readable", block.isRead());
                        segment.put("writable", block.isWrite());
                        segment.put("executable", block.isExecute());
                        segment.put("initialized", block.isInitialized());

                        // Add HATEOAS links for this segment
                        Map<String, Object> links = new HashMap<>();
                        Map<String, String> selfLink = new HashMap<>();
                        selfLink.put("href", "/segments/" + block.getName());
                        links.put("self", selfLink);

                        Map<String, String> memoryLink = new HashMap<>();
                        memoryLink.put("href", "/memory/" + block.getStart());
                        links.put("memory", memoryLink);

                        segment.put("_links", links);

                        segments.add(segment);
                    }

                    // Build response with HATEOAS links
                    ResponseBuilder builder = new ResponseBuilder(exchange, port)
                        .success(true);

                    // Handle optional name filter
                    String queryParams = nameFilter != null ? "name=" + nameFilter : null;

                    // Apply pagination and get paginated items
                    List<Map<String, Object>> paginatedSegments = applyPagination(
                        segments, offset, limit, builder, "/segments", queryParams);

                    // Set the paginated result
                    builder.result(paginatedSegments);

                    // Add program link
                    builder.addLink("program", "/program");

                    sendJsonResponse(exchange, builder.build(), 200);
                } else {
                    sendErrorResponse(exchange, 405, "Method Not Allowed", "METHOD_NOT_ALLOWED");
                }
            } catch (Exception e) {
                Msg.error(this, "Error in /segments endpoint", e);
                sendErrorResponse(exchange, 500, "Internal server error: " + e.getMessage(), "INTERNAL_ERROR");
            }
        }

        // parseIntOrDefault is inherited from AbstractEndpoint
    }
