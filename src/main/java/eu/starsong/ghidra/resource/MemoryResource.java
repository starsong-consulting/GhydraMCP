package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.MemoryBlockDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.MemoryService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * REST resource for /memory endpoints.
 */
public class MemoryResource implements Resource {

    private final MemoryService memoryService;

    public MemoryResource() {
        this.memoryService = new MemoryService();
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/memory", ctx -> listBlocks(contextFactory.apply(ctx)));
        app.get("/memory/{address}", ctx -> readMemory(contextFactory.apply(ctx)));
        app.get("/memory/search", ctx -> searchMemory(contextFactory.apply(ctx)));
    }

    /**
     * GET /memory - List all memory blocks
     */
    private void listBlocks(GhidraContext ctx) {
        var program = ctx.requireProgram();

        List<MemoryBlockDto> blocks = memoryService.listBlocks(program);

        var result = Paginator.paginate(blocks, ctx.pagination(), "/memory")
            .withItemLinks(block -> Links.builder()
                .self("/memory/{}", block.start())
                .build());

        ctx.json(result.toResponse()
            .link("program", "/program")
            .link("segments", "/segments")
            .build());
    }

    /**
     * GET /memory/{address} - Read memory at address
     */
    private void readMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        int length = ctx.queryParamAsInt("length", 256);
        String format = ctx.queryParam("format", "hex");

        // Limit read size
        if (length > 4096) {
            length = 4096;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", address);
        result.put("length", length);

        if ("hex".equals(format)) {
            String hex = memoryService.readBytesAsHex(program, address, length);
            result.put("hex", hex);
        } else {
            byte[] bytes = memoryService.readBytes(program, address, length);
            int[] byteArray = new int[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                byteArray[i] = bytes[i] & 0xff;
            }
            result.put("bytes", byteArray);
        }

        // Get block info
        try {
            MemoryBlockDto block = memoryService.getBlockContaining(program, address);
            result.put("block", block.name());
            result.put("permissions", block.permissions());
        } catch (Exception e) {
            // Ignore if can't get block info
        }

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/memory/{}?length={}", address, length)
            .link("memory", "/memory")
            .build());
    }

    /**
     * GET /memory/search - Search for bytes in memory
     */
    private void searchMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String hexPattern = ctx.queryParam("pattern");
        int maxResults = ctx.queryParamAsInt("max", 100);

        if (hexPattern == null || hexPattern.isEmpty()) {
            throw new IllegalArgumentException("pattern query parameter is required");
        }

        // Parse hex string to bytes
        byte[] pattern = hexStringToBytes(hexPattern);

        List<String> results = memoryService.searchBytes(program, pattern, maxResults);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("pattern", hexPattern);
        data.put("matches", results);
        data.put("count", results.size());

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/memory/search?pattern={}", hexPattern)
            .link("memory", "/memory")
            .build());
    }

    private byte[] hexStringToBytes(String hex) {
        hex = hex.replaceAll("\\s", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
