package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.ScalarService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

/**
 * Search for scalar (constant) values in instructions: GET /scalars?value=...
 */
public class ScalarResource implements Resource {

    private final ScalarService service;

    public ScalarResource(ScalarService service) {
        this.service = service;
    }

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/scalars", ctx -> search(contextFactory.apply(ctx)));
    }

    private void search(GhidraContext ctx) {
        var program = ctx.requireProgram();

        String valueParam = ctx.queryParam("value");
        if (valueParam == null || valueParam.isEmpty()) {
            throw new IllegalArgumentException("value is required (hex 0x... or decimal)");
        }
        long target = parseScalar(valueParam);

        String inFunction = ctx.queryParam("in_function");
        String toFunction = ctx.queryParam("to_function");
        var pagination = ctx.pagination();
        int offset = pagination.offset();
        int limit = pagination.limit();

        ScalarService.Result result = service.search(program, target, inFunction, toFunction, offset, limit);

        String base = "/scalars?" + buildQuery(valueParam, inFunction, toFunction);
        Response resp = Response.ok(ctx.ctx(), ctx.port(), result.matches())
            .self(base + "&offset=" + offset + "&limit=" + limit)
            .meta("offset", offset)
            .meta("limit", limit)
            .meta("returned", result.matches().size())
            .meta("scanTruncated", result.truncated())
            .link("program", "/program");
        if (result.truncated()) {
            // The full scan hit its time budget before finishing; results are partial.
            resp.meta("note", "Scan stopped early to keep the UI responsive; results may be "
                + "incomplete. Narrow the search with in_function, or use a more specific value.");
        }
        // No total: the scan terminates early, so we expose forward/back paging via hasMore.
        if (result.hasMore()) {
            resp.link("next", base + "&offset=" + (offset + limit) + "&limit=" + limit);
        }
        if (offset > 0) {
            resp.link("prev", base + "&offset=" + Math.max(0, offset - limit) + "&limit=" + limit);
        }
        ctx.json(resp.build());
    }

    private static String buildQuery(String value, String inFunction, String toFunction) {
        StringBuilder sb = new StringBuilder("value=").append(enc(value));
        if (inFunction != null && !inFunction.isEmpty()) {
            sb.append("&in_function=").append(enc(inFunction));
        }
        if (toFunction != null && !toFunction.isEmpty()) {
            sb.append("&to_function=").append(enc(toFunction));
        }
        return sb.toString();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /**
     * Parse a scalar value: hex ({@code 0x...} / {@code -0x...}) or decimal. Hex uses an
     * unsigned parse so a full-width pattern (e.g. 0xFFFFFFFFFFFFFFFF) maps to its bit value.
     */
    private static long parseScalar(String s) {
        s = s.trim();
        try {
            String low = s.toLowerCase();
            if (low.startsWith("0x")) {
                return Long.parseUnsignedLong(s.substring(2), 16);
            }
            if (low.startsWith("-0x")) {
                return -Long.parseLong(s.substring(3), 16);
            }
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid scalar value: " + s + " (use hex 0x... or decimal)");
        }
    }
}
