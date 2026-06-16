package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.FunctionDto;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.app.services.CodeViewerService;
import ghidra.program.util.ProgramLocation;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Current-UI-state endpoints. /address and /function report the cursor
 * position and containing function in the active CodeBrowser window.
 */
public class UiResource implements Resource {

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/address", ctx -> currentAddress(contextFactory.apply(ctx)));
        app.get("/function", ctx -> currentFunction(contextFactory.apply(ctx)));
    }

    private void currentAddress(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CodeViewerService cv = ctx.tool().getService(CodeViewerService.class);
        ProgramLocation loc = cv != null ? cv.getCurrentLocation() : null;
        String address = loc != null
            ? loc.getAddress().toString()
            : program.getImageBase().toString();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", address);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/address")
            .link("program", "/program")
            .build());
    }

    private void currentFunction(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CodeViewerService cv = ctx.tool().getService(CodeViewerService.class);
        ProgramLocation loc = cv != null ? cv.getCurrentLocation() : null;
        if (loc == null) {
            throw new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "No current UI location", "NO_CURRENT_LOCATION");
        }
        final var address = loc.getAddress();
        FunctionDto dto = GhidraSwing.runRead(() -> {
            ghidra.program.model.listing.Function fn =
                program.getFunctionManager().getFunctionContaining(address);
            return FunctionDto.from(fn);
        });
        if (dto == null) {
            throw new eu.starsong.ghidra.server.GhydraServer.NotFoundException(
                "No function at current UI location: " + address, "FUNCTION_NOT_FOUND");
        }
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), dto)
            .self("/function")
            .link("program", "/program")
            .link("by_address", "/functions/{}", dto.address())
            .build());
    }
}
