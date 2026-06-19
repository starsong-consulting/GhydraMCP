package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.EmulationStateDto;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.EmulationService;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** REST resource for /emulation endpoints (PCode emulation). */
public class EmulationResource implements Resource {

    private final EmulationService service = new EmulationService();

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.post("/emulation/reset", ctx -> reset(contextFactory.apply(ctx)));
        app.post("/emulation/run", ctx -> run(contextFactory.apply(ctx)));
        app.post("/emulation/step", ctx -> step(contextFactory.apply(ctx)));
        app.get("/emulation/state", ctx -> state(contextFactory.apply(ctx)));
        app.get("/emulation/registers/{name}", ctx -> readRegister(contextFactory.apply(ctx)));
        app.post("/emulation/registers", ctx -> writeRegister(contextFactory.apply(ctx)));
        app.get("/emulation/memory/{address}", ctx -> readMemory(contextFactory.apply(ctx)));
        app.post("/emulation/memory", ctx -> writeMemory(contextFactory.apply(ctx)));
        app.post("/emulation/breakpoints", ctx -> setBreakpoint(contextFactory.apply(ctx)));
        app.delete("/emulation/breakpoints/{address}", ctx -> clearBreakpoint(contextFactory.apply(ctx)));
        app.delete("/emulation", ctx -> dispose(contextFactory.apply(ctx)));
    }

    private void respond(GhidraContext ctx, EmulationStateDto dto) {
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), dto)
            .self("/emulation/state")
            .link("emulation", "/emulation/state")
            .build());
    }

    private void reset(GhidraContext ctx) {
        var program = ctx.requireProgram();
        ResetRequest req = ctx.bodyAsClass(ResetRequest.class);
        if (req == null || req.start == null) throw new IllegalArgumentException("start is required");
        List<EmulationService.MemWrite> mem = new ArrayList<>();
        if (req.memory != null) {
            for (Map<String, String> m : req.memory) {
                mem.add(new EmulationService.MemWrite(m.get("address"), m.get("hex")));
            }
        }
        respond(ctx, service.reset(program, req.start, req.registers, mem));
    }

    private void run(GhidraContext ctx) {
        var program = ctx.requireProgram();
        RunRequest req = ctx.bodyAsClass(RunRequest.class);
        if (req == null) req = new RunRequest();
        respond(ctx, service.run(program, req.until, req.max_steps, req.trace));
    }

    private void step(GhidraContext ctx) {
        var program = ctx.requireProgram();
        StepRequest req = ctx.bodyAsClass(StepRequest.class);
        if (req == null) req = new StepRequest();
        respond(ctx, service.step(program, req.count <= 0 ? 1 : req.count, req.trace));
    }

    private void state(GhidraContext ctx) {
        respond(ctx, service.state(ctx.requireProgram()));
    }

    private void readRegister(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", name);
        data.put("value", service.readRegister(program, name));
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/registers/{}", name).build());
    }

    private void writeRegister(GhidraContext ctx) {
        var program = ctx.requireProgram();
        RegisterRequest req = ctx.bodyAsClass(RegisterRequest.class);
        if (req == null || req.name == null || req.value == null) {
            throw new IllegalArgumentException("name and value are required");
        }
        service.writeRegister(program, req.name, req.value);
        respond(ctx, service.state(program));
    }

    private void readMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        int length = ctx.queryParamAsInt("length", 256);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", address);
        data.put("length", length);
        data.put("hex", service.readMemory(program, address, length));
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/memory/{}", address).build());
    }

    private void writeMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        MemoryRequest req = ctx.bodyAsClass(MemoryRequest.class);
        if (req == null || req.address == null || req.hex == null) {
            throw new IllegalArgumentException("address and hex are required");
        }
        int written = service.writeMemory(program, req.address, req.hex);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", req.address);
        data.put("written", written);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/memory/{}", req.address).build());
    }

    private void setBreakpoint(GhidraContext ctx) {
        var program = ctx.requireProgram();
        BreakpointRequest req = ctx.bodyAsClass(BreakpointRequest.class);
        if (req == null || req.address == null) throw new IllegalArgumentException("address is required");
        service.setBreakpoint(program, req.address);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", req.address);
        data.put("breakpoint", "set");
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/breakpoints").build());
    }

    private void clearBreakpoint(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        service.clearBreakpoint(program, address);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", address);
        data.put("breakpoint", "cleared");
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation/breakpoints/{}", address).build());
    }

    private void dispose(GhidraContext ctx) {
        service.dispose(ctx.requireProgram());
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("session", "disposed");
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data).self("/emulation").build());
    }

    private static class ResetRequest {
        public String start;
        public Map<String, String> registers;
        public List<Map<String, String>> memory;
    }
    private static class RunRequest { public String until; public long max_steps; public boolean trace; }
    private static class StepRequest { public long count; public boolean trace; }
    private static class RegisterRequest { public String name; public String value; }
    private static class MemoryRequest { public String address; public String hex; }
    private static class BreakpointRequest { public String address; }
}
