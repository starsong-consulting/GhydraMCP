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

    /** Free all emulator sessions; called on plugin teardown to avoid leaking EmulatorHelpers. */
    public void dispose() {
        service.disposeAll();
    }

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
        app.post("/emulation/hooks", ctx -> setHook(contextFactory.apply(ctx)));
        app.delete("/emulation/hooks/{address}", ctx -> clearHook(contextFactory.apply(ctx)));
        app.get("/emulation/hooks", ctx -> listHooks(contextFactory.apply(ctx)));
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
        respond(ctx, service.reset(program, req.start, req.registers, mem, req.auto_stack));
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
        // The service owns the count<=0 -> 1 clamp; don't duplicate it here.
        respond(ctx, service.step(program, req.count, req.trace));
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
        String hex = service.readMemory(program, address, length);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("address", address);
        // Report the actual byte count returned (the service clamps to 4096), not the request.
        data.put("length", hex.length() / 2);
        data.put("hex", hex);
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

    private void setHook(GhidraContext ctx) {
        var program = ctx.requireProgram();
        HookRequest req = ctx.bodyAsClass(HookRequest.class);
        if (req == null || req.address == null || req.action == null) {
            throw new IllegalArgumentException("address and action are required");
        }
        List<EmulationService.MemWrite> mem = new ArrayList<>();
        if (req.mem_writes != null) {
            for (Map<String, String> m : req.mem_writes) {
                mem.add(new EmulationService.MemWrite(m.get("address"), m.get("hex")));
            }
        }
        service.setHook(program, req.address, new EmulationService.HookAction(req.action, req.return_value, mem));
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of("address", req.address, "hook", "set")).build());
    }

    private void clearHook(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        service.clearHook(program, address);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of("address", address, "hook", "cleared")).build());
    }

    private void listHooks(GhidraContext ctx) {
        var program = ctx.requireProgram();
        Map<String, EmulationService.HookAction> hooks = service.listHooks(program);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of("hooks", hooks)).build());
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
        public boolean auto_stack;
    }
    private static class RunRequest { public String until; public long max_steps; public boolean trace; }
    private static class StepRequest { public long count; public boolean trace; }
    private static class RegisterRequest { public String name; public String value; }
    private static class MemoryRequest { public String address; public String hex; }
    private static class BreakpointRequest { public String address; }
    private static class HookRequest { 
        public String address; 
        public String action; 
        public String return_value; 
        public List<Map<String, String>> mem_writes; 
    }
}
