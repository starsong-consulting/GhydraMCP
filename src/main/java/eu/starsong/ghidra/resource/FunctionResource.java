package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.DecompileResultDto;
import eu.starsong.ghidra.dto.DisassemblyInstructionDto;
import eu.starsong.ghidra.dto.FunctionDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.DecompilerService;
import eu.starsong.ghidra.service.FunctionService;
import eu.starsong.ghidra.service.FunctionService.FunctionFilter;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.program.model.listing.Function;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.List;
import java.util.Map;

public class FunctionResource implements Resource {

    private final FunctionService functionService;
    private final DecompilerService decompilerService;

    public FunctionResource() {
        this.functionService = new FunctionService();
        this.decompilerService = new DecompilerService(functionService);
    }

    public FunctionResource(FunctionService functionService, DecompilerService decompilerService) {
        this.functionService = functionService;
        this.decompilerService = decompilerService;
    }

    @Override
    public void register(Javalin app, java.util.function.Function<Context, GhidraContext> contextFactory) {
        // By-address routes
        app.get("/functions", ctx -> list(contextFactory.apply(ctx)));
        app.post("/functions", ctx -> create(contextFactory.apply(ctx)));
        app.get("/functions/{address}", ctx -> getByAddress(contextFactory.apply(ctx)));
        app.patch("/functions/{address}", ctx -> update(contextFactory.apply(ctx)));
        app.delete("/functions/{address}", ctx -> delete(contextFactory.apply(ctx)));
        app.get("/functions/{address}/decompile", ctx -> decompile(contextFactory.apply(ctx)));
        app.get("/functions/{address}/disassembly", ctx -> disassembly(contextFactory.apply(ctx)));
        app.get("/functions/{address}/variables", ctx -> variables(contextFactory.apply(ctx)));
        app.patch("/functions/{address}/variables/{varName}", ctx -> updateVariable(contextFactory.apply(ctx)));

        // By-name routes
        app.get("/functions/by-name/{name}", ctx -> getByName(contextFactory.apply(ctx)));
        app.patch("/functions/by-name/{name}", ctx -> updateByName(contextFactory.apply(ctx)));
        app.delete("/functions/by-name/{name}", ctx -> deleteByName(contextFactory.apply(ctx)));
        app.get("/functions/by-name/{name}/decompile", ctx -> decompileByName(contextFactory.apply(ctx)));
        app.get("/functions/by-name/{name}/disassembly", ctx -> disassemblyByName(contextFactory.apply(ctx)));
        app.get("/functions/by-name/{name}/variables", ctx -> variablesByName(contextFactory.apply(ctx)));
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        String containingAddr = ctx.queryParam("containing_addr");
        String afterAddr = ctx.queryParam("after");
        String beforeAddr = ctx.queryParam("before");

        // Short-circuit single-result lookups (containing/after/before).
        if (containingAddr != null || afterAddr != null || beforeAddr != null) {
            Function fn;
            if (containingAddr != null) {
                fn = functionService.findContaining(program, containingAddr);
            } else if (afterAddr != null) {
                fn = functionService.findNext(program, afterAddr);
            } else {
                fn = functionService.findPrev(program, beforeAddr);
            }
            // Building the DTO reads the stored signature/return type; keep it on the EDT.
            final Function found = fn;
            List<FunctionSummaryDto> single = found != null
                ? List.of(GhidraSwing.runRead(() -> {
                    return FunctionSummaryDto.from(found);
                })) : List.of();
            var single_result = Paginator.paginate(single, pagination, "/functions")
                .withItemLinks(s -> Links.builder()
                    .self("/functions/{}", s.address()).build());
            ctx.json(single_result.toResponse(ctx.ctx(), ctx.port()).link("program", "/program").build());
            return;
        }

        FunctionFilter filter = FunctionFilter.fromQueryParams(
            ctx.queryParam("name"),
            ctx.queryParam("name_contains"),
            ctx.queryParam("name_matches_regex"),
            ctx.queryParam("is_external"),
            ctx.queryParam("is_thunk"),
            ctx.queryParam("addr_min"),
            ctx.queryParam("addr_max")
        );

        List<FunctionSummaryDto> functions = functionService.list(program, filter);
        var result = Paginator.paginate(functions, pagination, "/functions")
            .withItemLinks(fn -> Links.builder()
                .self("/functions/{}", fn.address())
                .link("decompile", "/functions/{}/decompile", fn.address())
                .build());

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("program", "/program")
            .linkWithMethod("create", "/functions", "POST")
            .build());
    }

    private void getByAddress(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        FunctionDto fn = functionService.requireByAddress(program, address);
        ctx.json(functionResponse(ctx, fn, address).build());
    }

    private void getByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        FunctionDto fn = functionService.requireByName(program, name);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), fn)
            .self("/functions/by-name/{}", name)
            .link("by_address", "/functions/{}", fn.address())
            .link("decompile", "/functions/{}/decompile", fn.address())
            .link("disassembly", "/functions/{}/disassembly", fn.address())
            .link("variables", "/functions/{}/variables", fn.address())
            .build());
    }

    private void decompile(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        int timeout = ctx.queryParamAsInt("timeout", 60);
        DecompileResultDto result = decompilerService.decompile(program, address, timeout);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/functions/{}/decompile", address)
            .link("function", "/functions/{}", address)
            .build());
    }

    private void decompileByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        int timeout = ctx.queryParamAsInt("timeout", 60);
        DecompileResultDto result = decompilerService.decompileByName(program, name, timeout);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
            .self("/functions/by-name/{}/decompile", name)
            .link("function", "/functions/by-name/{}", name)
            .build());
    }

    private void disassembly(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        Function fn = functionService.requireFunctionByAddress(program, address);
        respondDisassembly(ctx, program, fn, "/functions/" + address + "/disassembly");
    }

    private void disassemblyByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        Function fn = functionService.requireFunctionByName(program, name);
        respondDisassembly(ctx, program, fn, "/functions/by-name/" + name + "/disassembly");
    }

    private void respondDisassembly(GhidraContext ctx, ghidra.program.model.listing.Program program,
                                    Function fn, String basePath) {
        var pagination = ctx.pagination();
        List<DisassemblyInstructionDto> instructions = functionService.disassemble(program, fn);
        Map<String, Object> fnMeta = GhidraSwing.runRead(() -> {
            return Map.<String, Object>of(
                "name", fn.getName(),
                "address", fn.getEntryPoint().toString(),
                "signature", fn.getSignature().toString());
        });
        String entryPoint = (String) fnMeta.get("address");
        var result = Paginator.paginate(instructions, pagination, basePath);
        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .meta("function", fnMeta)
            .link("function", "/functions/{}", entryPoint)
            .link("decompile", "/functions/{}/decompile", entryPoint)
            .build());
    }

    private void variables(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        Function fn = functionService.requireFunctionByAddress(program, address);
        respondVariables(ctx, fn, "/functions/" + address + "/variables");
    }

    private void variablesByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        Function fn = functionService.requireFunctionByName(program, name);
        respondVariables(ctx, fn, "/functions/by-name/" + name + "/variables");
    }

    private void respondVariables(GhidraContext ctx, Function fn, String selfPath) {
        // getFunctionVariables splits internally: DB reads on the EDT, decompiler off it.
        // Do NOT wrap this call in runRead (it would drag the decompiler onto the EDT).
        List<Map<String, Object>> vars = GhidraUtil.getFunctionVariables(fn);
        FunctionRef ref = GhidraSwing.runRead(() -> {
            return new FunctionRef(fn.getName(), fn.getEntryPoint().toString());
        });
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of(
                "function", Map.of(
                    "name", ref.name(),
                    "address", ref.address()),
                "variables", vars))
            .self(selfPath)
            .link("function", "/functions/{}", ref.address())
            .link("decompile", "/functions/{}/decompile", ref.address())
            .build());
    }

    private record FunctionRef(String name, String address) {
    }

    private void updateVariable(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        String varName = ctx.pathParam("varName");
        Function fn = functionService.requireFunctionByAddress(program, address);
        UpdateVariableRequest req = ctx.bodyAsClass(UpdateVariableRequest.class);
        if (req.name == null && req.dataType == null && req.data_type == null) {
            throw new IllegalArgumentException("Missing update parameters — name or data_type required");
        }
        String newType = req.dataType != null ? req.dataType : req.data_type;
        try {
            boolean ok = functionService.updateLocalVariable(program, fn, varName, req.name, newType);
            if (!ok) {
                throw new NotFoundException("Variable not found: " + varName, "VARIABLE_NOT_FOUND");
            }
            FunctionRef ref = GhidraSwing.runRead(() -> {
                return new FunctionRef(fn.getName(), fn.getEntryPoint().toString());
            });
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of(
                    "function", ref.name(),
                    "address", ref.address(),
                    "name", req.name != null ? req.name : varName))
                .self("/functions/{}/variables/{}", address, varName)
                .link("variables", "/functions/{}/variables", address)
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to update variable: " + e.getMessage(), e);
        }
    }

    private void update(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        UpdateRequest req = ctx.bodyAsClass(UpdateRequest.class);
        try {
            FunctionDto fn = applyUpdate(program, address, req);
            ctx.json(functionResponse(ctx, fn, address).build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to update function: " + e.getMessage(), e);
        }
    }

    private void updateByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        Function fn = functionService.requireFunctionByName(program, name);
        UpdateRequest req = ctx.bodyAsClass(UpdateRequest.class);
        String address = fn.getEntryPoint().toString();
        try {
            FunctionDto updated = applyUpdate(program, address, req);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), updated)
                .self("/functions/by-name/{}", updated.name())
                .link("by_address", "/functions/{}", updated.address())
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to update function: " + e.getMessage(), e);
        }
    }

    private FunctionDto applyUpdate(ghidra.program.model.listing.Program program, String address, UpdateRequest req) throws Exception {
        FunctionDto fn = functionService.requireByAddress(program, address);
        if (req.signature != null && !req.signature.isEmpty()) {
            fn = functionService.setSignature(program, address, req.signature);
        }
        if (req.name != null && !req.name.isEmpty()) {
            fn = functionService.rename(program, address, req.name);
        }
        if (req.comment != null) {
            fn = functionService.setComment(program, address, req.comment);
        }
        return fn;
    }

    private void delete(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        try {
            functionService.delete(program, address);
            ctx.status(204);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete function: " + e.getMessage(), e);
        }
    }

    private void deleteByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");
        Function fn = functionService.requireFunctionByName(program, name);
        try {
            functionService.delete(program, fn.getEntryPoint().toString());
            ctx.status(204);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete function: " + e.getMessage(), e);
        }
    }

    private void create(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CreateRequest request = ctx.bodyAsClass(CreateRequest.class);
        if (request.address == null || request.address.isEmpty()) {
            throw new IllegalArgumentException("Address is required");
        }
        try {
            FunctionDto fn = functionService.create(
                program, request.address,
                request.name != null ? request.name : "FUN_" + request.address);
            ctx.status(201);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), fn)
                .self("/functions/{}", fn.address())
                .link("program", "/program")
                .link("decompile", "/functions/{}/decompile", fn.address())
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create function: " + e.getMessage(), e);
        }
    }

    private Response functionResponse(GhidraContext ctx, FunctionDto fn, String address) {
        return Response.ok(ctx.ctx(), ctx.port(), fn)
            .self("/functions/{}", address)
            .link("program", "/program")
            .link("decompile", "/functions/{}/decompile", address)
            .link("disassembly", "/functions/{}/disassembly", address)
            .link("variables", "/functions/{}/variables", address)
            .link("xrefs_to", "/xrefs?to_addr={}", address)
            .link("xrefs_from", "/xrefs?from_addr={}", address)
            .link("by_name", "/functions/by-name/{}", fn.name());
    }

    private static class UpdateRequest {
        public String name;
        public String comment;
        public String signature;
    }

    private static class CreateRequest {
        public String address;
        public String name;
    }

    private static class UpdateVariableRequest {
        public String name;
        public String dataType;
        public String data_type;  // bridge sends snake_case
    }
}
