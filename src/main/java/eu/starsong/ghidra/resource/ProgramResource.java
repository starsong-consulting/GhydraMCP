package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.service.MemoryService;
import eu.starsong.ghidra.service.SaveService;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * REST resource for /program and /programs endpoints.
 */
public class ProgramResource implements Resource {

    private final MemoryService memoryService = new MemoryService();
    private final SaveService saveService = new SaveService();

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/program", ctx -> getCurrentProgram(contextFactory.apply(ctx)));
        app.get("/programs", ctx -> listPrograms(contextFactory.apply(ctx)));
        app.get("/programs/current", ctx -> getCurrentProgram(contextFactory.apply(ctx)));
        app.patch("/programs/current/memory/{address}", ctx -> writeMemory(contextFactory.apply(ctx)));
        // Persist analysis. ?all=true saves every open program with unsaved changes.
        app.post("/program/save", ctx -> saveProgram(contextFactory.apply(ctx)));
        app.post("/programs/save", ctx -> saveProgram(contextFactory.apply(ctx)));
    }

    private void saveProgram(GhidraContext ctx) {
        boolean all = "true".equalsIgnoreCase(ctx.queryParam("all"));
        try {
            Object result = all
                ? saveService.saveAllChanged(ctx.tool())
                : saveService.save(ctx.requireProgram());
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), result)
                .self("/program/save")
                .link("program", "/program")
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to save program: " + e.getMessage(), e);
        }
    }

    private void writeMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        MemoryWriteRequest req = ctx.bodyAsClass(MemoryWriteRequest.class);
        try {
            int written = memoryService.writeBytes(program, address, req.bytes);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of(
                    "address", address,
                    "bytesWritten", written))
                .self("/programs/current/memory/{}", address)
                .link("memory", "/memory/{}", address)
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to write memory: " + e.getMessage(), e);
        }
    }

    private static class MemoryWriteRequest {
        public String bytes;
        public String format; // unused in simple hex-only handler
    }

    /**
     * GET /program or /programs/current - Get current program info
     */
    private void getCurrentProgram(GhidraContext ctx) {
        // TODO: extract this into ProgramInfoDto once the dual field names
        // (language/languageId, compiler/compilerSpecId) are decided — pick one
        // set and drop the other, then the flat map goes away.
        Program program = ctx.requireProgram();

        // Assembling this snapshot touches many DB facets (language, compiler, address
        // factory, function manager, symbol table, memory blocks). Run the whole build
        // on the EDT so the compound read doesn't interleave with UI activity.
        Map<String, Object> data = GhidraSwing.runRead(() -> {
            // programId uses main's "project:/path" shape so the bridge can split it.
            String projectName = program.getDomainFile().getProjectLocator() != null
                ? program.getDomainFile().getProjectLocator().getName() : "";
            String programId = projectName + ":" + program.getDomainFile().getPathname();

            Map<String, Object> d = new LinkedHashMap<>();
            d.put("name", program.getName());
            d.put("programId", programId);
            d.put("path", program.getExecutablePath());
            d.put("language", program.getLanguageID().getIdAsString());
            d.put("languageId", program.getLanguageID().getIdAsString());
            d.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            d.put("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
            d.put("processor", program.getLanguage().getProcessor().toString());
            d.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
            d.put("minAddress", program.getMinAddress().toString());
            d.put("maxAddress", program.getMaxAddress().toString());
            d.put("imageBase", program.getImageBase().toString());
            d.put("creationDate", program.getCreationDate().toString());

            Map<String, Object> stats = new LinkedHashMap<>();
            stats.put("functionCount", program.getFunctionManager().getFunctionCount());
            stats.put("symbolCount", program.getSymbolTable().getNumSymbols());
            stats.put("memoryBlockCount", program.getMemory().getBlocks().length);
            d.put("statistics", stats);
            return d;
        });

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/program")
            .link("functions", "/functions")
            .link("symbols", "/symbols")
            .link("data", "/data")
            .link("strings", "/strings")
            .link("segments", "/segments")
            .link("memory", "/memory")
            .link("xrefs", "/xrefs")
            .link("analysis", "/analysis/status")
            .link("programs", "/programs")
            .build());
    }

    /**
     * GET /programs - List all programs in the project
     */
    private void listPrograms(GhidraContext ctx) {
        Project project = ctx.project();
        if (project == null) {
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), List.of())
                .self("/programs")
                .link("root", "/")
                .build());
            return;
        }

        List<Map<String, Object>> programs = new ArrayList<>();
        DomainFolder rootFolder = project.getProjectData().getRootFolder();
        collectPrograms(rootFolder, programs, "");

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), programs)
            .self("/programs")
            .link("current", "/programs/current")
            .link("root", "/")
            .build());
    }

    private void collectPrograms(DomainFolder folder, List<Map<String, Object>> programs, String path) {
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("name", file.getName());
                info.put("path", path + "/" + file.getName());
                info.put("contentType", file.getContentType());
                info.put("version", file.getVersion());
                info.put("readOnly", file.isReadOnly());
                programs.add(info);
            }
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            collectPrograms(subfolder, programs, path + "/" + subfolder.getName());
        }
    }
}
