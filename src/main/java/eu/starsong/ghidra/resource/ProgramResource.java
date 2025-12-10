package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
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

    @Override
    public void register(Javalin app, Function<Context, GhidraContext> contextFactory) {
        app.get("/program", ctx -> getCurrentProgram(contextFactory.apply(ctx)));
        app.get("/programs", ctx -> listPrograms(contextFactory.apply(ctx)));
        app.get("/programs/current", ctx -> getCurrentProgram(contextFactory.apply(ctx)));
    }

    /**
     * GET /program or /programs/current - Get current program info
     */
    private void getCurrentProgram(GhidraContext ctx) {
        Program program = ctx.requireProgram();

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", program.getName());
        data.put("path", program.getExecutablePath());
        data.put("language", program.getLanguageID().getIdAsString());
        data.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        data.put("processor", program.getLanguage().getProcessor().toString());
        data.put("addressSize", program.getAddressFactory().getDefaultAddressSpace().getSize());
        data.put("minAddress", program.getMinAddress().toString());
        data.put("maxAddress", program.getMaxAddress().toString());
        data.put("imageBase", program.getImageBase().toString());
        data.put("creationDate", program.getCreationDate().toString());

        // Add statistics
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("functionCount", program.getFunctionManager().getFunctionCount());
        stats.put("symbolCount", program.getSymbolTable().getNumSymbols());
        stats.put("memoryBlockCount", program.getMemory().getBlocks().length);
        data.put("statistics", stats);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), data)
            .self("/program")
            .link("functions", "/functions")
            .link("symbols", "/symbols")
            .link("data", "/data")
            .link("strings", "/strings")
            .link("segments", "/segments")
            .link("memory", "/memory")
            .link("xrefs", "/xrefs")
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
