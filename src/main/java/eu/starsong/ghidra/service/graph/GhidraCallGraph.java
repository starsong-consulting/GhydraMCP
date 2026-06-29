package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.service.FunctionService;
import eu.starsong.ghidra.service.XrefService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Production {@link CallGraph} backed by a live {@link Program} and the existing services.
 * The only graph implementation that touches Ghidra types. Construct and use it inside a
 * {@code GhidraSwing.runRead} boundary (see {@code AnalysisService}); the underlying service
 * calls run their own reentrant reads.
 *
 * <p>Each list method emits one element per call site / reference, in order. An edge or
 * reference whose source/target is not a defined function entry is emitted as {@code null}.
 */
public final class GhidraCallGraph implements CallGraph {

    private final Program program;
    private final FunctionService functionService;
    private final XrefService xrefService;

    public GhidraCallGraph(Program program, FunctionService functionService, XrefService xrefService) {
        this.program = Objects.requireNonNull(program, "program");
        this.functionService = Objects.requireNonNull(functionService, "functionService");
        this.xrefService = Objects.requireNonNull(xrefService, "xrefService");
    }

    @Override
    public List<String> calleesOf(String fnEntry) {
        Function fn = functionService.findByAddress(program, fnEntry);
        if (fn == null) {
            // Source address is not a defined function entry; signal one unresolved edge
            // so the DFS counts it rather than silently pruning the entire subtree.
            return Collections.singletonList(null);
        }
        List<String> out = new ArrayList<>();
        for (XrefDto xref : xrefService.getCallsFromFunction(program, fn)) {
            String calleeAddr = xref.toFunctionAddress();
            if (calleeAddr == null) { out.add(null); continue; }
            Function callee = functionService.findByAddress(program, calleeAddr);
            out.add(callee != null ? callee.getEntryPoint().toString() : null);
        }
        return out;
    }

    @Override
    public List<String> callersOf(String fnEntry) {
        List<String> out = new ArrayList<>();
        for (XrefDto x : xrefService.getCallsTo(program, fnEntry)) {
            Function caller = functionService.findContaining(program, x.fromAddress());
            out.add(caller != null ? caller.getEntryPoint().toString() : null);
        }
        return out;
    }

    @Override
    public List<String> referrersOf(String dataAddr) {
        List<String> out = new ArrayList<>();
        for (XrefDto x : xrefService.getReferencesTo(program, dataAddr)) {
            Function f = functionService.findContaining(program, x.fromAddress());
            out.add(f != null ? f.getEntryPoint().toString() : null);
        }
        return out;
    }

    @Override
    public FunctionSummaryDto summaryOf(String fnEntry) {
        Function fn = functionService.findByAddress(program, fnEntry);
        if (fn == null) {
            throw new IllegalArgumentException("No function at entry address: " + fnEntry);
        }
        return FunctionSummaryDto.from(fn);
    }
}
