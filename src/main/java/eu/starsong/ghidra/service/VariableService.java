package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.VariableDto;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

public class VariableService {

    // How many functions a single local-var page request will decompile-and-scan. The
    // decompile cache makes re-scanning earlier functions on later pages cheap, so this
    // can be generous; configurable for very large programs. Cross-program local-var
    // enumeration is inherently bounded — a truncated scan is logged, not silent.
    private static final int LOCAL_SCAN_BUDGET = Integer.getInteger("ghidra.mcp.localvar.scan", 100);
    private static final int DECOMPILE_TIMEOUT = 10;

    private final DecompilerService decompilerService;

    public VariableService() {
        this.decompilerService = new DecompilerService();
    }

    public VariableService(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    public record Page(List<VariableDto> results, boolean hasMore, int totalEstimate) {}

    /** Backward-compatible entry point; defaults to the cheap "database" source. */
    public Page list(Program program, String search, boolean globalOnly, int offset, int limit) {
        return list(program, search, globalOnly, "database", offset, limit);
    }

    /**
     * List variables (program globals plus function-scoped locals/parameters).
     *
     * <p>source = "database" (default): reads committed variables straight from the program
     * DB via {@code Function.getAllVariables()} — cheap (no decompilation), complete over
     * stored variables, and exactly paginated with a real total. This is the "all locals" view.
     *
     * <p>source = "decompiler": runs the decompiler per function to surface inferred locals the
     * DB may not hold yet — richer but expensive, bounded by {@code ghidra.mcp.localvar.scan}
     * and approximately paginated.
     */
    public Page list(Program program, String search, boolean globalOnly, String source, int offset, int limit) {
        if (program == null) return new Page(List.of(), false, 0);

        String lowerSearch = (search != null && !search.isEmpty()) ? search.toLowerCase() : null;
        List<VariableDto> globals = collectGlobals(program, lowerSearch);

        if (globalOnly) {
            return paginate(globals, offset, limit);
        }

        if ("decompiler".equalsIgnoreCase(source)) {
            return listWithDecompilerLocals(program, lowerSearch, globals, offset, limit);
        }

        // Default: database source — exact, cheap, complete over committed variables.
        List<VariableDto> all = new ArrayList<>(globals);
        all.addAll(collectLocalsFromDatabase(program, lowerSearch));
        all.sort(Comparator.comparing(VariableDto::name));
        return paginate(all, offset, limit);
    }

    /** Exact pagination over a fully-materialized list. */
    private Page paginate(List<VariableDto> all, int offset, int limit) {
        int total = all.size();
        int from = Math.min(Math.max(0, offset), total);
        int to = Math.min(from + limit, total);
        List<VariableDto> page = new ArrayList<>(all.subList(from, to));
        return new Page(page, to < total, total);
    }

    /**
     * Cheap DB-backed enumeration of every function's committed variables (params + locals).
     * One marshalled DB scan, no decompilation.
     */
    private List<VariableDto> collectLocalsFromDatabase(Program program, String lowerSearch) {
        return GhidraSwing.runRead(() -> {
            List<VariableDto> result = new ArrayList<>();
            for (Function fn : program.getFunctionManager().getFunctions(true)) {
                String fnName = fn.getName();
                for (Variable v : fn.getAllVariables()) {
                    String name = v.getName();
                    if (lowerSearch != null && !name.toLowerCase().contains(lowerSearch)) continue;
                    DataType dt = v.getDataType();
                    result.add(VariableDto.local(
                        name,
                        v.getVariableStorage().toString(),
                        dt != null ? dt.getName() : "unknown",
                        fnName,
                        v instanceof Parameter));
                }
            }
            return result;
        });
    }

    /** The decompiler-backed path: globals sliced, then budgeted decompiler locals appended. */
    private Page listWithDecompilerLocals(Program program, String lowerSearch, List<VariableDto> globals,
                                          int offset, int limit) {
        int globalCount = globals.size();
        List<VariableDto> page = new ArrayList<>();
        int endIdx = offset + limit;
        for (int i = offset; i < Math.min(endIdx, globalCount); i++) {
            page.add(globals.get(i));
        }

        int funcCount = program.getFunctionManager().getFunctionCount();
        int totalEstimate = globalCount + (lowerSearch != null ? funcCount / 5 : funcCount * 2);

        if (page.size() >= limit) {
            return new Page(page, true, totalEstimate);
        }

        int localsToSkip = Math.max(0, offset - globalCount);
        int localsNeeded = limit - page.size();
        LocalCollectResult local = collectLocals(program, lowerSearch, localsToSkip, localsNeeded, funcCount);
        page.addAll(local.locals);

        page.sort(Comparator.comparing(VariableDto::name));
        boolean hasMore = local.hasMore || endIdx < globalCount;
        return new Page(page, hasMore, totalEstimate);
    }

    private List<VariableDto> collectGlobals(Program program, String lowerSearch) {
        List<VariableDto> globals = GhidraSwing.runRead(() -> {
            SymbolTable symbolTable = program.getSymbolTable();
            List<VariableDto> result = new ArrayList<>();
            for (Symbol symbol : symbolTable.getDefinedSymbols()) {
                if (!symbol.isGlobal() || symbol.isExternal()) continue;
                if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) continue;
                if (lowerSearch != null && !symbol.getName().toLowerCase().contains(lowerSearch)) continue;
                result.add(VariableDto.global(
                    symbol.getName(),
                    symbol.getAddress().toString(),
                    getDataTypeName(program, symbol.getAddress())));
            }
            return result;
        });
        globals.sort(Comparator.comparing(VariableDto::name));
        return globals;
    }

    private record LocalCollectResult(List<VariableDto> locals, boolean hasMore) {}

    private LocalCollectResult collectLocals(Program program, String lowerSearch, int skip, int needed, int funcCount) {
        if (needed <= 0) return new LocalCollectResult(List.of(), false);

        List<VariableDto> locals = new ArrayList<>();
        int seenLocals = 0;
        int functionsProcessed = 0;

        final List<Function> allFunctions = GhidraSwing.runRead(() -> {
            List<Function> fns = new ArrayList<>();
            for (Function f : program.getFunctionManager().getFunctions(true)) fns.add(f);
            return fns;
        });

        for (Function function : allFunctions) {
            if (functionsProcessed >= LOCAL_SCAN_BUDGET) break;
            functionsProcessed++;

            HighFunction highFunc;
            try {
                highFunc = decompilerService.getHighFunction(program, function, DECOMPILE_TIMEOUT);
            } catch (Exception e) {
                continue;
            }
            if (highFunc == null) continue;

            Iterator<HighSymbol> iter = highFunc.getLocalSymbolMap().getSymbols();
            while (iter.hasNext() && locals.size() < needed) {
                HighSymbol sym = iter.next();
                if (lowerSearch != null) {
                    // search mode: include params too if they match
                    if (!sym.getName().toLowerCase().contains(lowerSearch)) continue;
                } else {
                    // list mode: only non-params
                    if (sym.isParameter()) continue;
                }
                if (seenLocals < skip) {
                    seenLocals++;
                    continue;
                }
                Address pcAddr = sym.getPCAddress();
                DataType dt = sym.getDataType();
                locals.add(VariableDto.local(
                    sym.getName(),
                    pcAddr != null ? pcAddr.toString() : "N/A",
                    dt != null ? dt.getName() : "unknown",
                    function.getName(),
                    sym.isParameter()));
            }
            if (locals.size() >= needed) break;
        }
        if (functionsProcessed >= LOCAL_SCAN_BUDGET && functionsProcessed < funcCount && locals.size() < needed) {
            Msg.warn(this, "Local-variable scan stopped after " + LOCAL_SCAN_BUDGET + " functions (of "
                + funcCount + "); page may be incomplete. Raise -Dghidra.mcp.localvar.scan to scan further.");
        }
        // More locals may exist if functions remain unprocessed (page filled early or scan
        // budget hit); only false once every function has been scanned.
        boolean hasMore = functionsProcessed < funcCount;
        return new LocalCollectResult(locals, hasMore);
    }

    private String getDataTypeName(Program program, Address address) {
        Data data = program.getListing().getDataAt(address);
        if (data == null) return "undefined";
        DataType dt = data.getDataType();
        return dt != null ? dt.getName() : "unknown";
    }
}
