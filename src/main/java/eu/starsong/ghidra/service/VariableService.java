package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.VariableDto;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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

    public Page list(Program program, String search, boolean globalOnly, int offset, int limit) {
        if (program == null) return new Page(List.of(), false, 0);

        String lowerSearch = (search != null && !search.isEmpty()) ? search.toLowerCase() : null;
        List<VariableDto> globals = collectGlobals(program, lowerSearch);
        int globalCount = globals.size();

        List<VariableDto> page = new ArrayList<>();
        int endIdx = offset + limit;

        // Slice globals for this page.
        for (int i = offset; i < Math.min(endIdx, globalCount); i++) {
            page.add(globals.get(i));
        }

        if (globalOnly) {
            boolean hasMore = endIdx < globalCount;
            return new Page(page, hasMore, globalCount);
        }

        // Estimate total: globals + rough local estimate. getFunctionCount() is O(1),
        // avoiding a full function-table scan just for the estimate.
        int funcCount = program.getFunctionManager().getFunctionCount();
        int totalEstimate = globalCount + (lowerSearch != null ? funcCount / 5 : funcCount * 2);

        int remainingSpace = endIdx - page.size() - offset;
        if (remainingSpace <= 0 && page.size() >= limit) {
            return new Page(page, true, totalEstimate);
        }

        // How many locals to skip before adding? If we already sliced some globals, zero.
        // Otherwise the offset eats into globals first, then into locals.
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
