package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.FunctionSummaryDto;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** In-memory CallGraph for unit tests. Lists may contain null entries (unresolved edges/refs). */
class FakeCallGraph implements CallGraph {
    final Map<String, List<String>> callees = new HashMap<>();
    final Map<String, List<String>> callers = new HashMap<>();
    final Map<String, List<String>> referrers = new HashMap<>();

    @Override public List<String> calleesOf(String fnEntry) { return callees.getOrDefault(fnEntry, List.of()); }
    @Override public List<String> callersOf(String fnEntry) { return callers.getOrDefault(fnEntry, List.of()); }
    @Override public List<String> referrersOf(String dataAddr) { return referrers.getOrDefault(dataAddr, List.of()); }

    @Override public FunctionSummaryDto summaryOf(String fnEntry) {
        return new FunctionSummaryDto("fn_" + fnEntry, fnEntry, "fn_" + fnEntry + "(void)", "void", false, false, 0);
    }
}
