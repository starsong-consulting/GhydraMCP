package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallerRefDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves one matched string's direct users and a bounded BFS walk up the reverse
 * call graph over a {@link CallGraph}. Pure: no Ghidra types, no I/O.
 *
 * <p>The {@code fnBudget}, {@code globalVisited}, {@code unresolvedRefs}, and
 * {@code truncated} accumulators are shared across all strings in one response page,
 * so the function budget and visited set are global and the counters aggregate.
 */
public final class StringUsageWalker {

    private final CallGraph graph;

    public StringUsageWalker(CallGraph graph) {
        this.graph = graph;
    }

    public StringUsageDto resolve(StringUsageDto.StringRef ref, int callerDepth,
                                  int[] fnBudget, Set<String> globalVisited,
                                  int[] unresolvedRefs, boolean[] truncated) {
        List<FunctionSummaryDto> directUsers = new ArrayList<>();
        Set<String> directAddrs = new LinkedHashSet<>();
        for (String userEntry : graph.referrersOf(ref.address())) {
            if (userEntry == null) { unresolvedRefs[0]++; continue; }
            if (directAddrs.add(userEntry)) {
                directUsers.add(graph.summaryOf(userEntry));
            }
        }

        List<CallerRefDto> callers = new ArrayList<>();
        if (callerDepth > 0) {
            Set<String> currentLevel = new LinkedHashSet<>(directAddrs);
            int depth = 1;
            while (depth <= callerDepth && !currentLevel.isEmpty()) {
                Set<String> nextLevel = new LinkedHashSet<>();
                for (String fnEntry : currentLevel) {
                    for (String callerEntry : graph.callersOf(fnEntry)) {
                        if (callerEntry == null) { unresolvedRefs[0]++; continue; }
                        if (directAddrs.contains(callerEntry) || globalVisited.contains(callerEntry)) continue;
                        if (fnBudget[0] <= 0) {
                            truncated[0] = true;
                            return new StringUsageDto(ref, directUsers, callers);
                        }
                        globalVisited.add(callerEntry);
                        callers.add(new CallerRefDto(graph.summaryOf(callerEntry), depth));
                        fnBudget[0]--;
                        nextLevel.add(callerEntry);
                    }
                }
                currentLevel = nextLevel;
                depth++;
            }
        }

        return new StringUsageDto(ref, directUsers, callers);
    }
}
