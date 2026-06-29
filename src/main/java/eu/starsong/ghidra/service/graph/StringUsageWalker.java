package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallerRefDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.dto.StringUsageDto;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves one matched string's direct users and a bounded BFS walk up the reverse
 * call graph over a {@link CallGraph}. Pure: no Ghidra types, no I/O.
 *
 * <p>A {@link WalkState} carries the shared accumulators (budget, visited set,
 * unresolved count, truncation flag) across all strings in one response page,
 * so the function budget and visited set are global and the counters aggregate.
 * Construct one {@code WalkState} per page and pass it to every {@link #resolve} call.
 */
public final class StringUsageWalker {

    private final CallGraph graph;

    public StringUsageWalker(CallGraph graph) {
        this.graph = graph;
    }

    /**
     * Shared mutable state for one page's worth of string-usage resolution.
     * All fields are package-visible for access by {@link StringUsageWalker#resolve}.
     */
    public static final class WalkState {
        int fnBudget;
        final Set<String> globalVisited = new HashSet<>();
        int unresolvedRefs;
        boolean truncated;

        public WalkState(int fnBudget) {
            if (fnBudget < 0) throw new IllegalArgumentException("fnBudget must be >= 0, got " + fnBudget);
            this.fnBudget = fnBudget;
        }

        public int unresolvedRefs() { return unresolvedRefs; }
        public boolean truncated() { return truncated; }
    }

    public StringUsageDto resolve(StringUsageDto.StringRef ref, int callerDepth, WalkState state) {
        List<FunctionSummaryDto> directUsers = new ArrayList<>();
        Set<String> directAddrs = new LinkedHashSet<>();
        for (String userEntry : graph.referrersOf(ref.address())) {
            if (userEntry == null) { state.unresolvedRefs++; continue; }
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
                        if (callerEntry == null) { state.unresolvedRefs++; continue; }
                        if (directAddrs.contains(callerEntry) || state.globalVisited.contains(callerEntry)) continue;
                        // Add to globalVisited BEFORE budget check so that even if we truncate,
                        // this entry won't re-trigger truncation for the next string on the page.
                        state.globalVisited.add(callerEntry);
                        if (state.fnBudget <= 0) {
                            state.truncated = true;
                            continue; // don't add to callers or nextLevel — budget exhausted
                        }
                        callers.add(new CallerRefDto(graph.summaryOf(callerEntry), depth));
                        state.fnBudget--;
                        nextLevel.add(callerEntry);
                    }
                }
                if (state.truncated) break; // don't expand further BFS levels
                currentLevel = nextLevel;
                depth++;
            }
        }

        return new StringUsageDto(ref, directUsers, callers);
    }
}
