package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallPathDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Enumerates bounded, simple (loop-free) call paths between two function entries
 * over a {@link CallGraph}. Pure: no Ghidra types, no I/O.
 */
public final class CallPathFinder {

    private final CallGraph graph;

    public CallPathFinder(CallGraph graph) {
        this.graph = graph;
    }

    public Result find(String fromEntry, String toEntry, int maxDepth, int maxPaths, int maxVisitedEdges) {
        Objects.requireNonNull(fromEntry, "fromEntry");
        Objects.requireNonNull(toEntry, "toEntry");
        if (maxPaths < 1) throw new IllegalArgumentException("maxPaths must be >= 1, got " + maxPaths);
        if (maxDepth < 0) throw new IllegalArgumentException("maxDepth must be >= 0, got " + maxDepth);
        if (maxVisitedEdges < 1) throw new IllegalArgumentException("maxVisitedEdges must be >= 1, got " + maxVisitedEdges);
        List<CallPathDto> paths = new ArrayList<>();
        int[] visitedEdges = {0};
        int[] unresolvedEdges = {0};
        boolean[] truncated = {false};

        List<String> path = new ArrayList<>();
        Set<String> onPath = new HashSet<>();
        path.add(fromEntry);
        onPath.add(fromEntry);

        dfs(fromEntry, toEntry, maxDepth, maxPaths, maxVisitedEdges,
            path, onPath, paths, visitedEdges, unresolvedEdges, truncated);

        return new Result(List.copyOf(paths), truncated[0], unresolvedEdges[0]);
    }

    private void dfs(String current, String toEntry, int depth, int maxPaths, int maxVisitedEdges,
                     List<String> path, Set<String> onPath, List<CallPathDto> paths,
                     int[] visitedEdges, int[] unresolvedEdges, boolean[] truncated) {
        if (current.equals(toEntry)) {
            List<FunctionSummaryDto> fns = new ArrayList<>();
            for (String entry : path) {
                fns.add(graph.summaryOf(entry));
            }
            paths.add(CallPathDto.of(fns));
            if (paths.size() >= maxPaths) truncated[0] = true;
            return;
        }
        if (depth <= 0) return;

        for (String callee : graph.calleesOf(current)) {
            if (paths.size() >= maxPaths) { truncated[0] = true; return; }
            if (visitedEdges[0] >= maxVisitedEdges) { truncated[0] = true; return; }
            visitedEdges[0]++;

            if (callee == null) { unresolvedEdges[0]++; continue; }
            if (onPath.contains(callee)) continue; // cycle: expected, not unresolved

            onPath.add(callee);
            path.add(callee);
            dfs(callee, toEntry, depth - 1, maxPaths, maxVisitedEdges,
                path, onPath, paths, visitedEdges, unresolvedEdges, truncated);
            path.remove(path.size() - 1);
            onPath.remove(callee);
        }
    }

    public record Result(List<CallPathDto> paths, boolean truncated, int unresolvedEdges) {
    }
}
