package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.FunctionSummaryDto;

import java.util.List;

/**
 * Read-only, address-keyed view of the program's call graph and string references,
 * decoupled from Ghidra types so the traversal algorithms are unit-testable.
 *
 * <p>Every list method returns one element per underlying call site / reference, in
 * iteration order, preserving duplicates. A {@code null} element marks an edge or
 * reference that exists but is not attributable to a defined function entry
 * (thunk/PLT, indirect/computed call, data-region or undisassembled reference); the
 * caller counts these as "unresolved" and skips them. De-duplication of repeated
 * non-null entries is the algorithm's responsibility, not the graph's.
 */
public interface CallGraph {

    /** Callee entry addresses for each CALL out of the function at {@code fnEntry}. */
    List<String> calleesOf(String fnEntry);

    /** Caller entry addresses for each CALL into the function at {@code fnEntry}. */
    List<String> callersOf(String fnEntry);

    /** Caller entry addresses for each reference to the data at {@code dataAddr}. */
    List<String> referrersOf(String dataAddr);

    /** Function summary for a resolved (non-null) entry address. */
    FunctionSummaryDto summaryOf(String fnEntry);
}
