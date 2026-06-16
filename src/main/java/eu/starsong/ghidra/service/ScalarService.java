package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.ScalarMatchDto;
import eu.starsong.ghidra.util.GhidraSwing;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Search for scalar (constant) values in instruction operands, like Ghidra's
 * "Search For Scalars" feature.
 *
 * <p>The scan runs on the EDT via {@link GhidraSwing#runRead} (the instruction iterator is a
 * DB iterator; a background read would risk a Locked buffer). Two guards keep that from
 * freezing the UI on a large program:
 * <ul>
 *   <li>An {@code in_function} filter scans only the matching functions' bodies, not every
 *       instruction in the program.</li>
 *   <li>A full scan (no/selective {@code in_function}) is bounded by a wall-clock budget; if it
 *       runs out, the result is flagged {@code truncated} so the caller knows to narrow it.</li>
 * </ul>
 */
public class ScalarService {

    /** How far to look ahead from a matched operand for the CALL it feeds. */
    private static final int CALL_LOOKAHEAD = 10;

    /** Wall-clock budget for a full scan before it gives up and reports truncation. */
    private static final long SCAN_BUDGET_NANOS = 12_000_000_000L;

    /** Check the time budget every this many instructions (cheap amortized cost). */
    private static final int TIME_CHECK_INTERVAL = 4096;

    /**
     * Bounded scan for a scalar value: skips {@code offset} matches, collects up to
     * {@code limit}, flags whether more exist, and flags whether the scan was cut short by the
     * time budget.
     */
    public Result search(Program program, long targetValue, String inFunction, String toFunction,
                         int offset, int limit) {
        String inFilter = (inFunction != null && !inFunction.isEmpty()) ? inFunction.toLowerCase() : null;
        String toFilter = (toFunction != null && !toFunction.isEmpty()) ? toFunction.toLowerCase() : null;

        return GhidraSwing.runRead(() -> {
            Listing listing = program.getListing();
            ReferenceManager refMgr = program.getReferenceManager();
            Collector c = new Collector(offset, limit);
            long deadline = System.nanoTime() + SCAN_BUDGET_NANOS;

            if (inFilter != null) {
                // Only the named functions: resolve them, then scan each body. Avoids walking the
                // whole program just to filter by containing function.
                FunctionIterator funcs = program.getFunctionManager().getFunctions(true);
                for (Function func : funcs) {
                    if (!func.getName(true).toLowerCase().contains(inFilter)) {
                        continue;
                    }
                    InstructionIterator it = listing.getInstructions(func.getBody(), true);
                    if (!scan(it, targetValue, toFilter, func, listing, refMgr, c, deadline)) {
                        break;
                    }
                }
            } else {
                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    if (!block.isInitialized()) {
                        continue;
                    }
                    InstructionIterator it = listing.getInstructions(block.getStart(), true);
                    if (!scan(it, targetValue, toFilter, null, listing, refMgr, c, deadline, block)) {
                        break;
                    }
                }
            }
            return new Result(c.matches, c.hasMore, c.truncated);
        });
    }

    private boolean scan(InstructionIterator it, long target, String toFilter, Function knownFunc,
                         Listing listing, ReferenceManager refMgr, Collector c, long deadline) {
        return scan(it, target, toFilter, knownFunc, listing, refMgr, c, deadline, null);
    }

    /**
     * Walk an instruction iterator, collecting matches. Returns false to tell the caller to stop
     * the whole search (limit reached or time budget exhausted). {@code knownFunc} is the
     * containing function when the source is a single function body; otherwise it's resolved per
     * instruction and {@code block} bounds the walk.
     */
    private boolean scan(InstructionIterator it, long target, String toFilter, Function knownFunc,
                         Listing listing, ReferenceManager refMgr, Collector c, long deadline,
                         MemoryBlock block) {
        int sinceTimeCheck = 0;
        while (it.hasNext()) {
            Instruction instr = it.next();
            Address addr = instr.getAddress();
            if (block != null && !block.contains(addr)) {
                return true;
            }
            if (++sinceTimeCheck >= TIME_CHECK_INTERVAL) {
                sinceTimeCheck = 0;
                if (System.nanoTime() > deadline) {
                    c.truncated = true;
                    return false;
                }
            }

            int numOps = instr.getNumOperands();
            for (int op = 0; op < numOps; op++) {
                for (Object obj : instr.getOpObjects(op)) {
                    if (!(obj instanceof Scalar)) {
                        continue;
                    }
                    Scalar scalar = (Scalar) obj;
                    if (scalar.getValue() != target) {
                        continue;
                    }
                    Function func = knownFunc != null ? knownFunc : listing.getFunctionContaining(addr);
                    Function callTarget = findCallTarget(instr, listing, refMgr);
                    if (toFilter != null
                            && (callTarget == null
                                || !callTarget.getName(true).toLowerCase().contains(toFilter))) {
                        continue;
                    }
                    ScalarMatchDto dto = new ScalarMatchDto(
                        addr.toString(),
                        target,
                        ScalarMatchDto.hex(target),
                        scalar.bitLength(),
                        scalar.isSigned(),
                        op,
                        instr.toString(),
                        func != null ? func.getName(true) : null,
                        func != null ? func.getEntryPoint().toString() : null,
                        callTarget != null ? callTarget.getName(true) : null,
                        callTarget != null ? callTarget.getEntryPoint().toString() : null);
                    if (!c.add(dto)) {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Look ahead a few instructions for the next CALL and resolve its target function.
     * Stops at the first non-fallthrough (jump/return) so we stay within the basic block.
     */
    private Function findCallTarget(Instruction start, Listing listing, ReferenceManager refMgr) {
        Instruction scan = start;
        for (int i = 0; i < CALL_LOOKAHEAD && scan != null; i++) {
            if (scan.getFlowType().isCall()) {
                for (Reference ref : refMgr.getReferencesFrom(scan.getAddress())) {
                    if (ref.getReferenceType().isCall()) {
                        return listing.getFunctionAt(ref.getToAddress());
                    }
                }
                return null;
            }
            if (!scan.getFlowType().hasFallthrough()) {
                return null;
            }
            scan = scan.getNext();
        }
        return null;
    }

    /** Accumulates a page of matches: skips {@code offset}, collects {@code limit}, flags more. */
    private static final class Collector {
        private final int offset;
        private final int limit;
        private final List<ScalarMatchDto> matches = new ArrayList<>();
        private int skipped = 0;
        private boolean hasMore = false;
        private boolean truncated = false;

        Collector(int offset, int limit) {
            this.offset = offset;
            this.limit = limit;
        }

        /** Returns false once one past the limit is seen (stop scanning). */
        boolean add(ScalarMatchDto dto) {
            if (skipped < offset) {
                skipped++;
                return true;
            }
            if (matches.size() >= limit) {
                hasMore = true;
                return false;
            }
            matches.add(dto);
            return true;
        }
    }

    /** A page of scalar matches, whether more exist, and whether the scan timed out. */
    public record Result(List<ScalarMatchDto> matches, boolean hasMore, boolean truncated) {
    }
}
