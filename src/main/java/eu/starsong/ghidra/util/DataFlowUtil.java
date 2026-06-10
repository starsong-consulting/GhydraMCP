package eu.starsong.ghidra.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;

/**
 * Utility helpers for lightweight data-flow style traversal.
 *
 * NOTE: This is a reference-flow approximation built from Ghidra cross-references.
 * It is intentionally lightweight and deterministic for API usage.
 */
public final class DataFlowUtil {

    private DataFlowUtil() {
    }

    public static Map<String, Object> analyzeReferenceFlow(
            Program program,
            Address startAddress,
            String direction,
            int maxSteps) {
        // The traversal drains live ReferenceIterators; keep the whole bounded walk on the EDT.
        return GhidraSwing.runRead(() -> {
            return doAnalyzeReferenceFlow(program, startAddress, direction, maxSteps);
        });
    }

    private static Map<String, Object> doAnalyzeReferenceFlow(
            Program program,
            Address startAddress,
            String direction,
            int maxSteps) {

        boolean forward = "forward".equals(direction);
        ReferenceManager referenceManager = program.getReferenceManager();

        Deque<Address> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        List<Map<String, Object>> steps = new ArrayList<>();

        queue.add(startAddress);
        visited.add(startAddress.toString());

        int stepIndex = 0;
        while (!queue.isEmpty() && stepIndex < maxSteps) {
            Address current = queue.removeFirst();

            Instruction instruction = program.getListing().getInstructionAt(current);
            if (instruction == null) {
                instruction = program.getListing().getInstructionContaining(current);
            }

            Function function = program.getFunctionManager().getFunctionContaining(current);

            Map<String, Object> step = new HashMap<>();
            step.put("index", stepIndex);
            step.put("address", current.toString());
            step.put("instruction", instruction != null ? instruction.toString() : "<no instruction>");

            if (function != null) {
                step.put("function", function.getName());
                step.put("function_address", function.getEntryPoint().toString());
            }

            List<Map<String, Object>> refEntries = new ArrayList<>();
            List<Reference> refs = new ArrayList<>();
            if (forward) {
                Reference[] fromRefs = referenceManager.getReferencesFrom(current);
                refs.addAll(Arrays.asList(fromRefs));
            } else {
                Iterator<Reference> toRefs = referenceManager.getReferencesTo(current);
                while (toRefs.hasNext()) {
                    refs.add(toRefs.next());
                }
            }

            for (Reference ref : refs) {
                Map<String, Object> refInfo = new HashMap<>();
                refInfo.put("from", ref.getFromAddress().toString());
                refInfo.put("to", ref.getToAddress().toString());
                refInfo.put("type", ref.getReferenceType().toString());
                refEntries.add(refInfo);

                Address next = forward ? ref.getToAddress() : ref.getFromAddress();
                if (next != null && next.isMemoryAddress()) {
                    String key = next.toString();
                    if (!visited.contains(key)) {
                        visited.add(key);
                        queue.addLast(next);
                    }
                }
            }

            step.put("references", refEntries);
            step.put("reference_count", refEntries.size());
            steps.add(step);
            stepIndex++;
        }

        Map<String, Object> result = new HashMap<>();
        result.put("analysis_kind", "reference_flow");
        result.put("start_address", startAddress.toString());
        result.put("direction", direction);
        result.put("max_steps", maxSteps);
        result.put("visited_addresses", visited.size());
        result.put("steps", steps);

        if (steps.isEmpty()) {
            result.put("message", "No reference-flow steps found from the starting address.");
        } else if (queue.isEmpty()) {
            result.put("message", "Reference-flow traversal completed.");
        } else {
            result.put("message", "Traversal reached max_steps; increase max_steps for deeper results.");
        }

        return result;
    }
}
