package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.XrefDto;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Service for cross-reference operations.
 */
public class XrefService {

    /**
     * Get references TO an address.
     */
    public List<XrefDto> getReferencesTo(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        ReferenceManager refMgr = program.getReferenceManager();

        return GhidraSwing.runRead(() -> {
            ReferenceIterator iter = refMgr.getReferencesTo(address);
            List<XrefDto> results = new ArrayList<>();
            while (iter.hasNext()) {
                results.add(XrefDto.from(iter.next(), program));
            }
            return results;
        });
    }

    /**
     * Get references FROM an address.
     */
    public List<XrefDto> getReferencesFrom(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        ReferenceManager refMgr = program.getReferenceManager();

        return GhidraSwing.runRead(() -> {
            Reference[] refs = refMgr.getReferencesFrom(address);
            return Arrays.stream(refs)
                .map(ref -> XrefDto.from(ref, program))
                .toList();
        });
    }

    /**
     * Get all references with optional filtering.
     */
    public List<XrefDto> getReferences(Program program, String toAddr, String fromAddr, String refType, int limit) {
        List<XrefDto> results = new ArrayList<>();

        if (toAddr != null && !toAddr.isEmpty()) {
            results.addAll(getReferencesTo(program, toAddr));
        }

        if (fromAddr != null && !fromAddr.isEmpty()) {
            List<XrefDto> fromRefs = getReferencesFrom(program, fromAddr);
            if (results.isEmpty()) {
                results.addAll(fromRefs);
            } else {
                // Intersect if both filters provided
                results.retainAll(fromRefs);
            }
        }

        // Filter by reference type if specified
        if (refType != null && !refType.isEmpty()) {
            String upperType = refType.toUpperCase();
            results = results.stream()
                .filter(xref -> xref.refType().toUpperCase().contains(upperType))
                .toList();
        }

        // Limit results
        if (results.size() > limit) {
            results = results.subList(0, limit);
        }

        return results;
    }

    /**
     * Get call references to a function.
     */
    public List<XrefDto> getCallsTo(Program program, String addressStr) {
        return getReferencesTo(program, addressStr).stream()
            .filter(xref -> xref.refType().contains("CALL"))
            .toList();
    }

    /**
     * Get call references from a function.
     */
    public List<XrefDto> getCallsFrom(Program program, String addressStr) {
        return getReferencesFrom(program, addressStr).stream()
            .filter(xref -> xref.refType().contains("CALL"))
            .toList();
    }

    /**
     * Get CALL references made anywhere inside a function's body.
     *
     * <p>{@link #getCallsFrom} only inspects a single address — almost never the
     * instruction that makes the call — so callee discovery must scan the body.
     */
    public List<XrefDto> getCallsFromFunction(Program program, ghidra.program.model.listing.Function function) {
        if (function == null) {
            return List.of();
        }
        ReferenceManager refMgr = program.getReferenceManager();
        return GhidraSwing.runRead(() -> {
            List<XrefDto> calls = new ArrayList<>();
            var sources = refMgr.getReferenceSourceIterator(function.getBody(), true);
            while (sources.hasNext()) {
                Address from = sources.next();
                for (Reference ref : refMgr.getReferencesFrom(from)) {
                    if (ref.getReferenceType().isCall()) {
                        calls.add(XrefDto.from(ref, program));
                    }
                }
            }
            return calls;
        });
    }
}
