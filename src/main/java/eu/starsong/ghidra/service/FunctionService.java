package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.DisassemblyInstructionDto;
import eu.starsong.ghidra.dto.FunctionDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;

/**
 * Service for function-related operations.
 * Contains business logic extracted from FunctionEndpoints.
 */
public class FunctionService {

    /**
     * List all functions in the program.
     */
    public List<FunctionSummaryDto> list(Program program) {
        return list(program, null);
    }

    /**
     * List functions matching a filter.
     */
    public List<FunctionSummaryDto> list(Program program, FunctionFilter filter) {
        Predicate<Function> predicate = filter != null ? filter.toPredicate() : fn -> true;

        return GhidraSwing.runRead(() -> {
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            List<FunctionSummaryDto> out = StreamSupport.stream(functions.spliterator(), false)
                .filter(predicate)
                .map(FunctionSummaryDto::from)
                .toList();
            return out;
        });
    }

    /**
     * Get a function by its entry point address.
     */
    public Optional<FunctionDto> getByAddress(Program program, String addressStr) {
        Function fn = findByAddress(program, addressStr);
        return Optional.ofNullable(fn).map(FunctionDto::from);
    }

    /**
     * Get the raw Ghidra Function by address.
     */
    public Function findByAddress(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            return null;
        }
        return program.getFunctionManager().getFunctionAt(address);
    }

    /**
     * Get a function by its entry point address, throwing if not found.
     */
    public FunctionDto requireByAddress(Program program, String addressStr) {
        return getByAddress(program, addressStr)
            .orElseThrow(() -> new NotFoundException("Function not found at address: " + addressStr, "FUNCTION_NOT_FOUND"));
    }

    /**
     * Get the raw Ghidra Function by address, throwing if not found.
     */
    public Function requireFunctionByAddress(Program program, String addressStr) {
        Function fn = findByAddress(program, addressStr);
        if (fn == null) {
            throw new NotFoundException("Function not found at address: " + addressStr, "FUNCTION_NOT_FOUND");
        }
        return fn;
    }

    /**
     * Get a function by its name.
     */
    public Optional<FunctionDto> getByName(Program program, String name) {
        Function fn = findByName(program, name);
        return Optional.ofNullable(fn).map(FunctionDto::from);
    }

    /**
     * Get the raw Ghidra Function by name.
     */
    public Function findByName(Program program, String name) {
        return GhidraSwing.runRead(() -> {
            FunctionIterator functions = program.getFunctionManager().getFunctions(true);
            for (Function fn : functions) {
                if (fn.getName().equals(name)) {
                    return fn;
                }
            }
            return null;
        });
    }

    /**
     * Get a function by name, throwing if not found.
     */
    public FunctionDto requireByName(Program program, String name) {
        return getByName(program, name)
            .orElseThrow(() -> new NotFoundException("Function not found with name: " + name, "FUNCTION_NOT_FOUND"));
    }

    /**
     * Get the raw Ghidra Function by name, throwing if not found.
     */
    public Function requireFunctionByName(Program program, String name) {
        Function fn = findByName(program, name);
        if (fn == null) {
            throw new NotFoundException("Function not found with name: " + name, "FUNCTION_NOT_FOUND");
        }
        return fn;
    }

    /**
     * Rename a function.
     */
    public FunctionDto rename(Program program, String addressStr, String newName) throws Exception {
        Function fn = requireFunctionByAddress(program, addressStr);

        TransactionHelper.executeInTransaction(program, "Rename Function", () -> {
            fn.setName(newName, SourceType.USER_DEFINED);
            return null;
        });

        return FunctionDto.from(fn);
    }

    /**
     * Set a function's comment.
     */
    public FunctionDto setComment(Program program, String addressStr, String comment) throws Exception {
        Function fn = requireFunctionByAddress(program, addressStr);

        TransactionHelper.executeInTransaction(program, "Set Function Comment", () -> {
            fn.setComment(comment);
            return null;
        });

        return FunctionDto.from(fn);
    }

    /**
     * Delete a function.
     */
    public void delete(Program program, String addressStr) throws Exception {
        Function fn = requireFunctionByAddress(program, addressStr);

        TransactionHelper.executeInTransaction(program, "Delete Function", () -> {
            program.getFunctionManager().removeFunction(fn.getEntryPoint());
            return null;
        });
    }

    /**
     * Create a function at an address.
     */
    public FunctionDto create(Program program, String addressStr, String name) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        Function existingFn = program.getFunctionManager().getFunctionAt(address);
        if (existingFn != null) {
            throw new IllegalArgumentException("Function already exists at address: " + addressStr);
        }

        Function fn = TransactionHelper.executeInTransaction(program, "Create Function", () -> {
            return program.getFunctionManager().createFunction(
                name,
                address,
                null,
                SourceType.USER_DEFINED
            );
        });

        return FunctionDto.from(fn);
    }

    /**
     * Find the function containing a given address.
     */
    public Function findContaining(Program program, String addressStr) {
        Address addr = GhidraUtil.resolveAddress(program, addressStr);
        if (addr == null) return null;
        return program.getFunctionManager().getFunctionContaining(addr);
    }

    public FunctionDto requireContaining(Program program, String addressStr) {
        Function fn = findContaining(program, addressStr);
        if (fn == null) {
            throw new NotFoundException("No function contains address: " + addressStr, "FUNCTION_NOT_FOUND");
        }
        return FunctionDto.from(fn);
    }

    /**
     * Find the next function after the given address (by memory order).
     */
    public Function findNext(Program program, String addressStr) {
        Address addr = GhidraUtil.resolveAddress(program, addressStr);
        if (addr == null) return null;
        return GhidraSwing.runRead(() -> {
            Function current = program.getFunctionManager().getFunctionContaining(addr);
            Address searchFrom = current != null ? current.getBody().getMaxAddress().next() : addr.next();
            if (searchFrom == null) return null;
            FunctionIterator it = program.getFunctionManager().getFunctions(searchFrom, true);
            return it.hasNext() ? it.next() : null;
        });
    }

    /**
     * Find the previous function before the given address (by memory order).
     */
    public Function findPrev(Program program, String addressStr) {
        Address addr = GhidraUtil.resolveAddress(program, addressStr);
        if (addr == null) return null;
        return GhidraSwing.runRead(() -> {
            Function current = program.getFunctionManager().getFunctionContaining(addr);
            Address searchFrom = current != null ? current.getEntryPoint().previous() : addr.previous();
            if (searchFrom == null) return null;
            FunctionIterator it = program.getFunctionManager().getFunctions(searchFrom, false);
            return it.hasNext() ? it.next() : null;
        });
    }

    /**
     * Set the function's signature using Ghidra's signature parser.
     */
    public FunctionDto setSignature(Program program, String addressStr, String signature) throws Exception {
        Function fn = requireFunctionByAddress(program, addressStr);
        boolean ok = TransactionHelper.executeInTransaction(program, "Set Function Signature", () ->
            GhidraUtil.setFunctionSignature(fn, signature));
        if (!ok) {
            throw new IllegalArgumentException("Failed to set signature: " + signature);
        }
        return FunctionDto.from(fn);
    }

    /**
     * Disassemble a function body.
     */
    public List<DisassemblyInstructionDto> disassemble(Program program, Function function) {
        return GhidraSwing.runRead(() -> {
            List<DisassemblyInstructionDto> results = new ArrayList<>();
            Listing listing = program.getListing();
            Address start = function.getEntryPoint();
            Address end = function.getBody().getMaxAddress();
            for (Instruction i : listing.getInstructions(start, true)) {
                if (i.getAddress().compareTo(end) > 0) break;
                results.add(DisassemblyInstructionDto.from(i, program));
            }
            return results;
        });
    }

    /**
     * Update a local variable (rename and/or retype) in a function.
     */
    public boolean updateLocalVariable(Program program, Function function, String variableName,
                                       String newName, String newDataTypeName) throws Exception {
        DecompileResults decompResults;
        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);
            decompResults = decomp.decompileFunction(function, 60, new ConsoleTaskMonitor());
        } finally {
            decomp.dispose();
        }
        if (decompResults == null || !decompResults.decompileCompleted()) {
            throw new IllegalStateException("Decompilation failed for " + function.getName());
        }
        HighFunction highFunc = decompResults.getHighFunction();
        if (highFunc == null) {
            throw new IllegalStateException("No high function available");
        }

        ghidra.program.model.data.DataType resolvedType = null;
        if (newDataTypeName != null && !newDataTypeName.isEmpty()) {
            resolvedType = GhidraUtil.resolveDataType(program, newDataTypeName);
            if (resolvedType == null) {
                throw new IllegalArgumentException("Unknown data type: " + newDataTypeName);
            }
        }
        final ghidra.program.model.data.DataType finalType = resolvedType;

        return TransactionHelper.executeInTransaction(program,
            "Update variable " + variableName + " in " + function.getName(), () -> {
                for (var it = highFunc.getLocalSymbolMap().getSymbols(); it.hasNext(); ) {
                    HighSymbol sym = it.next();
                    if (sym.getName().equals(variableName)) {
                        HighFunctionDBUtil.updateDBVariable(sym, newName, finalType, SourceType.USER_DEFINED);
                        return true;
                    }
                }
                return false;
            });
    }

    // -------------------------------------------------------------------------
    // Filter class
    // -------------------------------------------------------------------------

    /**
     * Filter for function listing.
     */
    public static class FunctionFilter {
        private String nameEquals;
        private String nameContains;
        private String nameMatchesRegex;
        private Boolean isExternal;
        private Boolean isThunk;

        public FunctionFilter nameEquals(String name) {
            this.nameEquals = name;
            return this;
        }

        public FunctionFilter nameContains(String substring) {
            this.nameContains = substring;
            return this;
        }

        public FunctionFilter nameMatchesRegex(String regex) {
            this.nameMatchesRegex = regex;
            return this;
        }

        public FunctionFilter isExternal(Boolean external) {
            this.isExternal = external;
            return this;
        }

        public FunctionFilter isThunk(Boolean thunk) {
            this.isThunk = thunk;
            return this;
        }

        /**
         * Create a filter from query parameters.
         */
        public static FunctionFilter fromQueryParams(
                String name,
                String nameContains,
                String nameMatchesRegex,
                String isExternal,
                String isThunk) {

            FunctionFilter filter = new FunctionFilter();

            if (name != null && !name.isEmpty()) {
                filter.nameEquals(name);
            }
            if (nameContains != null && !nameContains.isEmpty()) {
                filter.nameContains(nameContains);
            }
            if (nameMatchesRegex != null && !nameMatchesRegex.isEmpty()) {
                filter.nameMatchesRegex(nameMatchesRegex);
            }
            if (isExternal != null && !isExternal.isEmpty()) {
                filter.isExternal(Boolean.parseBoolean(isExternal));
            }
            if (isThunk != null && !isThunk.isEmpty()) {
                filter.isThunk(Boolean.parseBoolean(isThunk));
            }

            return filter;
        }

        Predicate<Function> toPredicate() {
            List<Predicate<Function>> predicates = new ArrayList<>();

            if (nameEquals != null) {
                predicates.add(fn -> fn.getName().equals(nameEquals));
            }
            if (nameContains != null) {
                String lower = nameContains.toLowerCase();
                predicates.add(fn -> fn.getName().toLowerCase().contains(lower));
            }
            if (nameMatchesRegex != null) {
                Pattern pattern = Pattern.compile(nameMatchesRegex);
                predicates.add(fn -> pattern.matcher(fn.getName()).matches());
            }
            if (isExternal != null) {
                predicates.add(fn -> fn.isExternal() == isExternal);
            }
            if (isThunk != null) {
                predicates.add(fn -> fn.isThunk() == isThunk);
            }

            return predicates.stream().reduce(fn -> true, Predicate::and);
        }
    }
}
