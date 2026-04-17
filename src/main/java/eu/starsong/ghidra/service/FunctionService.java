package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.FunctionDto;
import eu.starsong.ghidra.dto.FunctionSummaryDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

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
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);

        Predicate<Function> predicate = filter != null ? filter.toPredicate() : fn -> true;

        return StreamSupport.stream(functions.spliterator(), false)
            .filter(predicate)
            .map(FunctionSummaryDto::from)
            .toList();
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
        Address address = program.getAddressFactory().getAddress(addressStr);
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
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        for (Function fn : functions) {
            if (fn.getName().equals(name)) {
                return fn;
            }
        }
        return null;
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
        Address address = program.getAddressFactory().getAddress(addressStr);
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
