package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.SymbolDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;

/**
 * Service for symbol-related operations.
 */
public class SymbolService {

    /**
     * List all symbols in the program.
     */
    public List<SymbolDto> list(Program program) {
        return list(program, null);
    }

    /**
     * List symbols matching a filter.
     */
    public List<SymbolDto> list(Program program, SymbolFilter filter) {
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);

        Predicate<Symbol> predicate = filter != null ? filter.toPredicate() : sym -> true;

        return StreamSupport.stream(symbols.spliterator(), false)
            .filter(predicate)
            .map(SymbolDto::from)
            .toList();
    }

    /**
     * List external/imported symbols.
     */
    public List<SymbolDto> listImports(Program program) {
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getExternalSymbols();

        return StreamSupport.stream(symbols.spliterator(), false)
            .map(SymbolDto::from)
            .toList();
    }

    /**
     * List exported symbols.
     */
    public List<SymbolDto> listExports(Program program) {
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getAllSymbols(true);

        return StreamSupport.stream(symbols.spliterator(), false)
            .filter(Symbol::isGlobal)
            .filter(sym -> !sym.isExternal())
            .map(SymbolDto::from)
            .toList();
    }

    /**
     * Get a symbol by address.
     */
    public Optional<SymbolDto> getByAddress(Program program, String addressStr) {
        Symbol sym = findByAddress(program, addressStr);
        return Optional.ofNullable(sym).map(SymbolDto::from);
    }

    /**
     * Find raw symbol by address.
     */
    public Symbol findByAddress(Program program, String addressStr) {
        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            return null;
        }
        return program.getSymbolTable().getPrimarySymbol(address);
    }

    /**
     * Rename a symbol.
     */
    public SymbolDto rename(Program program, String addressStr, String newName) throws Exception {
        Symbol symbol = findByAddress(program, addressStr);
        if (symbol == null) {
            throw new NotFoundException("Symbol not found at address: " + addressStr, "SYMBOL_NOT_FOUND");
        }

        TransactionHelper.executeInTransaction(program, "Rename Symbol", () -> {
            symbol.setName(newName, SourceType.USER_DEFINED);
            return null;
        });

        return SymbolDto.from(symbol);
    }

    /**
     * Create a label at an address.
     */
    public SymbolDto createLabel(Program program, String addressStr, String name) throws Exception {
        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        Symbol symbol = TransactionHelper.executeInTransaction(program, "Create Label", () -> {
            return program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
        });

        return SymbolDto.from(symbol);
    }

    /**
     * Delete a symbol.
     */
    public void delete(Program program, String addressStr) throws Exception {
        Symbol symbol = findByAddress(program, addressStr);
        if (symbol == null) {
            throw new NotFoundException("Symbol not found at address: " + addressStr, "SYMBOL_NOT_FOUND");
        }

        TransactionHelper.executeInTransaction(program, "Delete Symbol", () -> {
            symbol.delete();
            return null;
        });
    }

    // -------------------------------------------------------------------------
    // Filter class
    // -------------------------------------------------------------------------

    public static class SymbolFilter {
        private String nameEquals;
        private String nameContains;
        private String nameMatchesRegex;
        private String type;
        private Boolean isExternal;
        private Boolean isGlobal;

        public SymbolFilter nameEquals(String name) {
            this.nameEquals = name;
            return this;
        }

        public SymbolFilter nameContains(String substring) {
            this.nameContains = substring;
            return this;
        }

        public SymbolFilter nameMatchesRegex(String regex) {
            this.nameMatchesRegex = regex;
            return this;
        }

        public SymbolFilter type(String type) {
            this.type = type;
            return this;
        }

        public SymbolFilter isExternal(Boolean external) {
            this.isExternal = external;
            return this;
        }

        public SymbolFilter isGlobal(Boolean global) {
            this.isGlobal = global;
            return this;
        }

        public static SymbolFilter fromQueryParams(
                String name,
                String nameContains,
                String nameMatchesRegex,
                String type,
                String isExternal,
                String isGlobal) {

            SymbolFilter filter = new SymbolFilter();

            if (name != null && !name.isEmpty()) filter.nameEquals(name);
            if (nameContains != null && !nameContains.isEmpty()) filter.nameContains(nameContains);
            if (nameMatchesRegex != null && !nameMatchesRegex.isEmpty()) filter.nameMatchesRegex(nameMatchesRegex);
            if (type != null && !type.isEmpty()) filter.type(type);
            if (isExternal != null && !isExternal.isEmpty()) filter.isExternal(Boolean.parseBoolean(isExternal));
            if (isGlobal != null && !isGlobal.isEmpty()) filter.isGlobal(Boolean.parseBoolean(isGlobal));

            return filter;
        }

        Predicate<Symbol> toPredicate() {
            List<Predicate<Symbol>> predicates = new ArrayList<>();

            if (nameEquals != null) {
                predicates.add(sym -> sym.getName().equals(nameEquals));
            }
            if (nameContains != null) {
                String lower = nameContains.toLowerCase();
                predicates.add(sym -> sym.getName().toLowerCase().contains(lower));
            }
            if (nameMatchesRegex != null) {
                Pattern pattern = Pattern.compile(nameMatchesRegex);
                predicates.add(sym -> pattern.matcher(sym.getName()).matches());
            }
            if (type != null) {
                predicates.add(sym -> sym.getSymbolType().toString().equalsIgnoreCase(type));
            }
            if (isExternal != null) {
                predicates.add(sym -> sym.isExternal() == isExternal);
            }
            if (isGlobal != null) {
                predicates.add(sym -> sym.isGlobal() == isGlobal);
            }

            return predicates.stream().reduce(sym -> true, Predicate::and);
        }
    }
}
