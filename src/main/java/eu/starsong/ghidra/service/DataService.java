package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Service for data/variable operations.
 */
public class DataService {

    /**
     * List defined data in the program.
     */
    public List<DataDto> list(Program program, DataFilter filter) {
        Listing listing = program.getListing();
        List<DataDto> results = new ArrayList<>();

        Predicate<Data> predicate = filter != null ? filter.toPredicate() : d -> true;

        for (Data data : listing.getDefinedData(true)) {
            if (predicate.test(data)) {
                results.add(DataDto.from(data));
            }
        }

        return results;
    }

    /**
     * List strings in the program.
     */
    public List<DataDto> listStrings(Program program) {
        Listing listing = program.getListing();
        List<DataDto> results = new ArrayList<>();

        for (Data data : listing.getDefinedData(true)) {
            if (data.getDataType().getName().toLowerCase().contains("string")) {
                results.add(DataDto.from(data));
            }
        }

        return results;
    }

    /**
     * Get data at an address.
     */
    public Optional<DataDto> getByAddress(Program program, String addressStr) {
        Data data = findByAddress(program, addressStr);
        return Optional.ofNullable(data).map(DataDto::from);
    }

    /**
     * Find raw Data at address.
     */
    public Data findByAddress(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            return null;
        }
        return program.getListing().getDataAt(address);
    }

    /**
     * Get data at address, throwing if not found.
     */
    public DataDto requireByAddress(Program program, String addressStr) {
        return getByAddress(program, addressStr)
            .orElseThrow(() -> new NotFoundException("No data at address: " + addressStr, "DATA_NOT_FOUND"));
    }

    /**
     * Set data type at an address. If size is provided (e.g. for variable-length
     * types like strings), createData is called with an explicit length.
     */
    public DataDto setDataType(Program program, String addressStr, String dataTypeName, Integer size) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        DataType dataType = GhidraUtil.resolveDataType(program, dataTypeName);
        if (dataType == null) {
            throw new IllegalArgumentException("Unknown data type: " + dataTypeName);
        }

        int length;
        if (size != null && size > 0) {
            length = size;
        } else {
            length = dataType.getLength();
            if (length <= 0) {
                throw new IllegalArgumentException("Type '" + dataTypeName
                    + "' has non-positive length; specify size explicitly");
            }
        }
        final int finalLength = length;

        Data data = TransactionHelper.executeInTransaction(program, "Set Data Type", () -> {
            program.getListing().clearCodeUnits(address, address.add(finalLength - 1), false);
            return program.getListing().createData(address, dataType, finalLength);
        });

        return DataDto.from(data);
    }

    public DataDto setDataType(Program program, String addressStr, String dataTypeName) throws Exception {
        return setDataType(program, addressStr, dataTypeName, null);
    }

    /**
     * Rename the label at an address (Ghidra's "Edit Label" action). Does not
     * define, clear, or change existing data at the address.
     */
    public UpdateResult renameLabel(Program program, String addressStr, String newName) throws Exception {
        if (newName == null || newName.isEmpty()) {
            throw new IllegalArgumentException("newName is required");
        }
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        return TransactionHelper.executeInTransaction(program, "Rename label at " + addressStr, () -> {
            SymbolTable symTable = program.getSymbolTable();
            Symbol existing = symTable.getPrimarySymbol(address);
            String originalName = existing != null ? existing.getName() : null;
            if (existing != null) {
                existing.setName(newName, SourceType.USER_DEFINED);
            } else {
                symTable.createLabel(address, newName, SourceType.USER_DEFINED);
            }
            Data data = program.getListing().getDataAt(address);
            String typeName = data != null ? data.getDataType().getName() : null;
            return new UpdateResult(address.toString(), newName, originalName, typeName, null);
        });
    }

    /**
     * Combined update: rename and/or retype at an address. If only newName is
     * provided, behaves like renameLabel. If type is provided, the data is
     * (re)defined; pure rename leaves existing data alone.
     */
    public UpdateResult update(Program program, String addressStr, String newName, String typeName) throws Exception {
        boolean hasName = newName != null && !newName.isEmpty();
        boolean hasType = typeName != null && !typeName.isEmpty();
        if (!hasName && !hasType) {
            throw new IllegalArgumentException("At least one of newName or type must be provided");
        }
        if (hasName && !hasType) {
            return renameLabel(program, addressStr, newName);
        }

        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        DataType dataType = GhidraUtil.resolveDataType(program, typeName);
        if (dataType == null) {
            throw new IllegalArgumentException("Unknown data type: " + typeName);
        }

        return TransactionHelper.executeInTransaction(program, "Update data at " + addressStr, () -> {
            Listing listing = program.getListing();
            SymbolTable symTable = program.getSymbolTable();
            Symbol existing = symTable.getPrimarySymbol(address);
            String originalName = existing != null ? existing.getName() : null;

            Data oldData = listing.getDataAt(address);
            String originalType = oldData != null ? oldData.getDataType().getName() : null;

            listing.clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
            Data newData = listing.createData(address, dataType);

            if (hasName) {
                existing = symTable.getPrimarySymbol(address);
                if (existing != null) {
                    existing.setName(newName, SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(address, newName, SourceType.USER_DEFINED);
                }
            }

            String finalName = hasName ? newName : originalName;
            return new UpdateResult(address.toString(), finalName, originalName, newData.getDataType().getName(), originalType);
        });
    }

    /**
     * Clear data or instruction at an address. Returns what was cleared.
     */
    public ClearResult clearAt(Program program, String addressStr) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        return TransactionHelper.executeInTransaction(program, "Clear at " + addressStr, () -> {
            Listing listing = program.getListing();
            Data existing = listing.getDefinedDataAt(address);
            if (existing != null) {
                String type = existing.getDataType().getName();
                int length = existing.getLength();
                Symbol sym = program.getSymbolTable().getPrimarySymbol(address);
                String name = sym != null ? sym.getName() : null;
                listing.clearCodeUnits(address, address.add(length - 1), true);
                return new ClearResult(address.toString(), "data", type, length, name);
            }
            if (listing.getInstructionAt(address) != null) {
                listing.clearCodeUnits(address, address, true);
                return new ClearResult(address.toString(), "instruction", null, 0, null);
            }
            return new ClearResult(address.toString(), "none", null, 0, null);
        });
    }

    public record UpdateResult(
        String address,
        String name,
        String originalName,
        String dataType,
        String originalType
    ) {}

    public record ClearResult(
        String address,
        String cleared,    // "data", "instruction", or "none"
        String originalType,
        int length,
        String originalName
    ) {}

    /**
     * Filter for data listing.
     */
    public static class DataFilter {
        private String labelEquals;
        private String labelContains;
        private String dataType;

        public DataFilter labelEquals(String label) {
            this.labelEquals = label;
            return this;
        }

        public DataFilter labelContains(String substring) {
            this.labelContains = substring;
            return this;
        }

        public DataFilter dataType(String type) {
            this.dataType = type;
            return this;
        }

        public static DataFilter fromQueryParams(String label, String labelContains, String dataType) {
            DataFilter filter = new DataFilter();
            if (label != null && !label.isEmpty()) filter.labelEquals(label);
            if (labelContains != null && !labelContains.isEmpty()) filter.labelContains(labelContains);
            if (dataType != null && !dataType.isEmpty()) filter.dataType(dataType);
            return filter;
        }

        Predicate<Data> toPredicate() {
            List<Predicate<Data>> predicates = new ArrayList<>();

            if (labelEquals != null) {
                predicates.add(d -> {
                    var sym = d.getPrimarySymbol();
                    return sym != null && sym.getName().equals(labelEquals);
                });
            }
            if (labelContains != null) {
                String lower = labelContains.toLowerCase();
                predicates.add(d -> {
                    var sym = d.getPrimarySymbol();
                    return sym != null && sym.getName().toLowerCase().contains(lower);
                });
            }
            if (dataType != null) {
                String lower = dataType.toLowerCase();
                predicates.add(d -> d.getDataType().getName().toLowerCase().contains(lower));
            }

            return predicates.stream().reduce(d -> true, Predicate::and);
        }
    }
}
