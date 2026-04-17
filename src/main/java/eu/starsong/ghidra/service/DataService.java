package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.DataDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

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
        Address address = program.getAddressFactory().getAddress(addressStr);
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
     * Set data type at an address.
     */
    public DataDto setDataType(Program program, String addressStr, String dataTypeName) throws Exception {
        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        DataType dataType = resolveDataType(program, dataTypeName);
        if (dataType == null) {
            throw new IllegalArgumentException("Unknown data type: " + dataTypeName);
        }

        Data data = TransactionHelper.executeInTransaction(program, "Set Data Type", () -> {
            program.getListing().clearCodeUnits(address, address.add(dataType.getLength() - 1), false);
            return program.getListing().createData(address, dataType);
        });

        return DataDto.from(data);
    }

    /**
     * Clear data at an address.
     */
    public void clearData(Program program, String addressStr) throws Exception {
        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        Data data = program.getListing().getDataAt(address);
        if (data == null) {
            throw new NotFoundException("No data at address: " + addressStr, "DATA_NOT_FOUND");
        }

        TransactionHelper.executeInTransaction(program, "Clear Data", () -> {
            program.getListing().clearCodeUnits(address, address.add(data.getLength() - 1), false);
            return null;
        });
    }

    /**
     * Resolve a data type by name.
     */
    public DataType resolveDataType(Program program, String dataTypeName) {
        DataTypeManager dtm = program.getDataTypeManager();

        // Try direct lookup
        DataType dt = dtm.getDataType("/" + dataTypeName);
        if (dt != null) return dt;

        // Try find
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(dataTypeName, found);
        if (!found.isEmpty()) return found.get(0);

        // Try built-in types
        ghidra.program.model.data.BuiltInDataTypeManager builtIn =
            ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager();
        dt = builtIn.getDataType("/" + dataTypeName);
        if (dt != null) return dt;

        return null;
    }

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
