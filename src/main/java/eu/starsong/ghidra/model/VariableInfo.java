package eu.starsong.ghidra.model;

/**
 * Model class representing Ghidra variable information.
 * This provides a structured object for variable data instead of using Map<String, Object>.
 */
public class VariableInfo {
    private String name;
    private String dataType;
    private String address;
    private String type; // "local", "parameter", "global", etc.
    private String function; // Function name if local/parameter
    private String storage; // Storage location
    private String value; // Value if known

    /**
     * Default constructor for serialization frameworks
     */
    public VariableInfo() {
    }

    /**
     * Constructor with essential fields
     */
    public VariableInfo(String name, String dataType, String type) {
        this.name = name;
        this.dataType = dataType;
        this.type = type;
    }

    /**
     * Full constructor
     */
    public VariableInfo(String name, String dataType, String address, String type,
                       String function, String storage, String value) {
        this.name = name;
        this.dataType = dataType;
        this.address = address;
        this.type = type;
        this.function = function;
        this.storage = storage;
        this.value = value;
    }

    /**
     * @return The variable name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name The variable name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return The variable data type
     */
    public String getDataType() {
        return dataType;
    }

    /**
     * @param dataType The variable data type
     */
    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    /**
     * @return The variable address (if applicable)
     */
    public String getAddress() {
        return address;
    }

    /**
     * @param address The variable address
     */
    public void setAddress(String address) {
        this.address = address;
    }

    /**
     * @return The variable type (local, parameter, global, etc.)
     */
    public String getType() {
        return type;
    }

    /**
     * @param type The variable type
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * @return The function name (for local variables and parameters)
     */
    public String getFunction() {
        return function;
    }

    /**
     * @param function The function name
     */
    public void setFunction(String function) {
        this.function = function;
    }

    /**
     * @return The variable storage location
     */
    public String getStorage() {
        return storage;
    }

    /**
     * @param storage The variable storage location
     */
    public void setStorage(String storage) {
        this.storage = storage;
    }

    /**
     * @return The variable value (if known)
     */
    public String getValue() {
        return value;
    }

    /**
     * @param value The variable value
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * @return Whether this variable is a local variable
     */
    public boolean isLocal() {
        return "local".equals(type);
    }

    /**
     * @return Whether this variable is a parameter
     */
    public boolean isParameter() {
        return "parameter".equals(type);
    }

    /**
     * @return Whether this variable is a global variable
     */
    public boolean isGlobal() {
        return "global".equals(type);
    }

    /**
     * Builder pattern for VariableInfo
     */
    public static class Builder {
        private String name;
        private String dataType;
        private String address;
        private String type;
        private String function;
        private String storage;
        private String value;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder dataType(String dataType) {
            this.dataType = dataType;
            return this;
        }

        public Builder address(String address) {
            this.address = address;
            return this;
        }

        public Builder type(String type) {
            this.type = type;
            return this;
        }

        public Builder function(String function) {
            this.function = function;
            return this;
        }

        public Builder storage(String storage) {
            this.storage = storage;
            return this;
        }

        public Builder value(String value) {
            this.value = value;
            return this;
        }

        public VariableInfo build() {
            return new VariableInfo(
                name, dataType, address, type,
                function, storage, value
            );
        }
    }

    /**
     * Create a new builder for VariableInfo
     * @return A new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
}
