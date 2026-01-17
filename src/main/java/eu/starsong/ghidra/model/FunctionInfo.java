package eu.starsong.ghidra.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Model class representing Ghidra function information.
 * This provides a structured object for function data instead of using Map<String, Object>.
 */
public class FunctionInfo {
    private String name;
    private String address;
    private String signature;
    private String returnType;
    private List<ParameterInfo> parameters;
    private String decompilation;
    private boolean isExternal;
    private String callingConvention;

    /**
     * Default constructor for serialization frameworks
     */
    public FunctionInfo() {
        this.parameters = new ArrayList<>();
    }

    /**
     * Constructor with essential fields
     */
    public FunctionInfo(String name, String address, String signature) {
        this.name = name;
        this.address = address;
        this.signature = signature;
        this.parameters = new ArrayList<>();
    }

    /**
     * Full constructor
     */
    public FunctionInfo(String name, String address, String signature, String returnType,
                       List<ParameterInfo> parameters, String decompilation,
                       boolean isExternal, String callingConvention) {
        this.name = name;
        this.address = address;
        this.signature = signature;
        this.returnType = returnType;
        this.parameters = parameters != null ? parameters : new ArrayList<>();
        this.decompilation = decompilation;
        this.isExternal = isExternal;
        this.callingConvention = callingConvention;
    }

    /**
     * @return The function name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name The function name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return The function entry point address
     */
    public String getAddress() {
        return address;
    }

    /**
     * @param address The function entry point address
     */
    public void setAddress(String address) {
        this.address = address;
    }

    /**
     * @return The function signature (prototype string)
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @param signature The function signature
     */
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * @return The function return type
     */
    public String getReturnType() {
        return returnType;
    }

    /**
     * @param returnType The function return type
     */
    public void setReturnType(String returnType) {
        this.returnType = returnType;
    }

    /**
     * @return The function parameters
     */
    public List<ParameterInfo> getParameters() {
        return parameters;
    }

    /**
     * @param parameters The function parameters
     */
    public void setParameters(List<ParameterInfo> parameters) {
        this.parameters = parameters != null ? parameters : new ArrayList<>();
    }

    /**
     * @return The decompiled C code for the function
     */
    public String getDecompilation() {
        return decompilation;
    }

    /**
     * @param decompilation The decompiled C code
     */
    public void setDecompilation(String decompilation) {
        this.decompilation = decompilation;
    }

    /**
     * @return Whether the function is external (imported)
     */
    public boolean isExternal() {
        return isExternal;
    }

    /**
     * @param external Whether the function is external
     */
    public void setExternal(boolean external) {
        isExternal = external;
    }

    /**
     * @return The function's calling convention
     */
    public String getCallingConvention() {
        return callingConvention;
    }

    /**
     * @param callingConvention The function's calling convention
     */
    public void setCallingConvention(String callingConvention) {
        this.callingConvention = callingConvention;
    }

    /**
     * Add a parameter to the function
     * @param parameter The parameter to add
     */
    public void addParameter(ParameterInfo parameter) {
        if (parameter != null) {
            this.parameters.add(parameter);
        }
    }

    /**
     * Builder pattern for FunctionInfo
     */
    public static class Builder {
        private String name;
        private String address;
        private String signature;
        private String returnType;
        private List<ParameterInfo> parameters = new ArrayList<>();
        private String decompilation;
        private boolean isExternal;
        private String callingConvention;

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder address(String address) {
            this.address = address;
            return this;
        }

        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }

        public Builder returnType(String returnType) {
            this.returnType = returnType;
            return this;
        }

        public Builder parameters(List<ParameterInfo> parameters) {
            this.parameters = parameters;
            return this;
        }

        public Builder addParameter(ParameterInfo parameter) {
            this.parameters.add(parameter);
            return this;
        }

        public Builder decompilation(String decompilation) {
            this.decompilation = decompilation;
            return this;
        }

        public Builder isExternal(boolean isExternal) {
            this.isExternal = isExternal;
            return this;
        }

        public Builder callingConvention(String callingConvention) {
            this.callingConvention = callingConvention;
            return this;
        }

        public FunctionInfo build() {
            return new FunctionInfo(
                name, address, signature, returnType,
                parameters, decompilation, isExternal,
                callingConvention
            );
        }
    }

    /**
     * Create a new builder for FunctionInfo
     * @return A new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Inner class representing function parameter information
     */
    public static class ParameterInfo {
        private String name;
        private String dataType;
        private int ordinal;
        private String storage;

        /**
         * Default constructor for serialization frameworks
         */
        public ParameterInfo() {
        }

        /**
         * Full constructor
         */
        public ParameterInfo(String name, String dataType, int ordinal, String storage) {
            this.name = name;
            this.dataType = dataType;
            this.ordinal = ordinal;
            this.storage = storage;
        }

        /**
         * @return The parameter name
         */
        public String getName() {
            return name;
        }

        /**
         * @param name The parameter name
         */
        public void setName(String name) {
            this.name = name;
        }

        /**
         * @return The parameter data type
         */
        public String getDataType() {
            return dataType;
        }

        /**
         * @param dataType The parameter data type
         */
        public void setDataType(String dataType) {
            this.dataType = dataType;
        }

        /**
         * @return The parameter position (0-based)
         */
        public int getOrdinal() {
            return ordinal;
        }

        /**
         * @param ordinal The parameter position
         */
        public void setOrdinal(int ordinal) {
            this.ordinal = ordinal;
        }

        /**
         * @return The parameter storage location
         */
        public String getStorage() {
            return storage;
        }

        /**
         * @param storage The parameter storage location
         */
        public void setStorage(String storage) {
            this.storage = storage;
        }

        /**
         * Builder pattern for ParameterInfo
         */
        public static class Builder {
            private String name;
            private String dataType;
            private int ordinal;
            private String storage;

            public Builder name(String name) {
                this.name = name;
                return this;
            }

            public Builder dataType(String dataType) {
                this.dataType = dataType;
                return this;
            }

            public Builder ordinal(int ordinal) {
                this.ordinal = ordinal;
                return this;
            }

            public Builder storage(String storage) {
                this.storage = storage;
                return this;
            }

            public ParameterInfo build() {
                return new ParameterInfo(name, dataType, ordinal, storage);
            }
        }

        /**
         * Create a new builder for ParameterInfo
         * @return A new builder instance
         */
        public static Builder builder() {
            return new Builder();
        }
    }
}
