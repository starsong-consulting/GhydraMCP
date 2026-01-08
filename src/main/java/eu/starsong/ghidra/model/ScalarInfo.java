package eu.starsong.ghidra.model;

/**
 * Model class representing a scalar (constant) value occurrence in the binary.
 * This provides a structured object for scalar search results.
 */
public class ScalarInfo {
    private String address;
    private long value;
    private String hexValue;
    private int bitLength;
    private boolean signed;
    private int operandIndex;
    private String instruction;
    private String inFunction;
    private String inFunctionAddress;
    private String toFunction;
    private String toFunctionAddress;

    /**
     * Default constructor for serialization frameworks
     */
    public ScalarInfo() {
    }

    /**
     * Full constructor
     */
    public ScalarInfo(String address, long value, String hexValue, int bitLength,
                      boolean signed, int operandIndex, String instruction,
                      String inFunction, String inFunctionAddress,
                      String toFunction, String toFunctionAddress) {
        this.address = address;
        this.value = value;
        this.hexValue = hexValue;
        this.bitLength = bitLength;
        this.signed = signed;
        this.operandIndex = operandIndex;
        this.instruction = instruction;
        this.inFunction = inFunction;
        this.inFunctionAddress = inFunctionAddress;
        this.toFunction = toFunction;
        this.toFunctionAddress = toFunctionAddress;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public long getValue() {
        return value;
    }

    public void setValue(long value) {
        this.value = value;
    }

    public String getHexValue() {
        return hexValue;
    }

    public void setHexValue(String hexValue) {
        this.hexValue = hexValue;
    }

    public int getBitLength() {
        return bitLength;
    }

    public void setBitLength(int bitLength) {
        this.bitLength = bitLength;
    }

    public boolean isSigned() {
        return signed;
    }

    public void setSigned(boolean signed) {
        this.signed = signed;
    }

    public int getOperandIndex() {
        return operandIndex;
    }

    public void setOperandIndex(int operandIndex) {
        this.operandIndex = operandIndex;
    }

    public String getInstruction() {
        return instruction;
    }

    public void setInstruction(String instruction) {
        this.instruction = instruction;
    }

    public String getInFunction() {
        return inFunction;
    }

    public void setInFunction(String inFunction) {
        this.inFunction = inFunction;
    }

    public String getInFunctionAddress() {
        return inFunctionAddress;
    }

    public void setInFunctionAddress(String inFunctionAddress) {
        this.inFunctionAddress = inFunctionAddress;
    }

    public String getToFunction() {
        return toFunction;
    }

    public void setToFunction(String toFunction) {
        this.toFunction = toFunction;
    }

    public String getToFunctionAddress() {
        return toFunctionAddress;
    }

    public void setToFunctionAddress(String toFunctionAddress) {
        this.toFunctionAddress = toFunctionAddress;
    }

    /**
     * Builder pattern for ScalarInfo
     */
    public static class Builder {
        private String address;
        private long value;
        private String hexValue;
        private int bitLength;
        private boolean signed;
        private int operandIndex;
        private String instruction;
        private String inFunction;
        private String inFunctionAddress;
        private String toFunction;
        private String toFunctionAddress;

        public Builder address(String address) {
            this.address = address;
            return this;
        }

        public Builder value(long value) {
            this.value = value;
            this.hexValue = String.format("0x%x", value);
            return this;
        }

        public Builder bitLength(int bitLength) {
            this.bitLength = bitLength;
            return this;
        }

        public Builder signed(boolean signed) {
            this.signed = signed;
            return this;
        }

        public Builder operandIndex(int operandIndex) {
            this.operandIndex = operandIndex;
            return this;
        }

        public Builder instruction(String instruction) {
            this.instruction = instruction;
            return this;
        }

        public Builder inFunction(String inFunction) {
            this.inFunction = inFunction;
            return this;
        }

        public Builder inFunctionAddress(String inFunctionAddress) {
            this.inFunctionAddress = inFunctionAddress;
            return this;
        }

        public Builder toFunction(String toFunction) {
            this.toFunction = toFunction;
            return this;
        }

        public Builder toFunctionAddress(String toFunctionAddress) {
            this.toFunctionAddress = toFunctionAddress;
            return this;
        }

        public ScalarInfo build() {
            return new ScalarInfo(
                address, value, hexValue, bitLength,
                signed, operandIndex, instruction,
                inFunction, inFunctionAddress,
                toFunction, toFunctionAddress
            );
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
