package eu.starsong.ghidra.dto;

public record VariableDto(
    String name,
    String address,
    String type,      // "global", "local", "parameter"
    String dataType,
    String function   // null for globals
) {
    public static VariableDto global(String name, String address, String dataType) {
        return new VariableDto(name, address, "global", dataType, null);
    }

    public static VariableDto local(String name, String address, String dataType, String function, boolean isParameter) {
        return new VariableDto(name, address, isParameter ? "parameter" : "local", dataType, function);
    }
}
