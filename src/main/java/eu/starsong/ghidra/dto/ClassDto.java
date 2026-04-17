package eu.starsong.ghidra.dto;

public record ClassDto(String name, String namespace, String simpleName) {
    public static ClassDto fromQualifiedName(String qualifiedName) {
        int dot = qualifiedName.lastIndexOf('.');
        if (dot >= 0) {
            return new ClassDto(qualifiedName, qualifiedName.substring(0, dot), qualifiedName.substring(dot + 1));
        }
        return new ClassDto(qualifiedName, "default", qualifiedName);
    }
}
