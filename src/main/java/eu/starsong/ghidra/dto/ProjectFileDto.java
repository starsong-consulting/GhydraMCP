package eu.starsong.ghidra.dto;

public record ProjectFileDto(
    String name,
    String path,
    String type,          // "file" or "folder"
    String contentType,   // null for folders
    Boolean isProgram,
    Boolean isOpen,
    String fileId,
    Integer version,
    Long modificationTime
) {
    public static ProjectFileDto folder(String name, String path) {
        return new ProjectFileDto(name, path, "folder", null, null, null, null, null, null);
    }
}
