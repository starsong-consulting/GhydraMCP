package eu.starsong.ghidra.dto;

public record ProjectDto(
    String name,
    String location,
    String projectPath,
    String rootPath,
    int fileCount,
    int folderCount
) {}
