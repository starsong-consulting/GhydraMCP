package eu.starsong.ghidra.dto;

import ghidra.program.model.mem.MemoryBlock;

/**
 * Data transfer object for memory block/segment information.
 */
public record MemoryBlockDto(
    String name,
    String start,
    String end,
    long size,
    boolean isRead,
    boolean isWrite,
    boolean isExecute,
    boolean isVolatile,
    boolean isInitialized,
    String sourceType,
    String comment
) {
    /**
     * Create a MemoryBlockDto from a Ghidra MemoryBlock.
     */
    public static MemoryBlockDto from(MemoryBlock block) {
        if (block == null) return null;

        return new MemoryBlockDto(
            block.getName(),
            block.getStart().toString(),
            block.getEnd().toString(),
            block.getSize(),
            block.isRead(),
            block.isWrite(),
            block.isExecute(),
            block.isVolatile(),
            block.isInitialized(),
            block.getSourceName(),
            block.getComment()
        );
    }

    /**
     * Get permissions as a string (e.g., "rwx", "r-x").
     */
    public String permissions() {
        return (isRead ? "r" : "-") +
               (isWrite ? "w" : "-") +
               (isExecute ? "x" : "-");
    }
}
