package eu.starsong.ghidra.dto;

import java.util.Objects;

/** A function that (transitively) calls a string user, with its BFS depth (1 = direct caller). */
public record CallerRefDto(FunctionSummaryDto function, int depth) {
    public CallerRefDto {
        Objects.requireNonNull(function, "function");
        if (depth < 1) {
            throw new IllegalArgumentException("depth must be >= 1, was " + depth);
        }
    }
}
