package eu.starsong.ghidra.dto;

/** A function that (transitively) calls a string user, with its BFS depth (1 = direct caller). */
public record CallerRefDto(FunctionSummaryDto function, int depth) {
}
