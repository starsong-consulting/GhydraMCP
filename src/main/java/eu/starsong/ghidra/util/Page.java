package eu.starsong.ghidra.util;

import java.util.Collections;
import java.util.List;

/** Pure pagination helper: returns the in-range window of a list for an offset/limit. */
public final class Page {

    private Page() {
    }

    /**
     * Returns the sublist starting at {@code offset} (clamped to {@code [0, size]}) with at
     * most {@code limit} elements. Returns an empty list when the window is out of range.
     */
    public static <T> List<T> slice(List<T> items, int offset, int limit) {
        int total = items.size();
        int start = Math.max(0, Math.min(offset, total));
        int end = Math.min(total, start + Math.max(0, limit));
        return start < end ? items.subList(start, end) : Collections.emptyList();
    }
}
