package eu.starsong.ghidra.util;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class PageTest {

    private final List<String> items = List.of("a", "b", "c", "d", "e");

    @Test
    public void returnsRequestedWindow() {
        assertEquals(List.of("b", "c"), Page.slice(items, 1, 2));
    }

    @Test
    public void clampsLimitToRemainder() {
        assertEquals(List.of("d", "e"), Page.slice(items, 3, 10));
    }

    @Test
    public void offsetAtOrBeyondTotalIsEmpty() {
        assertTrue(Page.slice(items, 5, 10).isEmpty());
        assertTrue(Page.slice(items, 99, 10).isEmpty());
    }

    @Test
    public void zeroLimitIsEmpty() {
        assertTrue(Page.slice(items, 0, 0).isEmpty());
    }

    @Test
    public void negativeOffsetIsClampedToZero() {
        assertEquals(List.of("a", "b"), Page.slice(items, -5, 2));
    }
}
