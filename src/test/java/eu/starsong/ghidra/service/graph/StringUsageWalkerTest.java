package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.StringUsageDto;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class StringUsageWalkerTest {

    private StringUsageDto.StringRef ref() {
        return new StringUsageDto.StringRef("0x8000", "CreateFileW");
    }

    @Test
    public void directUsersOnlyWhenCallerDepthZero() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000", "0x1000", "0x2000")); // dup 0x1000 deduped
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 0, new int[]{500}, new HashSet<>(), new int[]{0}, new boolean[]{false});
        assertEquals(2, u.directUsers().size());
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void countsNullReferencesAsUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", Arrays.asList("0x1000", null, null));
        int[] unresolved = {0};
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 0, new int[]{500}, new HashSet<>(), unresolved, new boolean[]{false});
        assertEquals(1, u.directUsers().size());
        assertEquals(2, unresolved[0]);
    }

    @Test
    public void walksCallersWithAscendingDepth() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));   // direct user
        g.callers.put("0x1000", List.of("0x2000"));      // depth 1
        g.callers.put("0x2000", List.of("0x3000"));      // depth 2
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 2, new int[]{500}, new HashSet<>(), new int[]{0}, new boolean[]{false});
        assertEquals(2, u.callers().size());
        assertEquals("0x2000", u.callers().get(0).function().address());
        assertEquals(1, u.callers().get(0).depth());
        assertEquals("0x3000", u.callers().get(1).function().address());
        assertEquals(2, u.callers().get(1).depth());
    }

    @Test
    public void doesNotRevisitDirectUsersOrGloballyVisitedCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x1000", "0x2000")); // 0x1000 is a direct user -> skipped
        Set<String> globalVisited = new HashSet<>();
        globalVisited.add("0x2000"); // already seen by a previous string -> skipped
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 1, new int[]{500}, globalVisited, new int[]{0}, new boolean[]{false});
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void budgetExhaustionTruncatesAndReturnsPartialCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000", "0x3000", "0x4000"));
        int[] budget = {2};
        boolean[] truncated = {false};
        StringUsageDto u = new StringUsageWalker(g).resolve(
            ref(), 1, budget, new HashSet<>(), new int[]{0}, truncated);
        assertEquals(2, u.callers().size()); // only 2 fit the budget
        assertTrue(truncated[0]);
        assertEquals(0, budget[0]);
    }
}
