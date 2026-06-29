package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.StringUsageDto;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class StringUsageWalkerTest {

    private StringUsageDto.StringRef ref() {
        return new StringUsageDto.StringRef("0x8000", "CreateFileW");
    }

    private StringUsageWalker.WalkState state(int budget) {
        return new StringUsageWalker.WalkState(budget);
    }

    @Test
    public void directUsersOnlyWhenCallerDepthZero() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000", "0x1000", "0x2000")); // dup 0x1000 deduped
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 0, state(500));
        assertEquals(2, u.directUsers().size());
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void countsNullReferencesAsUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", Arrays.asList("0x1000", null, null));
        StringUsageWalker.WalkState s = state(500);
        new StringUsageWalker(g).resolve(ref(), 0, s);
        assertEquals(2, s.unresolvedRefs());
    }

    @Test
    public void walksCallersWithAscendingDepth() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000"));
        g.callers.put("0x2000", List.of("0x3000"));
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 2, state(500));
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
        g.callers.put("0x1000", List.of("0x1000", "0x2000")); // 0x1000 is direct user
        StringUsageWalker.WalkState s = state(500);
        s.globalVisited.add("0x2000"); // pre-seed as if seen by a prior string
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 1, s);
        assertTrue(u.callers().isEmpty());
    }

    @Test
    public void budgetExhaustionTruncatesAndReturnsPartialCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000", "0x3000", "0x4000"));
        StringUsageWalker.WalkState s = state(2);
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 1, s);
        assertEquals(2, u.callers().size());
        assertTrue(s.truncated());
    }

    @Test
    public void zeroInitialBudgetTruncatesImmediatelyWithNoCallers() {
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000"));
        StringUsageWalker.WalkState s = state(0);
        StringUsageDto u = new StringUsageWalker(g).resolve(ref(), 1, s);
        assertEquals(1, u.directUsers().size()); // direct users unaffected by budget
        assertTrue(u.callers().isEmpty());
        assertTrue(s.truncated());
    }

    @Test
    public void exhaustedBudgetEntryAddedToGlobalVisitedPreventsCascade() {
        // When budget hits 0 on callerEntry X, X must be added to globalVisited
        // so a subsequent string that also has X as a caller doesn't re-trigger.
        FakeCallGraph g = new FakeCallGraph();
        g.referrers.put("0x8000", List.of("0x1000"));
        g.callers.put("0x1000", List.of("0x2000")); // 0x2000 triggers budget=0
        StringUsageWalker.WalkState s = state(0); // budget already exhausted
        new StringUsageWalker(g).resolve(ref(), 1, s);
        assertTrue("0x2000 should be in globalVisited to prevent cascade",
            s.globalVisited.contains("0x2000"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void negativeBudgetThrows() {
        new StringUsageWalker.WalkState(-1);
    }
}
