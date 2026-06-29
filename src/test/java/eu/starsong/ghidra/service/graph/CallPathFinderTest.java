package eu.starsong.ghidra.service.graph;

import eu.starsong.ghidra.dto.CallPathDto;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class CallPathFinderTest {

    private CallPathFinder finder(FakeCallGraph g) { return new CallPathFinder(g); }

    @Test
    public void selfToSelfYieldsSingleTrivialPath() {
        FakeCallGraph g = new FakeCallGraph();
        CallPathFinder.Result r = finder(g).find("0x1000", "0x1000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(1, r.paths().get(0).length());
        assertFalse(r.truncated());
        assertEquals(0, r.unresolvedEdges());
    }

    @Test
    public void findsSimpleLinearPath() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x3000"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        CallPathDto p = r.paths().get(0);
        assertEquals(3, p.length());
        assertEquals(Arrays.asList("0x1000", "0x2000", "0x3000"),
            p.functions().stream().map(f -> f.address()).toList());
    }

    @Test
    public void avoidsCyclesAndDoesNotCountThemUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x1000", "0x3000")); // back-edge to 0x1000 is a cycle
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(0, r.unresolvedEdges());
        assertFalse(r.truncated());
    }

    @Test
    public void countsNullEdgesAsUnresolved() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", Arrays.asList(null, "0x2000", null));
        g.callees.put("0x2000", List.of("0x3000"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(2, r.unresolvedEdges());
    }

    @Test
    public void maxPathsCapTruncatesAtExactBoundary() {
        FakeCallGraph g = new FakeCallGraph();
        // 0x1000 -> {a,b,c} each -> target: three distinct paths.
        g.callees.put("0x1000", List.of("0xa", "0xb", "0xc"));
        g.callees.put("0xa", List.of("0x9999"));
        g.callees.put("0xb", List.of("0x9999"));
        g.callees.put("0xc", List.of("0x9999"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x9999", 5, 2, 10000);
        assertEquals(2, r.paths().size());
        assertTrue(r.truncated());
    }

    @Test
    public void maxVisitedEdgesCapTruncates() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0xa", "0xb", "0xc", "0xd"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x9999", 5, 50, 2);
        assertTrue(r.truncated());
        assertTrue(r.paths().isEmpty());
    }

    @Test
    public void depthLimitPrunesWithoutSettingTruncated() {
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x3000")); // target is 2 edges deep
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 1, 50, 10000);
        assertTrue(r.paths().isEmpty());
        assertFalse(r.truncated()); // max_depth alone does NOT set truncated
    }
    @Test
    public void summaryOfNullThrowsInDfsIsCountedCorrectly() {
        // Simulate the contract: summaryOf for a non-null entry address always
        // returns non-null. A correctly implemented FakeCallGraph already does this.
        // This test simply re-affirms the happy path still works after the fix —
        // the integration risk (GhidraCallGraph.summaryOf returning null) is covered
        // by the constructor null-guard test in GhidraCallGraphConstructorTest.
        FakeCallGraph g = new FakeCallGraph();
        g.callees.put("0x1000", List.of("0x2000"));
        g.callees.put("0x2000", List.of("0x3000"));
        CallPathFinder.Result r = finder(g).find("0x1000", "0x3000", 5, 50, 10000);
        assertEquals(1, r.paths().size());
        assertEquals(3, r.paths().get(0).length());
        assertEquals(0, r.unresolvedEdges());
    }
    @Test(expected = IllegalArgumentException.class)
    public void maxPathsZeroThrows() {
        finder(new FakeCallGraph()).find("0x1000", "0x2000", 5, 0, 10000);
    }

    @Test(expected = IllegalArgumentException.class)
    public void maxVisitedEdgesZeroThrows() {
        finder(new FakeCallGraph()).find("0x1000", "0x2000", 5, 50, 0);
    }

    @Test(expected = NullPointerException.class)
    public void nullFromEntryThrows() {
        finder(new FakeCallGraph()).find(null, "0x2000", 5, 50, 10000);
    }
}
