package eu.starsong.ghidra.service.graph;

import org.junit.Test;

import static org.junit.Assert.*;

public class GhidraCallGraphConstructorTest {

    @Test(expected = NullPointerException.class)
    public void nullProgramThrows() {
        new GhidraCallGraph(null, null, null);
    }
}
