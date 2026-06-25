package eu.starsong.ghidra.dto;

import org.junit.Test;
import java.util.List;
import static org.junit.Assert.*;

public class CompoundReDtoTest {

    private FunctionSummaryDto fn(String name, String addr) {
        return new FunctionSummaryDto(name, addr, name + "(void)", "void", false, false, 0);
    }

    @Test
    public void callPathOfSetsLengthToNodeCount() {
        CallPathDto p = CallPathDto.of(List.of(fn("a", "0x1000"), fn("b", "0x2000"), fn("c", "0x3000")));
        assertEquals(3, p.length());
        assertEquals(3, p.functions().size());
        assertEquals("a", p.functions().get(0).name());
    }

    @Test
    public void callerRefCarriesDepth() {
        CallerRefDto c = new CallerRefDto(fn("caller", "0x4000"), 2);
        assertEquals(2, c.depth());
        assertEquals("caller", c.function().name());
    }

    @Test
    public void stringUsageHoldsRefUsersAndCallers() {
        StringUsageDto u = new StringUsageDto(
            new StringUsageDto.StringRef("0x8000", "CreateFileW"),
            List.of(fn("user", "0x5000")),
            List.of(new CallerRefDto(fn("up", "0x6000"), 1)));
        assertEquals("0x8000", u.string().address());
        assertEquals("CreateFileW", u.string().value());
        assertEquals(1, u.directUsers().size());
        assertEquals(1, u.callers().get(0).depth());
    }
}
