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
        assertThrows(UnsupportedOperationException.class,
            () -> p.functions().add(fn("d", "0x4000")));
    }

    @Test
    public void callPathCanonicalConstructorRejectsLengthMismatch() {
        // The canonical constructor (used by Gson deserialization and direct callers)
        // must enforce length == functions.size(), not only the of() factory.
        assertThrows(IllegalArgumentException.class,
            () -> new CallPathDto(99, List.of(fn("a", "0x1000"), fn("b", "0x2000"))));
    }

    @Test
    public void callPathCanonicalConstructorCopiesToImmutable() {
        List<FunctionSummaryDto> src = new java.util.ArrayList<>(List.of(fn("a", "0x1000")));
        CallPathDto p = new CallPathDto(1, src);
        src.add(fn("b", "0x2000"));                 // mutating the source must not leak in
        assertEquals(1, p.functions().size());
        assertThrows(UnsupportedOperationException.class, () -> p.functions().add(fn("c", "0x3000")));
    }

    @Test
    public void callerRefCarriesDepth() {
        CallerRefDto c = new CallerRefDto(fn("caller", "0x4000"), 2);
        assertEquals(2, c.depth());
        assertEquals("caller", c.function().name());
    }

    @Test
    public void callerRefRejectsNonPositiveDepthAndNullFunction() {
        assertThrows(IllegalArgumentException.class, () -> new CallerRefDto(fn("c", "0x4000"), 0));
        assertThrows(NullPointerException.class, () -> new CallerRefDto(null, 1));
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

    @Test
    public void stringUsageCopiesListsToImmutable() {
        StringUsageDto u = new StringUsageDto(
            new StringUsageDto.StringRef("0x8000", "s"),
            new java.util.ArrayList<>(List.of(fn("user", "0x5000"))),
            new java.util.ArrayList<>());
        assertThrows(UnsupportedOperationException.class, () -> u.directUsers().add(fn("x", "0x9000")));
        assertThrows(UnsupportedOperationException.class,
            () -> u.callers().add(new CallerRefDto(fn("y", "0xa000"), 1)));
    }

    @Test
    public void stringRefProjectsFromDataDto() {
        DataDto d = new DataDto("0x402000", "msg", "char[4]", "Hello", 4, true, null);
        StringUsageDto.StringRef ref = StringUsageDto.StringRef.from(d);
        assertEquals("0x402000", ref.address());
        assertEquals("Hello", ref.value());
    }
}
