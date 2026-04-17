package eu.starsong.ghidra.util;

import org.junit.Test;

import java.util.regex.Matcher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Pure-logic tests for GhidraUtil helpers that don't need a live Program.
 * Targets the parsing edge cases flagged during the Javalin port:
 *   - hex/decimal/bare-hex addresses
 *   - primitive type aliases (byte/dword/uint64_t/...)
 */
public class GhidraUtilTest {

    // ---- parseAddressOffset ------------------------------------------------

    @Test
    public void parseAddressOffset_withHexPrefix() {
        assertEquals(Long.valueOf(0x401000L), GhidraUtil.parseAddressOffset("0x401000"));
        assertEquals(Long.valueOf(0x401000L), GhidraUtil.parseAddressOffset("0X401000"));
    }

    @Test
    public void parseAddressOffset_bareHexIsHex() {
        // Main's semantics (commit 42e7082): bare hex-looking strings are hex.
        assertEquals(Long.valueOf(0x401000L), GhidraUtil.parseAddressOffset("401000"));
        assertEquals(Long.valueOf(0xdeadbeefL), GhidraUtil.parseAddressOffset("deadbeef"));
        assertEquals(Long.valueOf(0xABCDL), GhidraUtil.parseAddressOffset("ABCD"));
    }

    @Test
    public void parseAddressOffset_bareDigitsAreHex() {
        // Intentional semantics from main: a pure-digit string is hex-looking
        // (matches ^[0-9a-fA-F]+$), so it is parsed as hex. "12345" -> 0x12345.
        // Decimal only applies when the string contains no hex-only characters
        // (and doesn't fit the hex pattern at all).
        assertEquals(Long.valueOf(0x12345L), GhidraUtil.parseAddressOffset("12345"));
    }

    @Test
    public void parseAddressOffset_nonHexDecimal() {
        // Strings with non-hex-looking characters fall through to decimal.
        // (No realistic address input hits this path, but the fallback exists.)
        assertEquals(Long.valueOf(-5L), GhidraUtil.parseAddressOffset("-5"));
    }

    @Test
    public void parseAddressOffset_nullAndEmpty() {
        assertNull(GhidraUtil.parseAddressOffset(null));
        assertNull(GhidraUtil.parseAddressOffset(""));
        assertNull(GhidraUtil.parseAddressOffset("   "));
    }

    @Test
    public void parseAddressOffset_invalidReturnsNull() {
        assertNull(GhidraUtil.parseAddressOffset("not-a-number"));
        assertNull(GhidraUtil.parseAddressOffset("0xZZZZ"));
    }

    @Test
    public void parseAddressOffset_largeUnsigned() {
        // Addresses can exceed Long.MAX_VALUE signed — parseUnsignedLong handles this.
        assertEquals(Long.valueOf(0xFFFFFFFFFFFFFFFFL), GhidraUtil.parseAddressOffset("0xFFFFFFFFFFFFFFFF"));
    }

    @Test
    public void parseAddressOffset_trimsWhitespace() {
        assertEquals(Long.valueOf(0x401000L), GhidraUtil.parseAddressOffset("  0x401000  "));
    }

    // ---- resolvePrimitiveAlias --------------------------------------------
    //
    // Ghidra's primitive DataType classes (ByteDataType, DWordDataType, ...)
    // run static init that pulls in SettingsImpl -> javax.help -> a deep stack
    // we can't realistically recreate in isolated unit tests. So we only test
    // the fall-through path here (unknown names return null without triggering
    // any DataType construction). The happy-path "known alias resolves" is
    // covered by the Python integration suite exercising resolveDataType.

    @Test
    public void resolvePrimitiveAlias_unknownReturnsNull() {
        assertNull(GhidraUtil.resolvePrimitiveAlias("not_a_type"));
        assertNull(GhidraUtil.resolvePrimitiveAlias("MyCustomStruct"));
        assertNull(GhidraUtil.resolvePrimitiveAlias(""));
    }

    // ---- ARRAY_TYPE_PATTERN -----------------------------------------------

    @Test
    public void arrayPattern_matchesSimpleArray() {
        Matcher m = GhidraUtil.ARRAY_TYPE_PATTERN.matcher("uint64_t[8]");
        assertTrue(m.matches());
        assertEquals("uint64_t", m.group(1));
        assertEquals("8", m.group(2));
    }

    @Test
    public void arrayPattern_matchesMultiDimensional() {
        // Outer dimension matches first; inner remains as base.
        Matcher outer = GhidraUtil.ARRAY_TYPE_PATTERN.matcher("int[4][2]");
        assertTrue(outer.matches());
        assertEquals("int[4]", outer.group(1));
        assertEquals("2", outer.group(2));

        Matcher inner = GhidraUtil.ARRAY_TYPE_PATTERN.matcher("int[4]");
        assertTrue(inner.matches());
        assertEquals("int", inner.group(1));
        assertEquals("4", inner.group(2));
    }

    @Test
    public void arrayPattern_rejectsNonArray() {
        assertFalse(GhidraUtil.ARRAY_TYPE_PATTERN.matcher("uint64_t").matches());
        assertFalse(GhidraUtil.ARRAY_TYPE_PATTERN.matcher("char*").matches());
        assertFalse(GhidraUtil.ARRAY_TYPE_PATTERN.matcher("int[]").matches());
    }

    @Test
    public void arrayPattern_matchesEmptyBase_downstreamRejects() {
        // The regex itself matches "[8]" (base group captures the empty string),
        // but resolveDataType short-circuits on baseTypeName.isEmpty(). Documents the
        // split of responsibility between regex and caller.
        Matcher m = GhidraUtil.ARRAY_TYPE_PATTERN.matcher("[8]");
        assertTrue(m.matches());
        assertEquals("", m.group(1));
    }

}
