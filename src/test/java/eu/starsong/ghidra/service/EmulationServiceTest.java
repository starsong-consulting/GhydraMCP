package eu.starsong.ghidra.service;

import org.junit.Test;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class EmulationServiceTest {
    @Test
    public void hexToBytesParsesSpacedHex() {
        assertArrayEquals(new byte[]{(byte)0xca, (byte)0xfe},
                EmulationService.hexToBytes("ca fe"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void hexToBytesRejectsOddLength() {
        EmulationService.hexToBytes("abc");
    }

    @Test
    public void toHexIsUnsignedPrefixedLowercase() {
        assertEquals("0x140075000", EmulationService.toHex(new BigInteger("140075000", 16)));
    }

    @Test
    public void toHexHandlesZeroNullAndNegative() {
        assertEquals("0x0", EmulationService.toHex(BigInteger.ZERO));
        assertNull(EmulationService.toHex(null));
        // Negative magnitudes wrap into the unsigned 64-bit range (-1 -> 0xffffffffffffffff).
        assertEquals("0xffffffffffffffff", EmulationService.toHex(BigInteger.valueOf(-1)));
    }

    @Test
    public void parseBigHandlesHexPrefixDecimalAndBareHex() {
        assertEquals(new BigInteger("140075000", 16), EmulationService.parseBig("0x140075000"));
        assertEquals(new BigInteger("140075000", 16), EmulationService.parseBig("0X140075000"));
        // A bare value is decimal first...
        assertEquals(BigInteger.valueOf(123), EmulationService.parseBig("123"));
        // ...then falls back to hex when it isn't valid decimal.
        assertEquals(new BigInteger("deadbeef", 16), EmulationService.parseBig("deadbeef"));
        assertEquals(new BigInteger("ff", 16), EmulationService.parseBig(" ff "));
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseBigRejectsNull() {
        EmulationService.parseBig(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void parseBigRejectsEmpty() {
        EmulationService.parseBig("   ");
    }
}
