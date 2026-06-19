package eu.starsong.ghidra.service;

import org.junit.Test;
import java.math.BigInteger;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

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
    public void toHexIsUnsignedZeroPaddedPrefixed() {
        assertEquals("0x140075000", EmulationService.toHex(new BigInteger("140075000", 16)));
    }
}
