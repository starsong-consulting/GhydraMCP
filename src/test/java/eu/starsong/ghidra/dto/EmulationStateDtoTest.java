package eu.starsong.ghidra.dto;

import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.assertEquals;

public class EmulationStateDtoTest {
    @Test
    public void ofPopulatesAllFields() {
        EmulationStateDto dto = EmulationStateDto.of(
            "0x140075000", "BREAKPOINT", 42L,
            Map.of("RIP", "0x140075000"), List.of("0x140074000", "0x140074002"), null);
        assertEquals("0x140075000", dto.pc());
        assertEquals("BREAKPOINT", dto.stopReason());
        assertEquals(42L, dto.steps());
        assertEquals("0x140075000", dto.registers().get("RIP"));
        assertEquals(2, dto.trace().size());
    }
}
