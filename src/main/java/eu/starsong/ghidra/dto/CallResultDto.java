package eu.starsong.ghidra.dto;

import java.util.List;
import java.util.Map;
import eu.starsong.ghidra.service.EmulationService.MemWrite;

public class CallResultDto {
    public String return_value;
    public String convention;
    public List<String> args_passed;
    public Map<String, String> final_registers;
    public List<MemWrite> mem_writes;
    public EmulationStateDto.StopReason stop_reason;
    public String detail;
}
