package eu.starsong.ghidra.dto;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

public record DisassemblyInstructionDto(
    String address,
    String bytes,
    String mnemonic,
    String operands
) {
    public static DisassemblyInstructionDto from(Instruction instr, Program program) {
        String hex;
        try {
            byte[] raw = new byte[instr.getLength()];
            program.getMemory().getBytes(instr.getAddress(), raw);
            StringBuilder sb = new StringBuilder();
            for (byte b : raw) sb.append(String.format("%02X", b & 0xFF));
            hex = sb.toString();
        } catch (Exception e) {
            hex = "";
        }
        String mnemonic = instr.getMnemonicString();
        StringBuilder ops = new StringBuilder();
        int n = instr.getNumOperands();
        for (int i = 0; i < n; i++) {
            if (i > 0) ops.append(", ");
            ops.append(instr.getDefaultOperandRepresentation(i));
        }
        String operands = ops.toString();
        return new DisassemblyInstructionDto(
            instr.getAddress().toString(), hex, mnemonic, operands);
    }
}
