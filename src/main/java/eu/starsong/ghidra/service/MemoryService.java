package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.MemoryBlockDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import eu.starsong.ghidra.util.GhidraSwing;
import eu.starsong.ghidra.util.GhidraUtil;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.Arrays;
import java.util.List;

/**
 * Service for memory-related operations.
 */
public class MemoryService {

    /**
     * List all memory blocks/segments.
     */
    public List<MemoryBlockDto> listBlocks(Program program) {
        Memory memory = program.getMemory();
        return GhidraSwing.runRead(() -> Arrays.stream(memory.getBlocks())
            .map(MemoryBlockDto::from)
            .toList());
    }

    /**
     * Get a memory block by name.
     */
    public MemoryBlockDto getBlockByName(Program program, String name) {
        return GhidraSwing.runRead(() -> {
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(name);
            if (block == null) {
                throw new NotFoundException("Memory block not found: " + name, "BLOCK_NOT_FOUND");
            }
            return MemoryBlockDto.from(block);
        });
    }

    /**
     * Get the memory block containing an address.
     */
    public MemoryBlockDto getBlockContaining(Program program, String addressStr) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        return GhidraSwing.runRead(() -> {
            Memory memory = program.getMemory();
            MemoryBlock block = memory.getBlock(address);
            if (block == null) {
                throw new NotFoundException("No memory block at address: " + addressStr, "BLOCK_NOT_FOUND");
            }
            return MemoryBlockDto.from(block);
        });
    }

    /**
     * Read bytes from memory.
     */
    public byte[] readBytes(Program program, String addressStr, int length) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        return GhidraSwing.runRead(() -> {
            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            try {
                int bytesRead = memory.getBytes(address, bytes);
                if (bytesRead < length) {
                    byte[] result = new byte[bytesRead];
                    System.arraycopy(bytes, 0, result, 0, bytesRead);
                    return result;
                }
                return bytes;
            } catch (Exception e) {
                throw new RuntimeException("Failed to read memory at " + addressStr + ": " + e.getMessage(), e);
            }
        });
    }

    /**
     * Read bytes as hex string.
     */
    public String readBytesAsHex(Program program, String addressStr, int length) {
        byte[] bytes = readBytes(program, addressStr, length);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * Write bytes to memory. Input is a hex string (space/non-hex chars stripped).
     */
    public int writeBytes(Program program, String addressStr, String hexBytes) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        if (hexBytes == null || hexBytes.isEmpty()) {
            throw new IllegalArgumentException("bytes is required");
        }
        String cleaned = hexBytes.replaceAll("[^0-9a-fA-F]", "");
        if (cleaned.length() % 2 != 0) {
            throw new IllegalArgumentException("hex byte string must have even length");
        }
        byte[] data = new byte[cleaned.length() / 2];
        for (int i = 0; i < cleaned.length(); i += 2) {
            data[i / 2] = (byte) Integer.parseInt(cleaned.substring(i, i + 2), 16);
        }
        Address finalAddress = address;
        byte[] finalData = data;
        return TransactionHelper.executeInTransaction(program,
            "Write memory at " + addressStr, () -> {
                program.getMemory().setBytes(finalAddress, finalData);
                return finalData.length;
            });
    }

    /**
     * Disassemble instructions starting at an address.
     */
    public List<eu.starsong.ghidra.dto.DisassemblyInstructionDto> disassembleAt(
            Program program, String addressStr, int limit) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        Address finalAddress = address;
        return GhidraSwing.runRead(() -> {
            List<eu.starsong.ghidra.dto.DisassemblyInstructionDto> results = new java.util.ArrayList<>();
            var instrIter = program.getListing().getInstructions(finalAddress, true);
            int collected = 0;
            while (instrIter.hasNext() && (limit <= 0 || collected < limit)) {
                var instr = instrIter.next();
                results.add(eu.starsong.ghidra.dto.DisassemblyInstructionDto.from(instr, program));
                collected++;
            }
            return results;
        });
    }

    /**
     * Get a comment at an address of the given type.
     */
    public String getComment(Program program, String addressStr, String commentType) {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        CommentType type = parseCommentType(commentType);
        return GhidraSwing.runRead(() -> {
            return program.getListing().getComment(type, address);
        });
    }

    /**
     * Set a comment at an address of the given type.
     */
    public void setComment(Program program, String addressStr, String commentType, String comment) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        CommentType type = parseCommentType(commentType);
        TransactionHelper.executeInTransaction(program,
            "Set " + commentType + " comment at " + addressStr, () -> {
                program.getListing().setComment(address, type, comment);
                return null;
            });
    }

    private CommentType parseCommentType(String s) {
        if (s == null) throw new IllegalArgumentException("comment_type is required");
        return switch (s.toLowerCase()) {
            case "plate" -> CommentType.PLATE;
            case "pre" -> CommentType.PRE;
            case "post" -> CommentType.POST;
            case "eol" -> CommentType.EOL;
            case "repeatable" -> CommentType.REPEATABLE;
            default -> throw new IllegalArgumentException("Invalid comment type: " + s);
        };
    }

    /**
     * Search for bytes in memory.
     */
    public List<String> searchBytes(Program program, byte[] pattern, int maxResults) {
        Memory memory = program.getMemory();
        return GhidraSwing.runRead(() -> {
            List<String> results = new java.util.ArrayList<>();

            Address start = program.getMinAddress();
            Address end = program.getMaxAddress();

            Address found = memory.findBytes(start, end, pattern, null, true, null);
            while (found != null && results.size() < maxResults) {
                results.add(found.toString());
                try {
                    found = memory.findBytes(found.add(1), end, pattern, null, true, null);
                } catch (Exception e) {
                    break;
                }
            }

            return results;
        });
    }
}
