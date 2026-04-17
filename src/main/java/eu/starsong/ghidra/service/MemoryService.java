package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.MemoryBlockDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import ghidra.program.model.address.Address;
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
        return Arrays.stream(memory.getBlocks())
            .map(MemoryBlockDto::from)
            .toList();
    }

    /**
     * Get a memory block by name.
     */
    public MemoryBlockDto getBlockByName(Program program, String name) {
        Memory memory = program.getMemory();
        MemoryBlock block = memory.getBlock(name);
        if (block == null) {
            throw new NotFoundException("Memory block not found: " + name, "BLOCK_NOT_FOUND");
        }
        return MemoryBlockDto.from(block);
    }

    /**
     * Get the memory block containing an address.
     */
    public MemoryBlockDto getBlockContaining(Program program, String addressStr) {
        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

        Memory memory = program.getMemory();
        MemoryBlock block = memory.getBlock(address);
        if (block == null) {
            throw new NotFoundException("No memory block at address: " + addressStr, "BLOCK_NOT_FOUND");
        }
        return MemoryBlockDto.from(block);
    }

    /**
     * Read bytes from memory.
     */
    public byte[] readBytes(Program program, String addressStr, int length) {
        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }

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
     * Search for bytes in memory.
     */
    public List<String> searchBytes(Program program, byte[] pattern, int maxResults) {
        Memory memory = program.getMemory();
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
    }
}
