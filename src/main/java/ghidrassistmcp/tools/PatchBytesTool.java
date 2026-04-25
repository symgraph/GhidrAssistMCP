/*
 * MCP tool to patch bytes at a specific address.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Applies raw byte patches to the loaded program.
 */
public class PatchBytesTool implements McpTool {

    @Override
    public String getName() {
        return "patch_bytes";
    }

    @Override
    public String getDescription() {
        return "Patch raw bytes at an address. Example: {\"address\":\"0x401000\",\"bytes\":\"90 90\"}";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", Map.of(
                    "type", "string",
                    "description", "Address to patch (e.g. '0x401000' or '401000')"),
                "bytes", Map.of(
                    "type", "string",
                    "description", "Hex bytes to write. Separators allowed: spaces/commas. Example: '90 90'"),
                "clear_code_units", Map.of(
                    "type", "boolean",
                    "description", "If true, clear existing instructions/data at the patched range before writing. Default: false")
            ),
            List.of("address", "bytes"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return textResult("No program currently loaded");
        }

        String addressStr = (String) arguments.get("address");
        String bytesStr = (String) arguments.get("bytes");
        boolean clearCodeUnits = Boolean.TRUE.equals(arguments.get("clear_code_units"));

        if (addressStr == null || addressStr.isBlank()) {
            return textResult("address is required");
        }
        if (bytesStr == null || bytesStr.isBlank()) {
            return textResult("bytes is required");
        }

        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
        } catch (Exception e) {
            return textResult("Invalid address: " + addressStr);
        }

        if (address == null) {
            return textResult("Could not parse address: " + addressStr);
        }

        byte[] patchBytes;
        try {
            patchBytes = parseHexBytes(bytesStr);
        } catch (IllegalArgumentException e) {
            return textResult("Invalid bytes format: " + e.getMessage());
        }

        if (patchBytes.length == 0) {
            return textResult("No bytes provided to patch");
        }

        Memory memory = currentProgram.getMemory();
        Address endAddress;
        try {
            endAddress = address.addNoWrap(patchBytes.length - 1);
        } catch (Exception e) {
            return textResult("Patch range overflows address space: " + e.getMessage());
        }

        if (!memory.contains(address) || !memory.contains(endAddress)) {
            return textResult("Patch range is outside mapped memory: " + address + " - " + endAddress);
        }

        byte[] oldBytes = new byte[patchBytes.length];
        try {
            memory.getBytes(address, oldBytes);
        } catch (MemoryAccessException e) {
            return textResult("Failed reading original bytes: " + e.getMessage());
        }

        int txId = currentProgram.startTransaction("MCP Patch Bytes at " + address);
        try {
            if (clearCodeUnits) {
                currentProgram.getListing().clearCodeUnits(address, endAddress, false);
            }

            memory.setBytes(address, patchBytes);
            currentProgram.endTransaction(txId, true);
        } catch (Exception e) {
            currentProgram.endTransaction(txId, false);
            return textResult("Patch failed: " + e.getMessage());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Patched ").append(patchBytes.length).append(" byte(s) at ").append(address).append("\n");
        sb.append("Range: ").append(address).append(" - ").append(endAddress).append("\n");
        sb.append("Before: ").append(toHex(oldBytes)).append("\n");
        sb.append("After:  ").append(toHex(patchBytes));
        if (clearCodeUnits) {
            sb.append("\nCode units cleared in patched range: yes");
        }

        return textResult(sb.toString());
    }

    private static byte[] parseHexBytes(String input) {
        String normalized = input.replaceAll("0x", "")
            .replaceAll("0X", "")
            .replaceAll("[,\\s]", "");

        if (normalized.isEmpty()) {
            return new byte[0];
        }
        if ((normalized.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string must contain an even number of characters");
        }

        int len = normalized.length() / 2;
        byte[] bytes = new byte[len];
        for (int i = 0; i < len; i++) {
            String hex = normalized.substring(i * 2, i * 2 + 2);
            try {
                bytes[i] = (byte) Integer.parseInt(hex, 16);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("invalid hex byte '" + hex + "'");
            }
        }
        return bytes;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xff));
        }
        return sb.toString();
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
