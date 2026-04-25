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
                    "description", "Bytes to write. Either a hex string (e.g. '90 90') or an integer array (e.g. [144, 144])."),
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
        Object bytesObj = arguments.get("bytes");
        boolean clearCodeUnits = Boolean.TRUE.equals(arguments.get("clear_code_units"));

        if (addressStr == null || addressStr.isBlank()) {
            return textResult("address is required");
        }
        if (bytesObj == null) {
            return textResult("bytes is required");
        }

        Address address = parseAddress(currentProgram, addressStr);
        if (address == null) {
            return textResult("Could not parse address: " + addressStr);
        }

        byte[] patchBytes;
        try {
            patchBytes = parsePatchBytes(bytesObj);
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

    private static Address parseAddress(Program program, String addressStr) {
        try {
            Address parsed = program.getAddressFactory().getAddress(addressStr);
            if (parsed != null) {
                return parsed;
            }
        } catch (Exception ignored) {
            // Fall through to numeric parse
        }

        try {
            String clean = addressStr.strip();
            if (clean.startsWith("0x") || clean.startsWith("0X")) {
                clean = clean.substring(2);
            }
            long value = Long.parseUnsignedLong(clean, 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static byte[] parsePatchBytes(Object input) {
        if (input instanceof String) {
            return parseHexBytes((String) input);
        }

        if (input instanceof List<?>) {
            List<?> list = (List<?>) input;
            byte[] out = new byte[list.size()];
            for (int i = 0; i < list.size(); i++) {
                Object item = list.get(i);
                if (!(item instanceof Number)) {
                    throw new IllegalArgumentException("array element at index " + i + " is not a number");
                }
                int value = ((Number) item).intValue();
                if (value < 0 || value > 255) {
                    throw new IllegalArgumentException("array element at index " + i + " out of range (0-255): " + value);
                }
                out[i] = (byte) value;
            }
            return out;
        }

        throw new IllegalArgumentException("bytes must be a hex string or integer array");
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
