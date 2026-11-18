/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that retrieves a hexdump of memory at a specific address.
 * Displays data in standard hex+ASCII format.
 */
public class GetHexdumpTool implements McpTool {

    private static final int BYTES_PER_LINE = 16;

    @Override
    public String getName() {
        return "get_data_at";
    }

    @Override
    public String getDescription() {
        return "Get a hexdump of memory at a specific address in standard hex+ASCII format. " +
               "Useful for examining data structures, .rodata, .data, .bss, and other non-code regions.";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "address", new JsonSchema("string", null, null, null, null, null),
                "len", new JsonSchema("number", null, null, null, null, null)
            ),
            List.of("address", "len"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        // Get and validate address parameter
        String addressStr = (String) arguments.get("address");
        if (addressStr == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("address parameter is required").build())
                .build();
        }

        // Get and validate length parameter
        Object lenObj = arguments.get("len");
        if (lenObj == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("len parameter is required").build())
                .build();
        }

        int length;
        try {
            // Handle both Integer and Double (JSON numbers can be either)
            if (lenObj instanceof Integer) {
                length = (Integer) lenObj;
            } else if (lenObj instanceof Double) {
                length = ((Double) lenObj).intValue();
            } else if (lenObj instanceof Long) {
                length = ((Long) lenObj).intValue();
            } else {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("len parameter must be a number").build())
                    .build();
            }

            if (length <= 0) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("len must be greater than 0").build())
                    .build();
            }

            // Limit maximum length to prevent excessive output
            if (length > 65536) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("len exceeds maximum allowed value of 65536 bytes").build())
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Invalid len parameter: " + e.getMessage()).build())
                .build();
        }

        // Parse the address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid address format: " + addressStr).build())
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Invalid address format: " + addressStr + " - " + e.getMessage()).build())
                .build();
        }

        // Generate the hexdump
        try {
            String hexdump = generateHexdump(currentProgram, address, length);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder(hexdump).build())
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error generating hexdump: " + e.getMessage()).build())
                .build();
        }
    }

    /**
     * Generate a hexdump in standard format with hex and ASCII representation.
     * Format: ADDRESS  HEX_BYTES (16 per line, grouped by 8)  |ASCII|
     */
    private String generateHexdump(Program program, Address startAddr, int length) {
        StringBuilder result = new StringBuilder();
        Memory memory = program.getMemory();

        result.append("Hexdump at ").append(startAddr).append(" (").append(length).append(" bytes):\n\n");

        int bytesRead = 0;
        int unreadableBytes = 0;
        Address currentAddr = startAddr;

        while (bytesRead < length) {
            // Calculate how many bytes to read on this line
            int bytesToRead = Math.min(BYTES_PER_LINE, length - bytesRead);
            byte[] lineBytes = new byte[bytesToRead];
            boolean[] readable = new boolean[bytesToRead];

            // Read the bytes for this line
            int actualBytesRead = 0;
            for (int i = 0; i < bytesToRead; i++) {
                try {
                    lineBytes[i] = memory.getByte(currentAddr);
                    readable[i] = true;
                    currentAddr = currentAddr.add(1);
                    actualBytesRead++;
                } catch (MemoryAccessException e) {
                    // Preserve uncertainty: an unreadable byte is not a known zero.
                    unreadableBytes++;
                    currentAddr = currentAddr.add(1);
                    actualBytesRead++;
                }
            }

            // Format the line
            result.append(formatHexdumpLine(startAddr.add(bytesRead), lineBytes, readable, actualBytesRead));
            result.append("\n");

            bytesRead += actualBytesRead;
        }

        if (unreadableBytes > 0) {
            result.append("Unreadable bytes: ").append(unreadableBytes)
                .append(" (shown as ??; ASCII shown as ?)\n");
        }
        return result.toString();
    }

    /**
     * Format a single line of the hexdump.
     */
    private String formatHexdumpLine(Address lineAddr, byte[] bytes, boolean[] readable, int validBytes) {
        StringBuilder line = new StringBuilder();

        if ( lineAddr.getOffset() > (1L << 32)) {
	        // Address (8 hex digits)
	        line.append(String.format("%08x  ", lineAddr.getOffset()));
        } else {
            // Address (4 hex digits)
            line.append(String.format("%04x  ", lineAddr.getOffset()));
        }

        // Hex bytes (16 per line, with space after 8th byte)
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (i < validBytes) {
                line.append(readable[i] ? String.format("%02x ", bytes[i] & 0xFF) : "?? ");
            } else {
                line.append("   "); // 3 spaces for missing bytes
            }

            // Extra space after 8th byte
            if (i == 7) {
                line.append(" ");
            }
        }

        // ASCII representation
        line.append(" |");
        for (int i = 0; i < validBytes; i++) {
            if (!readable[i]) {
                line.append('?');
                continue;
            }
            char c = (char) (bytes[i] & 0xFF);
            // Print printable ASCII characters, otherwise use '.'
            if (c >= 32 && c <= 126) {
                line.append(c);
            } else {
                line.append('.');
            }
        }
        line.append("|");

        return line.toString();
    }
}
