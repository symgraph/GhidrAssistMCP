/*
 * MCP tool for listing relocations.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists relocation entries from the program.
 */
public class ListRelocationsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_relocations";
    }

    @Override
    public String getDescription() {
        return "List relocation entries from the program's relocation table";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "offset", new JsonSchema("integer", null, null, null, null, null),
                "limit", new JsonSchema("integer", null, null, null, null, null)
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        int offset = 0;
        int limit = 100;

        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        RelocationTable relocationTable = currentProgram.getRelocationTable();
        int totalCount = relocationTable.getSize();

        StringBuilder result = new StringBuilder();
        result.append("Relocation Table for: ").append(currentProgram.getName()).append("\n\n");
        result.append("Total relocations: ").append(totalCount).append("\n\n");

        if (totalCount == 0) {
            result.append("No relocations found in this program.\n");
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder(result.toString()).build())
                .build();
        }

        result.append("## Relocations:\n\n");
        result.append("| Address | Type | Symbol | Values |\n");
        result.append("|---------|------|--------|--------|\n");

        Iterator<Relocation> iter = relocationTable.getRelocations();
        int currentIndex = 0;
        int displayedCount = 0;

        while (iter.hasNext() && displayedCount < limit) {
            Relocation reloc = iter.next();

            // Skip entries before offset
            if (currentIndex < offset) {
                currentIndex++;
                continue;
            }

            result.append("| ").append(reloc.getAddress()).append(" | ");
            result.append(reloc.getType()).append(" | ");

            String symbolName = reloc.getSymbolName();
            result.append(symbolName != null ? symbolName : "-").append(" | ");

            // Format relocation values
            long[] values = reloc.getValues();
            if (values != null && values.length > 0) {
                StringBuilder valStr = new StringBuilder();
                for (int i = 0; i < values.length && i < 4; i++) {
                    if (i > 0) valStr.append(", ");
                    valStr.append(String.format("0x%x", values[i]));
                }
                if (values.length > 4) {
                    valStr.append("...");
                }
                result.append(valStr);
            } else {
                result.append("-");
            }
            result.append(" |\n");

            currentIndex++;
            displayedCount++;
        }

        result.append("\n");
        result.append("Showing ").append(displayedCount).append(" of ").append(totalCount).append(" relocations");
        if (offset > 0) {
            result.append(" (offset: ").append(offset).append(")");
        }
        result.append("\n");

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}
