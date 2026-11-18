/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that gets the current cursor address in Ghidra.
 */
public class GetCurrentAddressTool implements McpTool {

    @Override
    public String getName() {
        return "get_current_address";
    }

    @Override
    public String getDescription() {
        return "Get the current cursor address in Ghidra";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // Fallback for when backend reference is not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder("Current address functionality requires UI context. " +
                          "Program minimum address: " + currentProgram.getMinAddress()).build())
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        // Get the active plugin for UI context
        GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
        if (plugin == null) {
            return execute(arguments, currentProgram);
        }

        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No current address available (cursor may not be positioned in the listing)").build())
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Current Address: ").append(currentAddress).append("\n");
        result.append("Program: ").append(currentProgram.getName()).append("\n");
        result.append("Address Space: ").append(currentAddress.getAddressSpace().getName());

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}
