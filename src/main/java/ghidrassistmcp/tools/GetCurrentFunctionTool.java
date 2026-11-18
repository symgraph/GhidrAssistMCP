/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that gets the current function in Ghidra.
 */
public class GetCurrentFunctionTool implements McpTool {

    @Override
    public String getName() {
        return "get_current_function";
    }

    @Override
    public String getDescription() {
        return "Get the current function containing the cursor in Ghidra";
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
            .addContent(McpSchema.TextContent.builder("Current function functionality requires UI context. Use get_function_info with a function name or address instead.").build())
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

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Address currentAddress = plugin.getCurrentAddress();
            if (currentAddress == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("No current address available (cursor may not be positioned in the listing)").build())
                    .build();
            }
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No function contains the current address: " + currentAddress).build())
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Current Function Information:\n\n");
        result.append("Name: ").append(currentFunction.getName(true)).append("\n");
        result.append("Entry Point: ").append(currentFunction.getEntryPoint()).append("\n");
        result.append("Address Range: ").append(currentFunction.getBody().getMinAddress())
              .append(" - ").append(currentFunction.getBody().getMaxAddress()).append("\n");
        result.append("Parameter Count: ").append(currentFunction.getParameterCount()).append("\n");
        result.append("Calling Convention: ").append(currentFunction.getCallingConventionName()).append("\n");

        // Add signature if available
        String signature = currentFunction.getSignature().getPrototypeString();
        if (signature != null && !signature.isEmpty()) {
            result.append("Signature: ").append(signature).append("\n");
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}
