/*
 * MCP tool that lists functions with optional pattern filtering and pagination.
 * Consolidates list_functions and search_functions functionality.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists functions with optional pattern filtering and pagination.
 * Consolidates list_functions and search_functions functionality.
 */
public class ListFunctionsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_functions";
    }

    @Override
    public String getDescription() {
        return "List functions with optional pattern filtering and pagination";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "pattern", new JsonSchema("string", null, null, null, null, null),
                "case_sensitive", new JsonSchema("boolean", null, null, null, null, null),
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

        // Parse optional parameters
        String pattern = (String) arguments.get("pattern");
        boolean caseSensitive = true;
        if (arguments.get("case_sensitive") instanceof Boolean) {
            caseSensitive = (Boolean) arguments.get("case_sensitive");
        }

        int offset = 0;
        int limit = 100;  // Default limit

        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        String result = listFunctions(currentProgram, pattern, caseSensitive, offset, limit);
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result).build())
            .build();
    }

    private String listFunctions(Program program, String pattern, boolean caseSensitive, int offset, int limit) {
        StringBuilder result = new StringBuilder();

        boolean hasPattern = pattern != null && !pattern.trim().isEmpty();
        String searchPattern = hasPattern ? (caseSensitive ? pattern : pattern.toLowerCase()) : null;

        if (hasPattern) {
            result.append("Functions matching pattern: \"").append(pattern).append("\"");
            result.append(" (case ").append(caseSensitive ? "sensitive" : "insensitive").append(")\n\n");
        } else {
            result.append("Functions in program:\n\n");
        }

        FunctionIterator functions = program.getFunctionManager().getFunctions(true);

        // Collect matching functions
        List<Function> matchingFunctions = new ArrayList<>();
        while (functions.hasNext()) {
            Function function = functions.next();

            if (hasPattern) {
                String functionName = caseSensitive ? function.getName(true) : function.getName(true).toLowerCase();
                if (functionName.contains(searchPattern)) {
                    matchingFunctions.add(function);
                }
            } else {
                matchingFunctions.add(function);
            }
        }

        int totalCount = matchingFunctions.size();
        int count = 0;

        // Apply offset and limit
        for (int i = offset; i < matchingFunctions.size() && count < limit; i++) {
            Function function = matchingFunctions.get(i);
            result.append("- ").append(function.getName(true))
                  .append(" @ ").append(function.getEntryPoint())
                  .append(" (").append(function.getParameterCount()).append(" params)")
                  .append("\n");
            count++;
        }

        if (totalCount == 0) {
            if (hasPattern) {
                result.append("No functions found matching pattern: \"").append(pattern).append("\"");
            } else {
                result.append("No functions found in the program.");
            }
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount);
            result.append(hasPattern ? " matching functions" : " functions");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }

        return result.toString();
    }
}