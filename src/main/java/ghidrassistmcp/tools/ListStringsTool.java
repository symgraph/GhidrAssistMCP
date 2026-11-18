/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists string data found in the program.
 */
public class ListStringsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_strings";
    }
    
    @Override
    public String getDescription() {
        return "List string data found in the program, with optional filtering";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "offset", new JsonSchema("integer", null, null, null, null, null),
                "limit", new JsonSchema("integer", null, null, null, null, null),
                "min_length", new JsonSchema("integer", null, null, null, null, null),
                "filter", new JsonSchema("string", null, null, null, null, null)
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
        int offset = 0;
        int limit = 100; // Default limit
        int minLength = 4; // Default minimum string length
        String filter = null;
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        if (arguments.get("min_length") instanceof Number) {
            minLength = ((Number) arguments.get("min_length")).intValue();
        }
        if (arguments.get("filter") instanceof String) {
            filter = ((String) arguments.get("filter")).trim();
            if (filter.isEmpty()) {
                filter = null;
            }
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Strings in program (min length: ").append(minLength);
        if (filter != null) {
            result.append(", filter: \"").append(filter).append("\"");
        }
        result.append("):\n\n");
        
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        
        int count = 0;
        int totalCount = 0;
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            
            // Check if this is string data
            if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();
                String stringText = extractStringText(stringValue);
                
                // Apply minimum length filter
                if (stringText != null && stringText.length() >= minLength) {
                    // Apply optional contains filter (applies before offset/limit)
                    if (filter != null && !stringText.contains(filter)) {
                        continue;
                    }

                    totalCount++;
                    
                    // Apply offset
                    if (totalCount <= offset) {
                        continue;
                    }
                    
                    // Apply limit to displayed results only; keep scanning for a true total.
                    if (count < limit) {
                        // Clean up the string representation for display
                        String displayString = stringValue;
                        if (displayString.length() > 80) {
                            displayString = displayString.substring(0, 77) + "...";
                        }

                        result.append("@ ").append(data.getAddress())
                              .append(" (").append(stringText.length()).append(" chars): ")
                              .append(displayString)
                              .append("\n");

                        count++;
                    }
                }
            }
        }
        
        if (totalCount == 0) {
            result.append("No strings found in the program with minimum length ").append(minLength).append(".");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" strings");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    /**
     * Extract the "actual" string text from Ghidra's default value representation.
     * This is usually quoted (e.g. "\"Hello\""), sometimes with a prefix (e.g. "L\"Hello\"").
     */
    private static String extractStringText(String defaultValueRepresentation) {
        if (defaultValueRepresentation == null) {
            return null;
        }

        int firstQuote = defaultValueRepresentation.indexOf('"');
        int lastQuote = defaultValueRepresentation.lastIndexOf('"');
        if (firstQuote >= 0 && lastQuote > firstQuote) {
            return defaultValueRepresentation.substring(firstQuote + 1, lastQuote);
        }

        return defaultValueRepresentation;
    }
}
