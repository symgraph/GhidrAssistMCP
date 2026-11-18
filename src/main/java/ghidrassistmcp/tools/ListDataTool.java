/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists defined data in the program.
 */
public class ListDataTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_data_vars";
    }
    
    @Override
    public String getDescription() {
        return "List defined data elements in the program";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "offset", new JsonSchema("integer", null, null, null, null, null),
                "limit", new JsonSchema("integer", null, null, null, null, null),
                "data_type_filter", new JsonSchema("string", null, null, null, null, null)
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
        String dataTypeFilter = (String) arguments.get("data_type_filter");
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Defined Data Elements");
        if (dataTypeFilter != null) {
            result.append(" (filtered by: ").append(dataTypeFilter).append(")");
        }
        result.append(":\n\n");
        
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        
        int count = 0;
        int totalCount = 0;
        
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            
            // Apply data type filter if specified
            if (dataTypeFilter != null) {
                DataType dataType = data.getDataType();
                if (dataType == null || !dataType.getName().toLowerCase().contains(dataTypeFilter.toLowerCase())) {
                    continue;
                }
            }
            
            totalCount++;
            
            // Apply offset
            if (totalCount <= offset) {
                continue;
            }
            
            // Apply limit to displayed results only; keep scanning for a true total.
            if (count < limit) {
                DataType dataType = data.getDataType();
                String typeName = dataType != null ? dataType.getName() : "unknown";
                String value = data.getDefaultValueRepresentation();
                if (value != null && value.length() > 50) {
                    value = value.substring(0, 47) + "...";
                }

                result.append("@ ").append(data.getAddress())
                      .append(" [").append(typeName).append("]");

                if (data.hasStringValue()) {
                    result.append(" String: ").append(value != null ? value : "null");
                } else if (value != null) {
                    result.append(" Value: ").append(value);
                }

                // Add symbol name if available
                if (data.getPrimarySymbol() != null) {
                    result.append(" (").append(data.getPrimarySymbol().getName()).append(")");
                }

                result.append("\n");
                count++;
            }
        }
        
        if (totalCount == 0) {
            if (dataTypeFilter != null) {
                result.append("No data elements found matching filter: ").append(dataTypeFilter);
            } else {
                result.append("No defined data elements found in the program.");
            }
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" data elements");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}
