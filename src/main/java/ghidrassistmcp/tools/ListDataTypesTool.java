/*
 *
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists all available data types in the program.
 * This includes built-in types, user-defined structures, and imported data types.
 */
public class ListDataTypesTool implements McpTool {

    @Override
    public String getName() {
        return "list_data_types";
    }

    @Override
    public String getDescription() {
        return "List all available data types in the program, including built-in types, user-defined structures, and imported types. " +
               "Supports filtering by name pattern and category. " +
               "Examples: " +
               "1) List all types: {} " +
               "2) Search for structures: {\"filter\": \"mystruct\"} " +
               "3) List types in category: {\"category\": \"/myproject\"} " +
               "4) Paginate results: {\"offset\": 0, \"limit\": 50}";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "filter", new JsonSchema("string", null, null, null, null, null),
                "category", new JsonSchema("string", null, null, null, null, null),
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
        String filter = (String) arguments.get("filter");
        String category = (String) arguments.get("category");
        int offset = 0;
        int limit = 100; // Default limit

        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // Collect all data types
        List<DataType> dataTypes = new ArrayList<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();

            // Apply name filter if specified
            if (filter != null && !dt.getName().toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }

            // Apply category filter if specified
            if (category != null && !dt.getCategoryPath().getPath().toLowerCase().contains(category.toLowerCase())) {
                continue;
            }

            dataTypes.add(dt);
        }

        // Sort by category path then name for consistent ordering
        Collections.sort(dataTypes, (a, b) -> {
            int pathCompare = a.getCategoryPath().getPath().compareTo(b.getCategoryPath().getPath());
            if (pathCompare != 0) {
                return pathCompare;
            }
            return a.getName().compareTo(b.getName());
        });

        StringBuilder result = new StringBuilder();
        result.append("Available Data Types");
        if (filter != null || category != null) {
            result.append(" (filtered");
            if (filter != null) {
                result.append(" by name: ").append(filter);
            }
            if (category != null) {
                result.append(" by category: ").append(category);
            }
            result.append(")");
        }
        result.append(":\n\n");

        int totalCount = dataTypes.size();
        int count = 0;

        // Apply offset and limit
        for (int i = offset; i < dataTypes.size() && count < limit; i++) {
            DataType dt = dataTypes.get(i);

            result.append("- ").append(dt.getName());
            result.append(" [").append(dt.getCategoryPath().getPath()).append("]");

            // Add size information
            int size = dt.getLength();
            if (size > 0) {
                result.append(" (").append(size).append(" bytes)");
            } else if (size == -1) {
                result.append(" (variable size)");
            }

            // Add description if available
            String description = dt.getDescription();
            if (description != null && !description.isEmpty()) {
                // Truncate long descriptions
                if (description.length() > 60) {
                    description = description.substring(0, 57) + "...";
                }
                result.append(" - ").append(description);
            }

            result.append("\n");
            count++;
        }

        if (totalCount == 0) {
            result.append("No data types found");
            if (filter != null) {
                result.append(" matching filter: ").append(filter);
            }
            if (category != null) {
                result.append(" in category: ").append(category);
            }
            result.append(".");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" data types");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}
