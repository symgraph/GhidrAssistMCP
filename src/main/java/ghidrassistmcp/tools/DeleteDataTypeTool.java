/**
 * MCP tool that deletes a data type from the program's DataTypeManager.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that deletes a data type from the program's DataTypeManager.
 */
public class DeleteDataTypeTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public String getName() {
        return "delete_data_type";
    }

    @Override
    public String getDescription() {
        return "Delete a data type by name (optionally scoped by category). " +
               "If multiple types share the same name in different categories, you must provide category or use a full path name.";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "name", new JsonSchema("string", null, null, null, null, null),
                "category", new JsonSchema("string", null, null, null, null, null)
            ),
            List.of("name"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        String name = (String) arguments.get("name");
        if (name == null || name.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("name parameter is required").build())
                .build();
        }
        name = name.trim();

        String category = (String) arguments.get("category");
        if (category != null) {
            category = category.trim();
            if (category.isEmpty()) {
                category = null;
            }
        }

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        ResolveResult resolved = resolveTargetDataType(dtm, name, category);
        if (!resolved.ok) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder(resolved.message).build())
                .build();
        }

        DataType target = resolved.dataType;
        if (target == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Data type not found: " + name + (category != null ? " in category: " + category : "")).build())
                .build();
        }

        // Some DataType instances may come from non-program managers (built-ins/archives).
        // Only attempt deletion if this type is owned by the program's DataTypeManager.
        try {
            if (target.getDataTypeManager() != dtm) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Refusing to delete data type '" + target.getName() + "' because it is not owned by this program's DataTypeManager " +
                                    "(likely a built-in or archived type). Resolved path: " + safePath(target)).build())
                    .build();
            }
        } catch (Exception e) {
            // If ownership cannot be determined, proceed cautiously and rely on dtm.remove() return value.
        }

        int txId = currentProgram.startTransaction("Delete Data Type");
        boolean committed = false;
        try {
            boolean removed = dtm.remove(target);
            if (!removed) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Failed to delete data type '" + target.getName() + "' at " + safePath(target) + ". " +
                                    "It may be built-in, read-only, or still referenced by other types/uses.").build())
                    .build();
            }

            committed = true;
            if (backend != null) {
                backend.clearCache();
            }

            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Successfully deleted data type '" + target.getName() + "' at " + safePath(target)).build())
                .build();
        } catch (Exception e) {
            String msg = "Error deleting data type '" + name + "': " + e.getMessage();
            Msg.error(this, msg, e);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder(msg).build())
                .build();
        } finally {
            currentProgram.endTransaction(txId, committed);
        }
    }

    private static class ResolveResult {
        final boolean ok;
        final DataType dataType;
        final String message;

        private ResolveResult(boolean ok, DataType dataType, String message) {
            this.ok = ok;
            this.dataType = dataType;
            this.message = message;
        }

        static ResolveResult ok(DataType dataType) {
            return new ResolveResult(true, dataType, null);
        }

        static ResolveResult error(String message) {
            return new ResolveResult(false, null, message);
        }
    }

    private ResolveResult resolveTargetDataType(DataTypeManager dtm, String name, String category) {
        // If category provided, require exact match.
        if (category != null) {
            try {
                DataType dt = dtm.getDataType(new CategoryPath(category), name);
                if (dt != null) {
                    return ResolveResult.ok(dt);
                }
                return ResolveResult.error("Data type not found: " + name + " in category: " + category);
            } catch (Exception e) {
                return ResolveResult.error("Invalid category path '" + category + "': " + e.getMessage());
            }
        }

        // If name looks like a full path, try direct path lookup.
        if (name.startsWith("/")) {
            DataType dt = dtm.getDataType(name);
            if (dt != null) {
                return ResolveResult.ok(dt);
            }
            return ResolveResult.error("Data type not found at path: " + name);
        }

        // Collect all exact-name matches and detect ambiguity by category.
        List<DataType> matches = new ArrayList<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt != null && name.equals(dt.getName())) {
                matches.add(dt);
            }
        }

        if (matches.isEmpty()) {
            // Fall back to dtm.getDataType(name) (may resolve built-ins or a single match)
            DataType dt = dtm.getDataType(name);
            if (dt != null) {
                return ResolveResult.ok(dt);
            }
            return ResolveResult.error("Data type not found: " + name);
        }

        if (matches.size() == 1) {
            return ResolveResult.ok(matches.get(0));
        }

        // Ambiguous: same name in multiple categories.
        Map<String, Integer> byCategory = new LinkedHashMap<>();
        for (DataType dt : matches) {
            String path = dt.getCategoryPath() != null ? dt.getCategoryPath().getPath() : "(unknown)";
            byCategory.put(path, byCategory.getOrDefault(path, 0) + 1);
        }

        StringBuilder msg = new StringBuilder();
        msg.append("Ambiguous data type name '").append(name).append("': found ")
           .append(matches.size()).append(" matches in ").append(byCategory.size()).append(" categories.\n")
           .append("Please provide 'category' to select the exact type, or pass a full path as 'name' (starting with '/').\n\n")
           .append("Candidate categories:\n");

        int shown = 0;
        for (Map.Entry<String, Integer> e : byCategory.entrySet()) {
            if (shown >= 20) {
                msg.append("- (more...)\n");
                break;
            }
            msg.append("- ").append(e.getKey());
            if (e.getValue() != 1) {
                msg.append(" (").append(e.getValue()).append(")");
            }
            msg.append("\n");
            shown++;
        }

        return ResolveResult.error(msg.toString());
    }

    private String safePath(DataType dt) {
        try {
            if (dt.getCategoryPath() != null) {
                return dt.getCategoryPath().getPath() + "/" + dt.getName();
            }
        } catch (Exception e) {
            // ignore
        }
        return dt.getName();
    }
}
