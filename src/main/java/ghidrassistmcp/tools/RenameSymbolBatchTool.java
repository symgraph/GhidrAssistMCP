/*
 * MCP tool for batch renaming symbols (functions, data, variables).
 * Uses the same core implementation as RenameSymbolTool to avoid duplicate logic.
 */
package ghidrassistmcp.tools;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.decompiler.DecompilerService;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Batch version of {@code rename_symbol}.
 *
 * Input: { "renames": [ { "target_type": "...", "identifier": "...", "new_name": "...", "variable_name"?: "..." }, ... ] }
 *
 * Output: JSON (as text) with per-item results to support partial success.
 */
public class RenameSymbolBatchTool implements McpTool {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DecompilerService decompilerService;

    public RenameSymbolBatchTool(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        // Matches behavior/annotation of the single-item rename tool.
        return true;
    }

    @Override
    public String getName() {
        return "batch_rename";
    }

    @Override
    public String getDescription() {
        return "Batch rename symbols (functions, data/labels, or local variables) with partial success reporting";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        // NOTE: McpSchema.JsonSchema doesn't have an 'items' field, so we represent arrays using raw Maps.
        Map<String, Object> renameItemProps = new HashMap<>();
        renameItemProps.put("target_type", Map.of(
            "type", "string",
            "description", "What kind of symbol to rename",
            "enum", List.of("function", "data", "variable")
        ));
        renameItemProps.put("identifier", Map.of(
            "type", "string",
            "description", "Target identifier (function: old function name; data: address string; variable: function name)"
        ));
        renameItemProps.put("new_name", Map.of(
            "type", "string",
            "description", "New symbol name (functions may be qualified like Namespace::Func)"
        ));
        renameItemProps.put("variable_name", Map.of(
            "type", "string",
            "description", "Required when target_type is 'variable': old local name to rename"
        ));

        Map<String, Object> renameItemSchema = new HashMap<>();
        renameItemSchema.put("type", "object");
        renameItemSchema.put("properties", renameItemProps);
        renameItemSchema.put("required", List.of("target_type", "identifier", "new_name"));

        Map<String, Object> renamesSchema = new HashMap<>();
        renamesSchema.put("type", "array");
        renamesSchema.put("items", renameItemSchema);

        Map<String, Object> props = new HashMap<>();
        props.put("renames", renamesSchema);

        return new McpSchema.JsonSchema("object", props, List.of("renames"), null, null, null);
    }

    @Override
    @SuppressWarnings("unchecked")
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        Object renamesObj = arguments.get("renames");
        if (!(renamesObj instanceof List<?>)) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("renames parameter is required and must be an array")
                .build();
        }

        List<?> renames = (List<?>) renamesObj;

        ObjectNode root = objectMapper.createObjectNode();
        root.put("program", currentProgram.getName());
        root.put("total", renames.size());

        ArrayNode results = objectMapper.createArrayNode();
        List<ObjectNode> itemNodes = new ArrayList<>(renames.size());

        // Track variable renames per function so we can decompile once per function.
        Map<String, List<RenameSymbolCore.VariableRenameRequest>> variableRenamesByFunction = new HashMap<>();

        for (int i = 0; i < renames.size(); i++) {
            ObjectNode itemResult = objectMapper.createObjectNode();
            itemResult.put("index", i);
            itemNodes.add(itemResult);
            results.add(itemResult);

            Object item = renames.get(i);
            if (!(item instanceof Map<?, ?>)) {
                itemResult.put("success", false);
                itemResult.put("message", "Item is not an object/map");
                continue;
            }

            Map<String, Object> itemArgs;
            try {
                itemArgs = (Map<String, Object>) item;
            } catch (ClassCastException cce) {
                itemResult.put("success", false);
                itemResult.put("message", "Item is not a valid object/map");
                continue;
            }

            // Echo request fields (best-effort) to make partial failures easier to debug.
            Object tt = itemArgs.get("target_type");
            Object id = itemArgs.get("identifier");
            Object nn = itemArgs.get("new_name");
            Object vn = itemArgs.get("variable_name");
            if (tt instanceof String) itemResult.put("target_type", (String) tt);
            if (id instanceof String) itemResult.put("identifier", (String) id);
            if (nn instanceof String) itemResult.put("new_name", (String) nn);
            if (vn instanceof String) itemResult.put("variable_name", (String) vn);

            String targetType = tt instanceof String ? ((String) tt).toLowerCase() : null;
            if ("variable".equals(targetType) && id instanceof String && vn instanceof String && nn instanceof String) {
                // Defer variable renames so they can be applied in one decompile pass per function.
                String functionName = (String) id;
                variableRenamesByFunction
                    .computeIfAbsent(functionName, k -> new ArrayList<>())
                    .add(new RenameSymbolCore.VariableRenameRequest(i, (String) vn, (String) nn));
                continue;
            }

            RenameSymbolCore.RenameResult r;
            try {
                r = RenameSymbolCore.renameOne(itemArgs, currentProgram, decompilerService);
            } catch (Exception e) {
                r = new RenameSymbolCore.RenameResult(false, "Unhandled error: " + e.getMessage());
            }

            itemResult.put("success", r.success);
            itemResult.put("message", r.message);
        }

        // Apply variable renames in batches per function (one decompile pass per function).
        for (Map.Entry<String, List<RenameSymbolCore.VariableRenameRequest>> entry : variableRenamesByFunction.entrySet()) {
            String functionName = entry.getKey();
            List<RenameSymbolCore.VariableRenameRequest> reqs = entry.getValue();

            Map<Integer, RenameSymbolCore.RenameResult> perIndex =
                RenameSymbolCore.renameVariablesBatch(currentProgram, functionName, reqs,
                    decompilerService);

            for (RenameSymbolCore.VariableRenameRequest req : reqs) {
                ObjectNode node = itemNodes.get(req.index);
                RenameSymbolCore.RenameResult r = perIndex.get(req.index);
                if (r == null) {
                    r = new RenameSymbolCore.RenameResult(false, "Unknown error renaming variable");
                }
                node.put("success", r.success);
                node.put("message", r.message);
            }
        }

        int succeeded = 0;
        int failed = 0;
        for (ObjectNode node : itemNodes) {
            if (node.has("success") && node.get("success").isBoolean() && node.get("success").asBoolean()) {
                succeeded++;
            } else {
                failed++;
            }
        }

        root.put("succeeded", succeeded);
        root.put("failed", failed);
        root.set("results", results);

        return McpSchema.CallToolResult.builder()
            .addTextContent(root.toPrettyString())
            .build();
    }
}
