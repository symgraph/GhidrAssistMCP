/*
 * MCP tool for comment operations (consolidated).
 * Replaces SetCommentTool with get/set/list/remove actions.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Consolidated MCP tool for comment operations.
 * Actions: get, set, list, remove
 */
public class CommentsTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "comments";
    }

    @Override
    public String getDescription() {
        return "Comment operations: get, set, list, or remove comments on functions or addresses";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Comment operation to perform",
                    "enum", List.of("get", "set", "list", "remove")
                )),
                Map.entry("address", Map.of(
                    "type", "string",
                    "description", "Address for get/set/remove operations"
                )),
                Map.entry("function_name", Map.of(
                    "type", "string",
                    "description", "Function name for get (function comment) or list (all comments in function)"
                )),
                Map.entry("comment", Map.of(
                    "type", "string",
                    "description", "Comment text (required for set)"
                )),
                Map.entry("comment_type", Map.of(
                    "type", "string",
                    "description", "Comment type: eol, pre, post, plate, repeatable (default: eol)",
                    "enum", List.of("eol", "pre", "post", "plate", "repeatable"),
                    "default", "eol"
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("action parameter is required")
                .build();
        }

        switch (action.toLowerCase()) {
            case "get":
                return executeGet(arguments, currentProgram);
            case "set":
                return executeSet(arguments, currentProgram);
            case "list":
                return executeList(arguments, currentProgram);
            case "remove":
                return executeRemove(arguments, currentProgram);
            default:
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid action: " + action + ". Use 'get', 'set', 'list', or 'remove'")
                    .build();
        }
    }

    private McpSchema.CallToolResult executeGet(Map<String, Object> arguments, Program program) {
        String functionName = (String) arguments.get("function_name");
        String addressStr = (String) arguments.get("address");
        String commentTypeStr = (String) arguments.get("comment_type");

        if (functionName != null && !functionName.isEmpty()) {
            Function function = findFunctionByName(program, functionName);
            if (function == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Function not found: " + functionName)
                    .build();
            }
            String comment = function.getComment();
            return McpSchema.CallToolResult.builder()
                .addTextContent(comment != null ? comment : "(no comment)")
                .build();
        }

        if (addressStr != null && !addressStr.isEmpty()) {
            Address address = parseAddress(program, addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
            if (codeUnit == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No code unit at address: " + addressStr)
                    .build();
            }
            CommentType commentType = parseCommentType(commentTypeStr);
            String comment = codeUnit.getComment(commentType);
            return McpSchema.CallToolResult.builder()
                .addTextContent(comment != null ? comment : "(no comment)")
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Either 'address' or 'function_name' is required for get")
            .build();
    }

    private McpSchema.CallToolResult executeSet(Map<String, Object> arguments, Program program) {
        String comment = (String) arguments.get("comment");
        if (comment == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("comment parameter is required for set")
                .build();
        }

        String functionName = (String) arguments.get("function_name");
        String addressStr = (String) arguments.get("address");

        if (functionName != null && !functionName.isEmpty()) {
            Function function = findFunctionByName(program, functionName);
            if (function == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Function not found: " + functionName)
                    .build();
            }
            int txId = program.startTransaction("Set Function Comment");
            try {
                function.setComment(comment);
                program.endTransaction(txId, true);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Set comment on function '" + functionName + "': \"" + comment + "\"")
                    .build();
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: " + e.getMessage())
                    .build();
            }
        }

        if (addressStr != null && !addressStr.isEmpty()) {
            Address address = parseAddress(program, addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address: " + addressStr)
                    .build();
            }
            CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
            if (codeUnit == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("No code unit at address: " + addressStr)
                    .build();
            }
            CommentType commentType = parseCommentType((String) arguments.get("comment_type"));
            int txId = program.startTransaction("Set Comment");
            try {
                codeUnit.setComment(commentType, comment);
                program.endTransaction(txId, true);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Set " + getCommentTypeName(commentType) + " comment at " + addressStr + ": \"" + comment + "\"")
                    .build();
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Error: " + e.getMessage())
                    .build();
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Either 'address' or 'function_name' is required for set")
            .build();
    }

    private McpSchema.CallToolResult executeList(Map<String, Object> arguments, Program program) {
        String functionName = (String) arguments.get("function_name");
        if (functionName == null || functionName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("function_name is required for list")
                .build();
        }

        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionName)
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Comments in function: ").append(functionName).append("\n\n");

        String funcComment = function.getComment();
        if (funcComment != null && !funcComment.isEmpty()) {
            result.append("Function comment: ").append(funcComment).append("\n\n");
        }

        CodeUnitIterator codeUnits = program.getListing().getCodeUnits(function.getBody(), true);
        int count = 0;
        while (codeUnits.hasNext()) {
            CodeUnit cu = codeUnits.next();
            for (CommentType ct : new CommentType[]{CommentType.EOL, CommentType.PRE, CommentType.POST, CommentType.PLATE, CommentType.REPEATABLE}) {
                String c = cu.getComment(ct);
                if (c != null && !c.isEmpty()) {
                    result.append(cu.getAddress()).append(" [").append(getCommentTypeName(ct)).append("]: ").append(c).append("\n");
                    count++;
                }
            }
        }

        if (count == 0 && (funcComment == null || funcComment.isEmpty())) {
            result.append("No comments found.");
        } else {
            result.append("\nTotal: ").append(count).append(" address comments");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private McpSchema.CallToolResult executeRemove(Map<String, Object> arguments, Program program) {
        String addressStr = (String) arguments.get("address");
        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address is required for remove")
                .build();
        }

        Address address = parseAddress(program, addressStr);
        if (address == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address: " + addressStr)
                .build();
        }

        CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
        if (codeUnit == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No code unit at address: " + addressStr)
                .build();
        }

        CommentType commentType = parseCommentType((String) arguments.get("comment_type"));
        int txId = program.startTransaction("Remove Comment");
        try {
            codeUnit.setComment(commentType, null);
            program.endTransaction(txId, true);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Removed " + getCommentTypeName(commentType) + " comment at " + addressStr)
                .build();
        } catch (Exception e) {
            program.endTransaction(txId, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error: " + e.getMessage())
                .build();
        }
    }

    private Address parseAddress(Program program, String addressStr) {
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            return addr;
        } catch (Exception e) {
            return null;
        }
    }

    private CommentType parseCommentType(String commentTypeStr) {
        if (commentTypeStr == null) return CommentType.EOL;
        switch (commentTypeStr.toLowerCase()) {
            case "pre": case "pre_comment": return CommentType.PRE;
            case "post": case "post_comment": return CommentType.POST;
            case "plate": case "plate_comment": return CommentType.PLATE;
            case "repeatable": case "repeatable_comment": return CommentType.REPEATABLE;
            default: return CommentType.EOL;
        }
    }

    private String getCommentTypeName(CommentType ct) {
        switch (ct) {
            case PRE: return "pre";
            case POST: return "post";
            case PLATE: return "plate";
            case REPEATABLE: return "repeatable";
            default: return "EOL";
        }
    }

    private Function findFunctionByName(Program program, String functionName) {
        return FunctionLookup.findByName(program, functionName);
    }
}
