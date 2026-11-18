/*
 * MCP tool for setting comments on functions or addresses.
 * Consolidates set_decompiler_comment and set_disassembly_comment into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that sets comments on functions or addresses.
 * Replaces separate set_decompiler_comment and set_disassembly_comment tools.
 */
public class SetCommentTool implements McpTool {

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
        return "set_comment";
    }

    @Override
    public String getDescription() {
        return "Set a comment on a function (decompiler view) or at an address (disassembly view)";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "target", Map.of(
                    "type", "string",
                    "description", "Where to set the comment",
                    "enum", List.of("function", "address")
                ),
                "function_name", Map.of(
                    "type", "string",
                    "description", "Required when target is 'function': function name"
                ),
                "address", Map.of(
                    "type", "string",
                    "description", "Required when target is 'address': address string"
                ),
                "comment", Map.of(
                    "type", "string",
                    "description", "Comment text"
                ),
                "comment_type", Map.of(
                    "type", "string",
                    "description", "Optional: comment type for target 'address' (canonical values). Aliases like 'eol_comment' are accepted at runtime.",
                    "enum", List.of("eol", "pre", "post", "plate", "repeatable"),
                    "default", "eol"
                )
            ),
            List.of("target", "comment"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }

        String target = (String) arguments.get("target");
        String comment = (String) arguments.get("comment");

        if (target == null || target.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("target parameter is required ('function' or 'address')").build())
                .build();
        }

        if (comment == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("comment parameter is required").build())
                .build();
        }

        target = target.toLowerCase();
        if (!target.equals("function") && !target.equals("address")) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Invalid target. Use 'function' or 'address'").build())
                .build();
        }

        // Dispatch to appropriate handler based on target
        if (target.equals("function")) {
            return setFunctionComment(arguments, currentProgram, comment);
        }
        return setAddressComment(arguments, currentProgram, comment);
    }

    /**
     * Set a comment on a function (appears in decompiler view).
     */
    private McpSchema.CallToolResult setFunctionComment(Map<String, Object> arguments, Program program, String comment) {
        String functionName = (String) arguments.get("function_name");

        if (functionName == null || functionName.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("function_name parameter is required when target is 'function'").build())
                .build();
        }

        // Find the function
        Function function = findFunctionByName(program, functionName);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Function not found: " + functionName).build())
                .build();
        }

        // Set the function comment within a transaction
        int transactionID = program.startTransaction("Set Function Comment");
        try {
            function.setComment(comment);
            program.endTransaction(transactionID, true);

            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Successfully set decompiler comment on function '" + functionName +
                              "': \"" + comment + "\"").build())
                .build();
        } catch (Exception e) {
            program.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error setting function comment: " + e.getMessage()).build())
                .build();
        }
    }

    /**
     * Set a comment at an address (appears in disassembly view).
     */
    private McpSchema.CallToolResult setAddressComment(Map<String, Object> arguments, Program program, String comment) {
        String addressStr = (String) arguments.get("address");
        String commentTypeStr = (String) arguments.get("comment_type");

        if (addressStr == null || addressStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("address parameter is required when target is 'address'").build())
                .build();
        }

        // Parse the address
        Address address;
        try {
            address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid address: " + addressStr).build())
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Invalid address format: " + addressStr).build())
                .build();
        }

        // Determine comment type (default to EOL comment)
        CommentType commentType = parseCommentType(commentTypeStr);

        // Get the code unit at the address
        CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
        if (codeUnit == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No code unit found at address: " + addressStr).build())
                .build();
        }

        // Set the comment within a transaction
        int transactionID = program.startTransaction("Set Disassembly Comment");
        try {
            codeUnit.setComment(commentType, comment);
            program.endTransaction(transactionID, true);

            String commentTypeName = getCommentTypeName(commentType);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Successfully set " + commentTypeName + " comment at " + addressStr +
                              ": \"" + comment + "\"").build())
                .build();
        } catch (Exception e) {
            program.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error setting comment: " + e.getMessage()).build())
                .build();
        }
    }

    /**
     * Parse comment type string into CommentType enum.
     */
    private CommentType parseCommentType(String commentTypeStr) {
        if (commentTypeStr == null) {
            return CommentType.EOL;
        }

        switch (commentTypeStr.toLowerCase()) {
            case "pre":
            case "pre_comment":
                return CommentType.PRE;
            case "post":
            case "post_comment":
                return CommentType.POST;
            case "plate":
            case "plate_comment":
                return CommentType.PLATE;
            case "repeatable":
            case "repeatable_comment":
                return CommentType.REPEATABLE;
            case "eol":
            case "eol_comment":
            default:
                return CommentType.EOL;
        }
    }

    /**
     * Get human-readable name for a comment type.
     */
    private String getCommentTypeName(CommentType commentType) {
        switch (commentType) {
            case PRE:
                return "pre";
            case POST:
                return "post";
            case PLATE:
                return "plate";
            case REPEATABLE:
                return "repeatable";
            case EOL:
            default:
                return "EOL";
        }
    }

    /**
     * Find a function by name.
     */
    private Function findFunctionByName(Program program, String functionName) {
        return FunctionLookup.findByName(program, functionName);
    }
}
