package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/** Read a function declaration without confusing it with a byte fingerprint. */
public final class GetFunctionPrototypeTool implements McpTool {
    @Override public String getName() { return "get_function_prototype"; }
    @Override public String getLegacyName() { return "analyze_function"; }
    @Override public boolean isCacheable() { return true; }
    @Override public boolean isIdempotent() { return true; }
    @Override public String getDescription() {
        return "Get a function's C prototype, return type, calling convention, and parameter count. This is its declaration, not a byte pattern or hash.";
    }
    @Override public JsonSchema getInputSchema() {
        return new JsonSchema("object", Map.of("function", Map.of("type", "string",
            "description", "Function name, qualified name, entry address, or address inside its body")),
            List.of("function"), false, null, null);
    }
    @Override public Map<String, Object> getOutputSchema() {
        return Map.of("type", "object", "properties", Map.of("name", Map.of("type", "string"), "address", Map.of("type", "string"),
                "prototype", Map.of("type", "string"), "calling_convention", Map.of("type", "string"),
                "return_type", Map.of("type", "string"),
                "parameter_count", Map.of("type", "integer", "minimum", 0)),
            "required", List.of("name", "address", "prototype", "calling_convention", "return_type", "parameter_count"), "additionalProperties", false);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        if (program == null) return error("No program currently loaded");
        if (!(arguments.get("function") instanceof String identifier) || identifier.isBlank()) {
            return error("Missing required parameter: function");
        }
        Function function = GetFunctionHashTool.resolve(program, identifier);
        if (function == null) return error("Function not found: " + identifier);
        try {
            String convention = function.getCallingConventionName();
            Map<String, Object> result = Map.of("name", function.getName(true),
                "address", function.getEntryPoint().toString(),
                "prototype", function.getSignature().getPrototypeString(),
                "calling_convention", convention == null ? "unknown" : convention,
                "return_type", function.getReturnType().getDisplayName(),
                "parameter_count", function.getParameterCount());
            return McpSchema.CallToolResult.builder().structuredContent(result)
                .addContent(McpSchema.TextContent.builder(new ObjectMapper().writeValueAsString(result)).build()).build();
        } catch (Exception e) {
            return error("Error reading function prototype: " + e.getMessage());
        }
    }
    private static McpSchema.CallToolResult error(String text) {
        return McpSchema.CallToolResult.builder().isError(true).addContent(McpSchema.TextContent.builder(text).build()).build();
    }
}
