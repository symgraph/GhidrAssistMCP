/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that provides detailed information about a specific function.
 */
public class GetFunctionInfoTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "analyze_function";
    }
    
    @Override
    public String getDescription() {
        return "Get detailed information about a specific function";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of("function_name", new JsonSchema("string", null, null, null, null, null)),
            List.of("function_name"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }
        
        String functionName = (String) arguments.get("function_name");
        if (functionName == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Function name is required").build())
                .build();
        }
        
        String info = getFunctionInfo(currentProgram, functionName);
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(info).build())
            .build();
    }
    
    private String getFunctionInfo(Program program, String functionName) {
        var function = FunctionLookup.findByName(program, functionName);
        if (function == null) {
            return "Function not found: " + functionName;
        }

        StringBuilder info = new StringBuilder();
        info.append("Function Information:\n");
        info.append("Name: ").append(function.getName(true)).append("\n");
        info.append("Entry Point: ").append(function.getEntryPoint()).append("\n");
        info.append("Body: ").append(function.getBody()).append("\n");
        info.append("Parameter Count: ").append(function.getParameterCount()).append("\n");
        info.append("Return Type: ").append(function.getReturnType()).append("\n");
        info.append("Signature: ").append(function.getSignature()).append("\n");

        return info.toString();
    }
}