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
 * MCP tool that provides basic information about the currently loaded program.
 */
public class ProgramInfoTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_binary_info";
    }
    
    @Override
    public String getDescription() {
        return "Get information about the currently loaded program";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object", Map.of(), List.of(), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .build();
        }
        
        String info = buildProgramInfo(currentProgram);
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(info).build())
            .build();
    }
    
    private String buildProgramInfo(Program program) {
        StringBuilder info = new StringBuilder();
        info.append("Program Information:\n");
        info.append("Name: ").append(program.getName()).append("\n");
        info.append("Language: ").append(program.getLanguage().getLanguageDescription()).append("\n");
        info.append("Address Space: ").append(program.getAddressFactory().getDefaultAddressSpace().getName()).append("\n");
        info.append("Image Base: ").append(program.getImageBase()).append("\n");
        info.append("Min Address: ").append(program.getMinAddress()).append("\n");
        info.append("Max Address: ").append(program.getMaxAddress()).append("\n");
        info.append("Function Count: ").append(program.getFunctionManager().getFunctionCount()).append("\n");
        
        return info.toString();
    }
}