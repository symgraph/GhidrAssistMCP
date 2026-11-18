/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists memory segments/blocks in the program.
 */
public class ListSegmentsTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_segments";
    }
    
    @Override
    public String getDescription() {
        return "List memory segments/blocks in the program";
    }
    
    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
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
        
        // Parse optional offset and limit
        int offset = 0;
        int limit = 100; // Default limit
        
        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Memory Segments/Blocks:\n\n");
        
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        
        int count = 0;
        int totalCount = blocks.length;
        
        for (int i = offset; i < blocks.length && count < limit; i++) {
            MemoryBlock block = blocks[i];
            
            String permissions = "";
            if (block.isRead()) permissions += "R";
            if (block.isWrite()) permissions += "W";
            if (block.isExecute()) permissions += "X";
            
            result.append("- ").append(block.getName())
                  .append(" @ ").append(block.getStart())
                  .append("-").append(block.getEnd())
                  .append(" (").append(String.format("0x%x", block.getSize())).append(" bytes)")
                  .append(" [").append(permissions).append("]")
                  .append(" Type: ").append(block.getType())
                  .append("\n");
            
            count++;
        }
        
        if (totalCount == 0) {
            result.append("No memory blocks found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" segments");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}