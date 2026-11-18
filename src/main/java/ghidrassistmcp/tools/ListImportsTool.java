/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists imported functions and symbols.
 */
public class ListImportsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_imports";
    }
    
    @Override
    public String getDescription() {
        return "List imported functions and symbols";
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
        result.append("Imported Functions and Symbols:\n\n");
        
        SymbolIterator symbolIter = currentProgram.getSymbolTable().getSymbolIterator();
        
        int count = 0;
        int totalCount = 0;
        
        while (symbolIter.hasNext()) {
            Symbol symbol = symbolIter.next();
            
            // Only include external symbols (imports)
            if (symbol.isExternal() && 
                (symbol.getSymbolType() == SymbolType.FUNCTION || 
                 symbol.getSymbolType() == SymbolType.LABEL)) {
                
                totalCount++;
                
                // Apply offset
                if (totalCount <= offset) {
                    continue;
                }
                
                // Apply limit to displayed results only; keep scanning for a true total.
                if (count < limit) {
                    String libraryName = "unknown";
                    if (symbol.getParentNamespace() != null) {
                        libraryName = symbol.getParentNamespace().getName();
                    }

                    result.append("- ").append(symbol.getName())
                          .append(" from ").append(libraryName)
                          .append(" @ ").append(symbol.getAddress())
                          .append(" (").append(symbol.getSymbolType()).append(")")
                          .append("\n");

                    count++;
                }
            }
        }
        
        if (totalCount == 0) {
            result.append("No imported symbols found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" imports");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}
