/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists namespaces in the program.
 */
public class ListNamespacesTool implements McpTool {
    
    @Override
    public String getName() {
        return "get_namespaces";
    }
    
    @Override
    public String getDescription() {
        return "List namespaces in the program";
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
        result.append("Namespaces in program:\n\n");
        
        // Get all symbols and find unique namespaces
        SymbolIterator symbolIter = currentProgram.getSymbolTable().getSymbolIterator();
        java.util.Set<Namespace> uniqueNamespaces = new java.util.HashSet<>();
        
        while (symbolIter.hasNext()) {
            Symbol symbol = symbolIter.next();
            Namespace namespace = symbol.getParentNamespace();
            if (namespace != null && !namespace.isGlobal()) {
                uniqueNamespaces.add(namespace);
            }
        }
        
        int count = 0;
        int totalCount = 0;
        
        for (Namespace namespace : uniqueNamespaces) {
            totalCount++;
            
            // Apply offset
            if (totalCount <= offset) {
                continue;
            }
            
            // Apply limit
            if (count >= limit) {
                break;
            }
            
            result.append("- ").append(namespace.getName());
            
            // Show parent namespace if not global
            if (namespace.getParentNamespace() != null && !namespace.getParentNamespace().isGlobal()) {
                result.append(" (in ").append(namespace.getParentNamespace().getName()).append(")");
            }
            
            // Count symbols in this namespace
            try {
                int symbolCount = 0;
                SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(namespace);
                while (symbols.hasNext()) {
                    symbols.next();
                    symbolCount++;
                }
                result.append(" [").append(symbolCount).append(" symbols]");
            } catch (Exception e) {
                // Ignore errors counting symbols
            }
            
            result.append("\n");
            count++;
        }
        
        if (totalCount == 0) {
            result.append("No user-defined namespaces found in the program.");
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount).append(" namespaces");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }
        
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }
}