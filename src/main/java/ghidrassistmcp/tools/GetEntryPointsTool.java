package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

public class GetEntryPointsTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "get_entry_points"; }

    @Override
    public String getDescription() { return "Get the entry points of the program"; }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object", Map.of(), List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("No program currently loaded").build()).build();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Entry Points:\n\n");

        AddressIterator entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        int count = 0;
        while (entryPoints.hasNext()) {
            Address addr = entryPoints.next();
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            Symbol[] symbols = currentProgram.getSymbolTable().getSymbols(addr);
            String name = func != null ? func.getName(true) :
                          (symbols.length > 0 ? symbols[0].getName(true) : "unknown");

            sb.append("- ").append(addr).append(" ").append(name);
            if (func != null) {
                sb.append(" (function, ").append(func.getParameterCount()).append(" params)");
            }
            sb.append("\n");
            count++;
        }

        if (count == 0) {
            sb.append("No entry points found.");
        } else {
            sb.append("\nTotal: ").append(count).append(" entry points");
        }

        return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder(sb.toString()).build()).build();
    }
}
