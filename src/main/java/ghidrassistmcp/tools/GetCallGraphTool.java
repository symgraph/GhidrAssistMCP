/*
 * MCP tool for getting function call graph.
 */
package ghidrassistmcp.tools;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets the function call graph (callers and callees).
 */
public class GetCallGraphTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_call_graph";
    }

    @Override
    public String getDescription() {
        return "Get the function call graph showing callers and callees with specified depth";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "function", Map.of(
                    "type", "string",
                    "description", "Function identifier (name or address)"
                ),
                "depth", Map.of(
                    "type", "integer",
                    "description", "Optional: max graph depth (default 2, capped at 5)",
                    "default", 2
                ),
                "direction", Map.of(
                    "type", "string",
                    "description", "Optional: which side of the call graph to return",
                    "enum", List.of("both", "callers", "callees"),
                    "default", "both"
                )
            ),
            List.of("function"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String functionIdentifier = (String) arguments.get("function");
        int depth = 2; // Default depth
        String direction = "both";

        if (arguments.get("depth") instanceof Number) {
            depth = ((Number) arguments.get("depth")).intValue();
            depth = Math.min(depth, 5); // Limit max depth to avoid excessive output
        }

        if (arguments.get("direction") instanceof String) {
            String dir = (String) arguments.get("direction");
            if (dir != null && !dir.trim().isEmpty()) {
                direction = dir.toLowerCase();
            }
        }

        if (!direction.equals("both") && !direction.equals("callers") && !direction.equals("callees")) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid direction. Use 'both', 'callers', or 'callees'")
                .build();
        }

        // Find the function
        Function function = findFunction(currentProgram, functionIdentifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionIdentifier)
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Call Graph for: ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        Set<String> visited = new HashSet<>();

        // Get callers (functions that call this function)
        if (direction.equals("callers") || direction.equals("both")) {
            result.append("## Calling Functions (Who calls this):\n");
            buildCallerTree(currentProgram, function, depth, 0, visited, result);
            result.append("\n");
        }

        visited.clear();

        // Get callees (functions called by this function)
        if (direction.equals("callees") || direction.equals("both")) {
            result.append("## Called Functions (What this calls):\n");
            buildCalleeTree(currentProgram, function, depth, 0, visited, result);
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private void buildCallerTree(Program program, Function function, int maxDepth, int currentDepth,
                                  Set<String> visited, StringBuilder result) {
        String indent = "  ".repeat(currentDepth);
        String key = function.getEntryPoint().toString();

        if (visited.contains(key)) {
            result.append(indent).append("- ").append(function.getName(true))
                  .append(" @ ").append(function.getEntryPoint())
                  .append(" (recursive/already visited)\n");
            return;
        }

        visited.add(key);
        result.append(indent).append("- ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n");

        if (currentDepth < maxDepth) {
            Set<Function> callers = function.getCallingFunctions(TaskMonitor.DUMMY);
            for (Function caller : callers) {
                buildCallerTree(program, caller, maxDepth, currentDepth + 1, visited, result);
            }
        }
    }

    private void buildCalleeTree(Program program, Function function, int maxDepth, int currentDepth,
                                  Set<String> visited, StringBuilder result) {
        String indent = "  ".repeat(currentDepth);
        String key = function.getEntryPoint().toString();

        if (visited.contains(key)) {
            result.append(indent).append("- ").append(function.getName(true))
                  .append(" @ ").append(function.getEntryPoint())
                  .append(" (recursive/already visited)\n");
            return;
        }

        visited.add(key);
        result.append(indent).append("- ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n");

        if (currentDepth < maxDepth) {
            Set<Function> callees = function.getCalledFunctions(TaskMonitor.DUMMY);
            for (Function callee : callees) {
                buildCalleeTree(program, callee, maxDepth, currentDepth + 1, visited, result);
            }
        }
    }

    private Function findFunction(Program program, String identifier) {
        // Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not an address
        }

        // Try as function name
        return FunctionLookup.findByName(program, identifier);
    }
}
