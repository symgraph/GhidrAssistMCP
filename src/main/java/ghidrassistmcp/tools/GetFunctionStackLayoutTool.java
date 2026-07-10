package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class GetFunctionStackLayoutTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "get_function_stack_layout"; }

    @Override
    public String getDescription() { return "Get the stack frame layout for a function"; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of("function_name_or_address", Map.of("type", "string", "description", "Function name or address")),
            List.of("function_name_or_address"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No program currently loaded").build();
        }

        String identifier = (String) arguments.get("function_name_or_address");
        if (identifier == null) {
            return McpSchema.CallToolResult.builder().addTextContent("function_name_or_address is required").build();
        }

        Function function = findFunction(currentProgram, identifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder().addTextContent("Function not found: " + identifier).build();
        }

        StackFrame stackFrame = function.getStackFrame();
        if (stackFrame == null) {
            return McpSchema.CallToolResult.builder().addTextContent("No stack frame for: " + identifier).build();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Stack Layout for: ").append(function.getName(true))
          .append(" @ ").append(function.getEntryPoint()).append("\n");
        sb.append("Frame size: ").append(stackFrame.getFrameSize()).append(" bytes\n");
        sb.append("Return address offset: ").append(stackFrame.getReturnAddressOffset()).append("\n\n");

        Variable[] vars = stackFrame.getStackVariables();
        if (vars.length == 0) {
            sb.append("No stack variables.\n");
        } else {
            sb.append("Stack Variables:\n");
            for (Variable var : vars) {
                sb.append(String.format("  [%+5d] %-20s %-15s %s\n",
                    var.getStackOffset(),
                    var.getDataType().getName(),
                    var.getName(),
                    var.getComment() != null ? "// " + var.getComment() : ""));
            }
        }

        return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
    }

    private Function findFunction(Program program, String identifier) {
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function f = program.getFunctionManager().getFunctionAt(addr);
                if (f != null) return f;
            }
        } catch (Exception e) { /* not an address */ }
        return FunctionLookup.findByName(program, identifier);
    }
}
