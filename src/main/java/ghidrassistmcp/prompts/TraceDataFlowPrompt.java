/*
 * MCP Prompt for tracing data flow.
 */
package ghidrassistmcp.prompts;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Prompt for tracing data flow through a function or variable.
 */
public class TraceDataFlowPrompt implements McpPrompt {

    private final DecompilerService decompilerService;

    public TraceDataFlowPrompt(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public String getName() {
        return "trace_data_flow";
    }

    @Override
    public String getDescription() {
        return "Trace data flow through a function, tracking how input data is transformed and used";
    }

    @Override
    public List<McpSchema.PromptArgument> getArguments() {
        return List.of(
            new McpSchema.PromptArgument(
                "function_name",
                "Name or address of the function to trace",
                true
            ),
            new McpSchema.PromptArgument(
                "variable",
                "Specific variable or parameter to trace (optional)",
                false
            )
        );
    }

    @Override
    public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
        String functionIdentifier = arguments.get("function_name");
        String variable = arguments.get("variable");

        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return new McpSchema.GetPromptResult(
                "Error: function_name argument is required",
                List.of(new McpSchema.PromptMessage(
                    McpSchema.Role.USER,
                    new McpSchema.TextContent("Error: function_name argument is required")
                ))
            );
        }

        StringBuilder context = new StringBuilder();
        context.append("# Data Flow Analysis Request\n\n");
        context.append("Please trace the data flow ");
        if (variable != null && !variable.isEmpty()) {
            context.append("for variable **").append(variable).append("** ");
        }
        context.append("through the following function.\n\n");

        if (program != null) {
            Function function = findFunction(program, functionIdentifier);

            if (function != null) {
                context.append("## Function Information\n");
                context.append("- **Name**: ").append(function.getName(true)).append("\n");
                context.append("- **Address**: ").append(function.getEntryPoint()).append("\n");
                context.append("- **Signature**: ").append(function.getPrototypeString(false, false)).append("\n\n");

                // Parameters as potential data sources
                context.append("## Input Parameters (Data Sources)\n");
                var params = function.getParameters();
                if (params.length == 0) {
                    context.append("No parameters.\n\n");
                } else {
                    for (var param : params) {
                        context.append("- **").append(param.getName()).append("**: ")
                               .append(param.getDataType().getName()).append("\n");
                    }
                    context.append("\n");
                }

                // Get decompilation
                String decompiled = decompileFunction(program, function);
                if (decompiled != null) {
                    context.append("## Decompiled Code\n```c\n");
                    context.append(decompiled);
                    context.append("\n```\n\n");
                }

                // Called functions as potential sinks
                context.append("## Called Functions (Potential Data Sinks)\n");
                var calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
                if (calledFunctions.isEmpty()) {
                    context.append("No functions called.\n\n");
                } else {
                    for (Function called : calledFunctions) {
                        context.append("- ").append(called.getName()).append("\n");
                    }
                    context.append("\n");
                }

            } else {
                context.append("**Error**: Function '").append(functionIdentifier).append("' not found.\n\n");
            }
        } else {
            context.append("**Note**: No program loaded. Please provide function details manually.\n\n");
        }

        context.append("## Data Flow Analysis Tasks\n");
        context.append("Please analyze and document:\n\n");
        context.append("1. **Data Sources**: Where does input data come from?\n");
        context.append("   - Parameters\n");
        context.append("   - Global variables\n");
        context.append("   - Return values from called functions\n");
        context.append("   - Memory reads\n\n");

        context.append("2. **Transformations**: How is the data modified?\n");
        context.append("   - Arithmetic operations\n");
        context.append("   - Type conversions\n");
        context.append("   - String manipulations\n");
        context.append("   - Encoding/decoding\n\n");

        context.append("3. **Data Sinks**: Where does the data go?\n");
        context.append("   - Function calls (which parameter?)\n");
        context.append("   - Memory writes\n");
        context.append("   - Return values\n");
        context.append("   - Global variable assignments\n\n");

        context.append("4. **Taint Analysis**: If user-controlled data enters, where can it flow?\n");
        context.append("   - Identify tainted variables\n");
        context.append("   - Track propagation through operations\n");
        context.append("   - Note any sanitization points\n\n");

        context.append("5. **Data Flow Graph**: Describe the flow as a graph of:\n");
        context.append("   - Nodes (variables, memory locations)\n");
        context.append("   - Edges (data dependencies)\n");

        if (variable != null && !variable.isEmpty()) {
            context.append("\n## Specific Variable: ").append(variable).append("\n");
            context.append("Focus specifically on tracing this variable through the function:\n");
            context.append("- Where is it defined/assigned?\n");
            context.append("- What operations are performed on it?\n");
            context.append("- Where is it used?\n");
            context.append("- What is its final state/destination?\n");
        }

        List<McpSchema.PromptMessage> messages = new ArrayList<>();
        messages.add(new McpSchema.PromptMessage(
            McpSchema.Role.USER,
            new McpSchema.TextContent(context.toString())
        ));

        return new McpSchema.GetPromptResult(
            "Trace data flow: " + functionIdentifier + (variable != null ? " (var: " + variable + ")" : ""),
            messages
        );
    }

    private Function findFunction(Program program, String identifier) {
        try {
            var addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // Not an address
        }

        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(identifier)) {
                return function;
            }
        }
        return null;
    }

    private String decompileFunction(Program program, Function function) {
        try (DecompilerSession session = decompilerService.open(program)) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), TaskMonitor.DUMMY);
            if (results.decompileCompleted()) {
                return results.getDecompiledFunction().getC();
            }
        }
        return null;
    }
}
