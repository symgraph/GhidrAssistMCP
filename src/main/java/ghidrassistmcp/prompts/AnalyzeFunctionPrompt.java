/*
 * MCP Prompt for analyzing a function.
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
 * Prompt for comprehensive function analysis.
 */
public class AnalyzeFunctionPrompt implements McpPrompt {

    private final DecompilerService decompilerService;

    public AnalyzeFunctionPrompt(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public String getName() {
        return "analyze_function";
    }

    @Override
    public String getDescription() {
        return "Analyze a function comprehensively including decompilation, cross-references, and behavior";
    }

    @Override
    public List<McpSchema.PromptArgument> getArguments() {
        return List.of(
            new McpSchema.PromptArgument(
                "function_name",
                "Name or address of the function to analyze",
                true
            )
        );
    }

    @Override
    public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
        String functionIdentifier = arguments.get("function_name");

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
        context.append("# Function Analysis Request\n\n");
        context.append("Please provide a comprehensive analysis of the following function.\n\n");

        if (program != null) {
            // Find the function
            Function function = findFunction(program, functionIdentifier);

            if (function != null) {
                context.append("## Function Information\n");
                context.append("- **Name**: ").append(function.getName(true)).append("\n");
                context.append("- **Address**: ").append(function.getEntryPoint()).append("\n");
                context.append("- **Signature**: ").append(function.getPrototypeString(false, false)).append("\n");
                context.append("- **Calling Convention**: ").append(function.getCallingConventionName()).append("\n");
                context.append("- **Parameter Count**: ").append(function.getParameterCount()).append("\n");
                context.append("- **Is Thunk**: ").append(function.isThunk()).append("\n\n");

                // Get decompilation
                String decompiled = decompileFunction(program, function);
                if (decompiled != null) {
                    context.append("## Decompiled Code\n```c\n");
                    context.append(decompiled);
                    context.append("\n```\n\n");
                }

                // Get called functions
                context.append("## Called Functions\n");
                var calledFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
                if (calledFunctions.isEmpty()) {
                    context.append("No functions called.\n\n");
                } else {
                    for (Function called : calledFunctions) {
                        context.append("- ").append(called.getName()).append(" @ ").append(called.getEntryPoint()).append("\n");
                    }
                    context.append("\n");
                }

                // Get calling functions
                context.append("## Calling Functions\n");
                var callingFunctions = function.getCallingFunctions(TaskMonitor.DUMMY);
                if (callingFunctions.isEmpty()) {
                    context.append("No functions call this function.\n\n");
                } else {
                    for (Function caller : callingFunctions) {
                        context.append("- ").append(caller.getName()).append(" @ ").append(caller.getEntryPoint()).append("\n");
                    }
                    context.append("\n");
                }

            } else {
                context.append("**Error**: Function '").append(functionIdentifier).append("' not found.\n\n");
            }
        } else {
            context.append("**Note**: No program loaded. Please provide function details manually.\n\n");
        }

        context.append("## Analysis Tasks\n");
        context.append("Please analyze:\n");
        context.append("1. **Purpose**: What does this function do?\n");
        context.append("2. **Parameters**: What are the input parameters and their purposes?\n");
        context.append("3. **Return Value**: What does the function return?\n");
        context.append("4. **Side Effects**: Does it modify global state or have other side effects?\n");
        context.append("5. **Algorithm**: Describe the algorithm or logic used.\n");
        context.append("6. **Security**: Are there any potential security issues?\n");
        context.append("7. **Suggested Name**: If the current name is unclear, suggest a better name.\n");

        List<McpSchema.PromptMessage> messages = new ArrayList<>();
        messages.add(new McpSchema.PromptMessage(
            McpSchema.Role.USER,
            new McpSchema.TextContent(context.toString())
        ));

        return new McpSchema.GetPromptResult(
            "Analyze function: " + functionIdentifier,
            messages
        );
    }

    private Function findFunction(Program program, String identifier) {
        // Try as address first
        try {
            var addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // Not an address, try as name
        }

        // Try as function name
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
