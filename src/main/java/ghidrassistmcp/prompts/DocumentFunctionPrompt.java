/*
 * MCP Prompt for documenting a function.
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
 * Prompt for generating documentation for a function.
 */
public class DocumentFunctionPrompt implements McpPrompt {

    private final DecompilerService decompilerService;

    public DocumentFunctionPrompt(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public String getName() {
        return "document_function";
    }

    @Override
    public String getDescription() {
        return "Generate comprehensive documentation for a function including description, parameters, and usage";
    }

    @Override
    public List<McpSchema.PromptArgument> getArguments() {
        return List.of(
            new McpSchema.PromptArgument(
                "function_name",
                "Name or address of the function to document",
                true
            ),
            new McpSchema.PromptArgument(
                "format",
                "Documentation format: doxygen, markdown, or plain (default: doxygen)",
                false
            )
        );
    }

    @Override
    public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
        String functionIdentifier = arguments.get("function_name");
        String format = arguments.getOrDefault("format", "doxygen");

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
        context.append("# Function Documentation Request\n\n");
        context.append("Please generate comprehensive documentation for the following function in **")
               .append(format).append("** format.\n\n");

        if (program != null) {
            Function function = findFunction(program, functionIdentifier);

            if (function != null) {
                context.append("## Function Information\n");
                context.append("- **Name**: ").append(function.getName(true)).append("\n");
                context.append("- **Address**: ").append(function.getEntryPoint()).append("\n");
                context.append("- **Signature**: ").append(function.getPrototypeString(false, false)).append("\n");
                context.append("- **Parameter Count**: ").append(function.getParameterCount()).append("\n\n");

                // Parameters
                context.append("## Parameters\n");
                var params = function.getParameters();
                if (params.length == 0) {
                    context.append("No parameters.\n\n");
                } else {
                    for (var param : params) {
                        context.append("- **").append(param.getName()).append("** (")
                               .append(param.getDataType().getName()).append(")\n");
                    }
                    context.append("\n");
                }

                // Return type
                context.append("## Return Type\n");
                context.append(function.getReturnType().getName()).append("\n\n");

                // Get decompilation
                String decompiled = decompileFunction(program, function);
                if (decompiled != null) {
                    context.append("## Decompiled Code\n```c\n");
                    context.append(decompiled);
                    context.append("\n```\n\n");
                }

            } else {
                context.append("**Error**: Function '").append(functionIdentifier).append("' not found.\n\n");
            }
        } else {
            context.append("**Note**: No program loaded. Please provide function details manually.\n\n");
        }

        context.append("## Documentation Requirements\n");
        context.append("Generate documentation that includes:\n\n");
        context.append("1. **Brief Description**: One-line summary of what the function does\n");
        context.append("2. **Detailed Description**: Full explanation of the function's purpose and behavior\n");
        context.append("3. **Parameters**: Description of each parameter, its purpose, valid values, and constraints\n");
        context.append("4. **Return Value**: What the function returns and when\n");
        context.append("5. **Side Effects**: Any global state modifications or I/O operations\n");
        context.append("6. **Preconditions**: Requirements that must be met before calling\n");
        context.append("7. **Postconditions**: Guarantees after the function completes\n");
        context.append("8. **Example Usage**: Code example showing how to use the function\n");
        context.append("9. **Related Functions**: Other functions that work with this one\n");

        if (format.equalsIgnoreCase("doxygen")) {
            context.append("\n## Output Format (Doxygen)\n");
            context.append("```c\n");
            context.append("/**\n");
            context.append(" * @brief Brief description\n");
            context.append(" * \n");
            context.append(" * Detailed description...\n");
            context.append(" * \n");
            context.append(" * @param param_name Description\n");
            context.append(" * @return Return description\n");
            context.append(" * @see related_function\n");
            context.append(" */\n");
            context.append("```\n");
        }

        List<McpSchema.PromptMessage> messages = new ArrayList<>();
        messages.add(new McpSchema.PromptMessage(
            McpSchema.Role.USER,
            new McpSchema.TextContent(context.toString())
        ));

        return new McpSchema.GetPromptResult(
            "Document function: " + functionIdentifier,
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
