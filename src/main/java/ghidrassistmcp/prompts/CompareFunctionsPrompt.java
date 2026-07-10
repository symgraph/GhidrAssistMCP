package ghidrassistmcp.prompts;

import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.spec.McpSchema;

public class CompareFunctionsPrompt implements McpPrompt {

    private final DecompilerService decompilerService;

    public CompareFunctionsPrompt(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public String getName() { return "compare_functions"; }

    @Override
    public String getDescription() { return "Compare two functions for similarity and differences"; }

    @Override
    public List<McpSchema.PromptArgument> getArguments() {
        return List.of(
            new McpSchema.PromptArgument("func1", "First function name or address", true),
            new McpSchema.PromptArgument("func2", "Second function name or address", true)
        );
    }

    @Override
    public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
        String func1 = arguments.get("func1");
        String func2 = arguments.get("func2");

        StringBuilder context = new StringBuilder();
        context.append("# Function Comparison Request\n\n");
        context.append("Compare functions '").append(func1).append("' and '").append(func2).append("'.\n\n");

        if (program != null) {
            appendFunctionContext(context, program, func1, "Function 1");
            appendFunctionContext(context, program, func2, "Function 2");
        }

        context.append("## Comparison Analysis\n\n");
        context.append("### Structural Similarity\n");
        context.append("- Number of basic blocks (use `get_basic_blocks`)\n");
        context.append("- Control flow patterns\n");
        context.append("- Loop structures\n\n");
        context.append("### Semantic Similarity\n");
        context.append("- Parameter types and counts\n");
        context.append("- Return types\n");
        context.append("- Local variable usage (use `variables` with action='list')\n");
        context.append("- Called functions (use `xrefs`)\n\n");
        context.append("### Code Differences\n");
        context.append("- Highlight specific differences in logic\n");
        context.append("- Note any added/removed functionality\n\n");
        context.append("## Output\n");
        context.append("1. **Similarity Score**: 0-100%\n");
        context.append("2. **Key Differences**: With code snippets\n");
        context.append("3. **Key Similarities**: Shared patterns\n");
        context.append("4. **Assessment**: Related? (duplicate, patched, different implementation?)\n");

        return new McpSchema.GetPromptResult("Compare: " + func1 + " vs " + func2,
            List.of(new McpSchema.PromptMessage(McpSchema.Role.USER, new McpSchema.TextContent(context.toString()))));
    }

    private void appendFunctionContext(StringBuilder context, Program program, String identifier, String label) {
        Function function = findFunction(program, identifier);
        if (function != null) {
            context.append("## ").append(label).append(": ").append(function.getName(true))
                   .append(" @ ").append(function.getEntryPoint()).append("\n");
            context.append("- Signature: ").append(function.getPrototypeString(false, false)).append("\n");
            context.append("- Size: ").append(function.getBody().getNumAddresses()).append(" bytes\n");

            String decompiled = decompile(program, function);
            if (decompiled != null) {
                context.append("\n```c\n").append(decompiled).append("\n```\n\n");
            }
        } else {
            context.append("## ").append(label).append(": ").append(identifier).append(" (not found)\n\n");
        }
    }

    private Function findFunction(Program program, String identifier) {
        try {
            var addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function f = program.getFunctionManager().getFunctionAt(addr);
                if (f != null) return f;
            }
        } catch (Exception e) { }
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(identifier)) return f;
        }
        return null;
    }

    private String decompile(Program program, Function function) {
        try (DecompilerSession session = decompilerService.open(program)) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), TaskMonitor.DUMMY);
            if (results.decompileCompleted()) return results.getDecompiledFunction().getC();
        }
        return null;
    }
}
