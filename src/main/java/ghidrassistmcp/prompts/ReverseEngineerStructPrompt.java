package ghidrassistmcp.prompts;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.modern.McpSchema;

public class ReverseEngineerStructPrompt implements McpPrompt {

    @Override
    public String getName() { return "reverse_engineer_struct"; }

    @Override
    public String getDescription() { return "Reverse engineer a data structure from usage patterns"; }

    @Override
    public List<McpSchema.PromptArgument> getArguments() {
        return List.of(
            McpSchema.PromptArgument.builder("address").description("Address where structure is used").required(true).build()
        );
    }

    @Override
    public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
        String address = arguments.get("address");

        StringBuilder context = new StringBuilder();
        context.append("# Structure Reverse Engineering Request\n\n");
        context.append("Reverse engineer the data structure used at address ").append(address).append(".\n\n");

        context.append("## Analysis Steps\n\n");
        context.append("1. **Get Context**: Call `get_hexdump` with address and length to see the raw data\n");
        context.append("2. **Find Usage**: Call `get_xrefs_to` to find all references to this address\n");
        context.append("3. **Get Functions**: For each referencing function, call `get_pseudocode`\n");
        context.append("4. **Analyze Access Patterns**: Look at how the data is accessed\n\n");

        context.append("## Structure Recovery\n\n");
        context.append("### Field Layout\n");
        context.append("- What offsets are accessed?\n");
        context.append("- What are the sizes at each offset?\n");
        context.append("- What operations are performed (read/write)?\n\n");
        context.append("### Field Types\n");
        context.append("- Infer types from operations\n");
        context.append("- Identify pointers vs integers vs floating point\n");
        context.append("- Look for array patterns\n\n");
        context.append("### Relationships\n");
        context.append("- Are there pointers to other structures?\n");
        context.append("- Is this part of a linked list or tree?\n\n");

        context.append("## Output\n\n");
        context.append("Provide a C structure definition:\n\n```c\ntypedef struct {\n");
        context.append("    type1 field1;    // offset 0x00 - description\n");
        context.append("    type2 field2;    // offset 0x04 - description\n");
        context.append("} StructureName;\n```\n\n");
        context.append("Then call `create_structure` to define it.\n");

        return McpSchema.GetPromptResult.builder(List.of(new McpSchema.PromptMessage(McpSchema.Role.USER, McpSchema.TextContent.builder(context.toString()).build()))).description("Reverse engineer struct at " + address).build();
    }
}
