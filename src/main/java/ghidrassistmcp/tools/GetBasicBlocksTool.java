/*
 * MCP tool for getting basic blocks (control flow graph).
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that gets basic blocks and control flow graph for a function.
 */
public class GetBasicBlocksTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_basic_blocks";
    }

    @Override
    public String getDescription() {
        return "Get basic blocks and control flow graph for a function";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "function", new McpSchema.JsonSchema("string", null, null, null, null, null)
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

        // Find the function
        Function function = findFunction(currentProgram, functionIdentifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found: " + functionIdentifier)
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Basic Blocks for: ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        try {
            BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(
                function.getBody(), TaskMonitor.DUMMY);

            int blockCount = 0;

            while (blocks.hasNext()) {
                CodeBlock block = blocks.next();
                blockCount++;

                result.append("## Block ").append(blockCount).append("\n");
                result.append("- **Start**: ").append(block.getFirstStartAddress()).append("\n");
                result.append("- **End**: ").append(block.getMaxAddress()).append("\n");
                result.append("- **Size**: ").append(block.getNumAddresses()).append(" addresses\n");
                result.append("- **Name**: ").append(block.getName()).append("\n");

                // Get successors (where control can flow to)
                result.append("- **Successors**:\n");
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                boolean hasSucc = false;
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    result.append("    - ").append(ref.getDestinationAddress())
                          .append(" (").append(ref.getFlowType()).append(")\n");
                    hasSucc = true;
                }
                if (!hasSucc) {
                    result.append("    - (none - exit block)\n");
                }

                // Get predecessors (where control can come from)
                result.append("- **Predecessors**:\n");
                CodeBlockReferenceIterator srcIter = block.getSources(TaskMonitor.DUMMY);
                boolean hasPred = false;
                while (srcIter.hasNext()) {
                    CodeBlockReference ref = srcIter.next();
                    result.append("    - ").append(ref.getSourceAddress())
                          .append(" (").append(ref.getFlowType()).append(")\n");
                    hasPred = true;
                }
                if (!hasPred) {
                    result.append("    - (none - entry block)\n");
                }

                result.append("\n");
            }

            result.append("## Summary\n");
            result.append("- Total Basic Blocks: ").append(blockCount).append("\n");
            result.append("- Function Size: ").append(function.getBody().getNumAddresses()).append(" addresses\n");

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error getting basic blocks: " + e.getMessage())
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private Function findFunction(Program program, String identifier) {
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not an address
        }

        return FunctionLookup.findByName(program, identifier);
    }
}
