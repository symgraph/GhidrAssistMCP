/*
 * MCP tool for getting code representation of a function.
 * Consolidates decompile_function, disassemble_function, and get_pcode into a single tool.
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that gets code representation of a function in various formats.
 * Replaces separate decompile_function, disassemble_function, and get_pcode tools.
 */
public class GetCodeTool implements McpTool {

    private final DecompilerService decompilerService;

    public GetCodeTool(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public boolean isLongRunning() {
        // Decompiler and pcode formats require decompilation
        return true;
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getCacheDiscriminator(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend) {
        String format = (String) arguments.get("format");
        if (format != null && format.equalsIgnoreCase("disassembly")) {
            return "disassembly";
        }
        return decompilerService.getOptionsFingerprint(currentProgram);
    }

    @Override
    public String getName() {
        return "get_code";
    }

    @Override
    public String getDescription() {
        return "Get code representation of a function in various formats (decompiler, disassembly, or pcode)";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "function", Map.of(
                    "type", "string",
                    "description", "Function identifier (name, qualified name like Namespace::Func, or address like 0x401000)"
                ),
                "format", Map.of(
                    "type", "string",
                    "description", "Output format for the requested function",
                    "enum", List.of("decompiler", "disassembly", "pcode")
                ),
                "raw", Map.of(
                    "type", "boolean",
                    "description", "Optional: Only affects format 'pcode' (raw pcode ops vs grouped by basic blocks)",
                    "default", false
                )
            ),
            List.of("function", "format"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return executeWithMonitor(arguments, currentProgram, TaskMonitor.DUMMY);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, McpTask task) {
        TaskMonitor monitor = new McpTaskMonitor(task, 0, 100, "Retrieving function code");
        return executeWithMonitor(arguments, currentProgram, monitor);
    }

    private McpSchema.CallToolResult executeWithMonitor(Map<String, Object> arguments,
            Program currentProgram, TaskMonitor monitor) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("No program currently loaded").build())
                .isError(true)
                .build();
        }

        String functionIdentifier = (String) arguments.get("function");
        String format = (String) arguments.get("format");
        boolean raw = Boolean.TRUE.equals(arguments.get("raw"));

        if (functionIdentifier == null || functionIdentifier.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("function parameter is required").build())
                .isError(true)
                .build();
        }

        if (format == null || format.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("format parameter is required (decompiler, disassembly, or pcode)").build())
                .isError(true)
                .build();
        }

        format = format.toLowerCase();
        if (!format.equals("decompiler") && !format.equals("disassembly") && !format.equals("pcode")) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Invalid format. Use 'decompiler', 'disassembly', or 'pcode'").build())
                .isError(true)
                .build();
        }

        // Find the function
        Function function = findFunction(currentProgram, functionIdentifier);
        if (function == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Function not found: " + functionIdentifier).build())
                .isError(true)
                .build();
        }

        // Dispatch to appropriate handler based on format
        switch (format) {
            case "decompiler":
                return getDecompiledCode(currentProgram, function, monitor);
            case "disassembly":
                return getDisassemblyCode(currentProgram, function, monitor);
            case "pcode":
                return getPcodeRepresentation(currentProgram, function, raw, monitor);
            default:
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Unknown format: " + format).build())
                    .isError(true)
                    .build();
        }
    }

    /**
     * Get decompiled C-like code for a function.
     */
    private McpSchema.CallToolResult getDecompiledCode(Program program, Function function, TaskMonitor monitor) {
        try (DecompilerSession session = decompilerService.open(function.getProgram())) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), monitor);

            if (monitor.isCancelled()) {
                return cancelledResult();
            }
            if (results.isTimedOut()) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Decompilation timed out for function: " + function.getName(true)).build())
                    .isError(true)
                    .build();
            }

            if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Decompilation error for function " + function.getName(true) + ": " + results.getErrorMessage()).build())
                    .isError(true)
                    .build();
            }

            String decompiledCode = results.getDecompiledFunction().getC();

            if (decompiledCode == null || decompiledCode.trim().isEmpty()) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("No decompiled code available for function: " + function.getName(true)).build())
                    .isError(true)
                    .build();
            }

            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Decompiled function " + function.getName(true) + ":\n\n" + decompiledCode).build())
                .build();

        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Error decompiling function " + function.getName(true) + ": " + e.getMessage()).build())
                .isError(true)
                .build();
        }
    }

    /**
     * Get disassembly for a function.
     */
    private McpSchema.CallToolResult getDisassemblyCode(Program program, Function function, TaskMonitor monitor) {
        StringBuilder result = new StringBuilder();
        result.append("Disassembly of function: ").append(function.getName(true)).append("\n");
        result.append("Entry Point: ").append(function.getEntryPoint()).append("\n\n");

        // Iterate through instructions in the function
        InstructionIterator instrIter = program.getListing().getInstructions(function.getBody(), true);

        int instructionCount = 0;
        while (instrIter.hasNext()) {
            if (monitor.isCancelled()) {
                return cancelledResult();
            }
            Instruction instruction = instrIter.next();

            result.append(instruction.getAddress()).append(": ");
            result.append(instruction.getMnemonicString());

            // Add operands
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                if (i == 0) {
                    result.append(" ");
                } else {
                    result.append(", ");
                }
                result.append(instruction.getDefaultOperandRepresentation(i));
            }

            // Add any comments
            String comment = instruction.getComment(CommentType.EOL);
            if (comment != null && !comment.trim().isEmpty()) {
                result.append(" ; ").append(comment.trim());
            }

            result.append("\n");
            instructionCount++;
        }

        result.append("\nTotal instructions: ").append(instructionCount);

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    /**
     * Get P-Code representation for a function.
     */
    private McpSchema.CallToolResult getPcodeRepresentation(Program program, Function function, boolean raw, TaskMonitor monitor) {
        StringBuilder result = new StringBuilder();
        result.append("P-Code for: ").append(function.getName(true))
              .append(" @ ").append(function.getEntryPoint()).append("\n\n");

        try (DecompilerSession session = decompilerService.open(program)) {
            DecompileResults results = session.decompiler().decompileFunction(function,
                session.options().getDefaultTimeout(), monitor);

            if (monitor.isCancelled()) {
                return cancelledResult();
            }
            if (!results.decompileCompleted()) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Decompilation failed for function: " + function.getName(true)).build())
                    .isError(true)
                    .build();
            }

            HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Could not get high function for: " + function.getName(true)).build())
                    .isError(true)
                    .build();
            }

            // Get P-Code operations
            if (raw) {
                // Raw P-Code from high function
                result.append("## Raw P-Code Operations:\n```\n");
                Iterator<PcodeOpAST> ops = highFunction.getPcodeOps();
                while (ops.hasNext()) {
                    if (monitor.isCancelled()) {
                        return cancelledResult();
                    }
                    PcodeOpAST op = ops.next();
                    result.append(op.getSeqnum().getTarget()).append(": ")
                          .append(op.toString()).append("\n");
                }
                result.append("```\n");
            } else {
                // P-Code organized by basic blocks
                result.append("## P-Code by Basic Blocks:\n\n");
                var blocks = highFunction.getBasicBlocks();

                for (var block : blocks) {
                    if (monitor.isCancelled()) {
                        return cancelledResult();
                    }
                    if (block instanceof PcodeBlockBasic basicBlock) {
                        result.append("### Block ").append(basicBlock.getIndex())
                              .append(" @ ").append(basicBlock.getStart()).append("\n");
                        result.append("```\n");

                        Iterator<PcodeOp> blockOps = basicBlock.getIterator();
                        while (blockOps.hasNext()) {
                            if (monitor.isCancelled()) {
                                return cancelledResult();
                            }
                            PcodeOp op = blockOps.next();
                            result.append("  ").append(op.toString()).append("\n");
                        }
                        result.append("```\n\n");
                    }
                }
            }

            // Add summary
            result.append("## Summary:\n");
            result.append("- Function: ").append(function.getName(true)).append("\n");
            result.append("- Entry: ").append(function.getEntryPoint()).append("\n");

            var blocks = highFunction.getBasicBlocks();
            result.append("- Basic Blocks: ").append(blocks.size()).append("\n");

        }

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(result.toString()).build())
            .build();
    }

    private static McpSchema.CallToolResult cancelledResult() {
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder("Function code retrieval cancelled").build())
            .isError(true)
            .build();
    }

    /**
     * Find a function by name or address.
     * Supports C++ qualified names (e.g., "Class::method" or "Outer::Inner::method").
     */
    private Function findFunction(Program program, String identifier) {
        // Try to parse as address first
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                // Try to get function at the address
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;

                // If not found at address, try containing function
                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not an address, try as function name
        }

        // Handles C++ qualified names (Class::method) and plain names
        return FunctionLookup.findByQualifiedName(program, identifier);
    }
}
