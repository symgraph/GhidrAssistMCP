/*
 * MCP tool for listing all open programs in Ghidra.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists all currently open programs in Ghidra.
 * This is essential for multi-program scenarios where the LLM needs to know
 * which programs are available and select the correct one for operations.
 */
public class ListProgramsTool implements McpTool {

    @Override
    public String getName() {
        return "list_binaries";
    }

    @Override
    public String getDescription() {
        return "List all currently open programs/binaries in Ghidra. " +
               "Shows program names, project paths, executable paths, and which one is currently active. " +
               "Use this to discover available targets before running other tools. " +
               "IMPORTANT: When multiple programs are open, use the 'program_name' parameter " +
               "with the listed Project Path to specify which program to operate on. " +
               "Example: {}";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // This tool needs the backend to access all programs
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context. No programs available.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        List<Program> programs = backend.getAllOpenPrograms();
        Program activeProgram = backend.getCurrentProgram();

        if (programs.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No programs currently open in Ghidra.\n\n" +
                    "Please open a binary file in Ghidra before using MCP tools.")
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Open Programs in Ghidra:\n\n");

        for (int i = 0; i < programs.size(); i++) {
            Program p = programs.get(i);
            boolean isActive = (activeProgram != null && p.equals(activeProgram));

            result.append(String.format("%d. %s%s\n",
                i + 1,
                p.getName(),
                isActive ? " [ACTIVE]" : ""));

            // Add program details
            result.append(String.format("   Project Path: %s\n", projectPath(p)));
            result.append(String.format("   Executable Path: %s\n", p.getExecutablePath()));
            result.append(String.format("   Format: %s\n", p.getExecutableFormat()));
            result.append(String.format("   Language: %s\n", p.getLanguageID()));

            if (i < programs.size() - 1) {
                result.append("\n");
            }
        }

        result.append("\n---\n");
        result.append("Total: ").append(programs.size()).append(" program(s) open\n");

        if (programs.size() > 1) {
            result.append("\nNOTE: Multiple programs are open. To target a specific program, ");
            result.append("use the listed Project Path as the 'program_name' parameter in tool calls.\n");
            result.append("Example: {\"program_name\": \"").append(projectPath(programs.get(0))).append("\", ...}");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private String projectPath(Program program) {
        DomainFile domainFile = program.getDomainFile();
        return domainFile != null ? domainFile.getPathname() : program.getName();
    }
}
