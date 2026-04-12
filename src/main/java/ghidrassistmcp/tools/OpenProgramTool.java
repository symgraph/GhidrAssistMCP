/*
 * MCP tool for opening an existing program from the Ghidra project in CodeBrowser.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that opens an existing program from the Ghidra project in CodeBrowser.
 * This makes the program visible to other MCP tools that operate on open programs.
 */
public class OpenProgramTool implements McpTool {

    @Override
    public String getName() {
        return "open_program";
    }

    @Override
    public String getDescription() {
        return "Open a program from the Ghidra project in CodeBrowser, or list all " +
               "programs available in the project. " +
               "Use action 'list' to see all project files, or 'open' to open one by name. " +
               "Example: {\"action\": \"open\", \"name\": \"bank00.bin\"}";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "open")
                ),
                "name", Map.of(
                    "type", "string",
                    "description", "Program name to open (required for action 'open'). Supports partial matching."
                ),
                "folder", Map.of(
                    "type", "string",
                    "description", "Project folder to search in (e.g. '/' or '/banks'). Default: search all folders."
                )
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return textResult("This tool requires backend context (project access).");
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool pluginTool = manager.getActiveTool();
        if (pluginTool == null) {
            return textResult("No active Ghidra tool/window available.");
        }

        Project project = pluginTool.getProject();
        if (project == null) {
            return textResult("No Ghidra project is open.");
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return textResult("action parameter is required: 'list' or 'open'");
        }

        DomainFolder rootFolder = project.getProjectData().getRootFolder();

        switch (action.toLowerCase()) {
            case "list":
                return listPrograms(rootFolder, (String) arguments.get("folder"));
            case "open":
                return openProgram(rootFolder, arguments, pluginTool, backend);
            default:
                return textResult("Invalid action: " + action + ". Use 'list' or 'open'.");
        }
    }

    private McpSchema.CallToolResult listPrograms(DomainFolder rootFolder, String folderPath) {
        List<DomainFile> files = new ArrayList<>();

        if (folderPath != null && !folderPath.isBlank() && !"/".equals(folderPath)) {
            DomainFolder folder = rootFolder.getFolder(folderPath.replaceFirst("^/", ""));
            if (folder == null) {
                return textResult("Folder not found: " + folderPath);
            }
            collectFiles(folder, files);
        } else {
            collectFiles(rootFolder, files);
        }

        if (files.isEmpty()) {
            return textResult("No programs found in the project.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Programs in project:\n\n");
        for (DomainFile df : files) {
            sb.append("  ").append(df.getPathname());
            sb.append("  (").append(df.getContentType()).append(")\n");
        }
        sb.append("\nTotal: ").append(files.size()).append(" file(s)\n");
        sb.append("\nUse {\"action\": \"open\", \"name\": \"<name>\"} to open one in CodeBrowser.");

        return McpSchema.CallToolResult.builder()
            .addTextContent(sb.toString())
            .build();
    }

    private McpSchema.CallToolResult openProgram(DomainFolder rootFolder,
                                                  Map<String, Object> arguments,
                                                  PluginTool pluginTool,
                                                  GhidrAssistMCPBackend backend) {
        String name = (String) arguments.get("name");
        if (name == null || name.isBlank()) {
            return textResult("'name' is required for action 'open'.");
        }

        // Check if already open
        List<Program> openPrograms = backend.getAllOpenPrograms();
        for (Program p : openPrograms) {
            if (p.getName().equalsIgnoreCase(name)) {
                return textResult("Program '" + p.getName() + "' is already open in CodeBrowser.");
            }
        }

        // Find the file in the project
        List<DomainFile> allFiles = new ArrayList<>();
        collectFiles(rootFolder, allFiles);

        DomainFile match = findFile(allFiles, name);

        if (match == null) {
            return textResult("Program not found: '" + name +
                "'. Use action 'list' to see available programs.");
        }

        // Open it in CodeBrowser
        ProgramManager pm = pluginTool.getService(ProgramManager.class);
        if (pm == null) {
            return textResult("ProgramManager service not available. Is CodeBrowser open?");
        }

        try {
            Program program = (Program) match.getDomainObject(
                this, false, false, TaskMonitor.DUMMY);
            pm.openProgram(program);
            program.release(this);

            return textResult("Opened '" + match.getName() + "' (" + match.getPathname() +
                ") in CodeBrowser.\nLanguage: " + program.getLanguageID() +
                "\nImage Base: " + program.getImageBase());
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + match.getName(), e);
            return textResult("Failed to open '" + match.getName() + "': " + e.getMessage());
        }
    }

    /**
     * Find a file by name with exact, case-insensitive, then partial matching.
     */
    private DomainFile findFile(List<DomainFile> files, String name) {
        // Exact match
        for (DomainFile df : files) {
            if (df.getName().equals(name)) {
                return df;
            }
        }
        // Case-insensitive match
        for (DomainFile df : files) {
            if (df.getName().equalsIgnoreCase(name)) {
                return df;
            }
        }
        // Partial match (contains)
        String lowerName = name.toLowerCase();
        for (DomainFile df : files) {
            if (df.getName().toLowerCase().contains(lowerName)) {
                return df;
            }
        }
        return null;
    }

    private void collectFiles(DomainFolder folder, List<DomainFile> result) {
        for (DomainFile df : folder.getFiles()) {
            result.add(df);
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, result);
        }
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
