/*
 * MCP tool for opening an existing program from the Ghidra project in CodeBrowser.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
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
import ghidrassistmcp.tasks.McpTask;
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
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "open")
                )),
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "Program name to open (required for action 'open'). Supports partial matching."
                )),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Project folder to search in (e.g. '/' or '/banks'). Default: search all folders."
                )),
                Map.entry("suppress_analysis_prompt", Map.of(
                    "type", "boolean",
                    "description", "For action 'open': set 'Should Ask To Analyze' to false before opening. Default: true.",
                    "default", true
                )),
                Map.entry("analyze_after_open", Map.of(
                    "type", "boolean",
                    "description", "For action 'open': submit an analyze_program task after opening. Default: false.",
                    "default", false
                )),
                Map.entry("analysis_mode", Map.of(
                    "type", "string",
                    "description", "For analyze_after_open: analysis mode",
                    "enum", List.of("full", "changes"),
                    "default", "full"
                )),
                Map.entry("analysis_options", Map.of(
                    "type", "object",
                    "description", "For analyze_after_open: optional analysis option overrides"
                ))
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
                StringBuilder sb = new StringBuilder();
                sb.append("Program '").append(p.getName()).append("' is already open in CodeBrowser.\n");
                sb.append(maybeSubmitAnalysis(p, arguments, backend));
                return textResult(sb.toString().trim());
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

        Program program = null;
        try {
            program = (Program) match.getDomainObject(
                this, false, false, TaskMonitor.DUMMY);

            if (getBoolean(arguments, "suppress_analysis_prompt", true)) {
                AnalysisUtils.setAskToAnalyze(program, false);
            }

            pm.openProgram(program);

            StringBuilder sb = new StringBuilder();
            sb.append("Opened '").append(match.getName()).append("' (").append(match.getPathname())
              .append(") in CodeBrowser.\n");
            sb.append("Language: ").append(program.getLanguageID()).append("\n");
            sb.append("Image Base: ").append(program.getImageBase()).append("\n");
            sb.append("Should Ask To Analyze: ").append(AnalysisUtils.shouldAskToAnalyze(program)).append("\n");
            sb.append(maybeSubmitAnalysis(program, arguments, backend));
            return textResult(sb.toString().trim());
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + match.getName(), e);
            return textResult("Failed to open '" + match.getName() + "': " + e.getMessage());
        } finally {
            if (program != null) {
                program.release(this);
            }
        }
    }

    private String maybeSubmitAnalysis(Program program, Map<String, Object> arguments,
                                       GhidrAssistMCPBackend backend) {
        if (!getBoolean(arguments, "analyze_after_open", false)) {
            return "";
        }
        if (backend == null || backend.getTaskManager() == null) {
            return "Analysis not submitted: task manager unavailable.\n";
        }

        Map<String, Object> taskArgs = new HashMap<>();
        taskArgs.put("scope", "current");
        Object mode = arguments.get("analysis_mode");
        if (mode != null) {
            taskArgs.put("mode", mode);
        }
        Object options = arguments.get("analysis_options");
        if (options != null) {
            taskArgs.put("options", options);
        }

        AnalyzeProgramTool analyzeTool = new AnalyzeProgramTool();
        McpTask task = backend.getTaskManager().submitTask(
            analyzeTool.getName(), taskArgs,
            taskContext -> analyzeTool.execute(taskArgs, program, backend, taskContext));

        return "Analysis task submitted: " + task.getTaskId() +
            "\nUse get_task_status with this task_id to retrieve the result.\n";
    }

    private boolean getBoolean(Map<String, Object> arguments, String name, boolean defaultValue) {
        Object value = arguments.get(name);
        if (value instanceof Boolean bool) {
            return bool;
        }
        return defaultValue;
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
