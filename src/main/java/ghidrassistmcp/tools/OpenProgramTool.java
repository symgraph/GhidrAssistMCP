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
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

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
        return "Open a program from the Ghidra project in CodeBrowser by unique name or full path. " +
               "Use list_project_files to find available programs. " +
               "Example: {\"name\": \"/banks/bank00.bin\"}";
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
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "open")
                )),
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "Exact project path or unique filename to open; duplicate filenames require a full path."
                )),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Project folder to search in (e.g. '/' or '/banks'). Default: search all folders."
                )),
                Map.entry("suppress_analysis_prompt", Map.of(
                    "type", "boolean",
                    "description", "Set 'Should Ask To Analyze' to false before opening. Default: true.",
                    "default", true
                )),
                Map.entry("analyze_after_open", Map.of(
                    "type", "boolean",
                    "description", "Submit an analyze_program task after opening. Default: false.",
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
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.findInstance();
        if (manager == null) {
            return errorResult("Opening project programs requires the Ghidra GUI application.");
        }
        Project project = manager.getProject();
        if (project == null || project.isClosed()) {
            return errorResult("No Ghidra project is open. Open a project in the project manager first.");
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
                return openProgram(rootFolder, arguments, manager, project, backend);
            default:
                return textResult("Invalid action: " + action + ". Use 'list' or 'open'.");
        }
    }

    private McpSchema.CallToolResult listPrograms(DomainFolder rootFolder, String folderPath) {
        List<DomainFile> files = new ArrayList<>();

        if (folderPath != null && !folderPath.isBlank() && !"/".equals(folderPath)) {
            DomainFolder folder = resolveFolder(rootFolder, folderPath);
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
        sb.append("\nUse open_program with {\"name\": \"<pathname>\"} to open one in CodeBrowser.");

        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(sb.toString()).build())
            .build();
    }

    private McpSchema.CallToolResult openProgram(DomainFolder rootFolder,
                                                  Map<String, Object> arguments,
                                                  GhidrAssistMCPManager manager,
                                                  Project project,
                                                  GhidrAssistMCPBackend backend) {
        String name = (String) arguments.get("name");
        if (name == null || name.isBlank()) {
            return errorResult("'name' is required for open_program.");
        }


        // Find the file in the project
        List<DomainFile> allFiles = new ArrayList<>();
        String folderPath = (String) arguments.get("folder");
        DomainFolder searchRoot = resolveFolder(rootFolder, folderPath);
        if (searchRoot == null) {
            return errorResult("Project folder not found: " + folderPath);
        }
        collectFiles(searchRoot, allFiles);

        DomainFile match;
        try {
            match = findFile(allFiles, name);
        } catch (IllegalArgumentException e) {
            return errorResult(e.getMessage());
        }

        if (match == null) {
            return errorResult("Program not found: '" + name +
                "'. Use list_project_files with recursive=true, then open_program with a full project path.");
        }

        // Resolve globally and reject duplicate filenames rather than selecting one browser.
        Program alreadyOpen;
        try {
            alreadyOpen = manager.getProgramByName(match.getPathname());
        } catch (IllegalArgumentException e) {
            return errorResult(e.getMessage());
        }
        if (alreadyOpen != null) {
            PluginTool owner = manager.getToolForProgram(alreadyOpen);
            if (owner != null) {
                SystemUtilities.runSwingNow(() -> {
                    owner.getService(ProgramManager.class).setCurrentProgram(alreadyOpen);
                    owner.getToolFrame().toFront();
                });
            }
            return textResult("Program '" + alreadyOpen.getName() + "' is already open in CodeBrowser.\n" +
                maybeSubmitAnalysis(alreadyOpen, arguments, backend));
        }


        Program program = null;
        try {
            program = (Program) match.getDomainObject(
                this, false, false, TaskMonitor.DUMMY);

            if (getBoolean(arguments, "suppress_analysis_prompt", true)) {
                AnalysisUtils.setAskToAnalyze(program, false);
            }

            manager.openProgramInCodeBrowser(project, program);

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
            return errorResult("Failed to open '" + match.getName() + "': " + e.getMessage());
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
        McpTask task = backend.submitTask(
            analyzeTool.getName(), taskArgs, program,
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
     * Find a file by full project path or name, with exact, case-insensitive,
     * then partial matching. Full pathname (e.g. "/banks/bank00.bin") is tried
     * before plain name so that callers can paste directly from the 'list' output.
     */
    static DomainFile findFile(List<DomainFile> files, String name) {
        for (int stage = 0; stage < 5; stage++) {
            List<DomainFile> matches = new ArrayList<>();
            for (DomainFile file : files) {
                boolean matched = switch (stage) {
                    case 0 -> file.getPathname().equals(name);
                    case 1 -> file.getName().equals(name);
                    case 2 -> file.getPathname().equalsIgnoreCase(name);
                    case 3 -> file.getName().equalsIgnoreCase(name);
                    default -> file.getName().toLowerCase(java.util.Locale.ROOT)
                        .contains(name.toLowerCase(java.util.Locale.ROOT));
                };
                if (matched) {
                    matches.add(file);
                }
            }
            if (!matches.isEmpty()) {
                if (matches.size() != 1) {
                    throw new IllegalArgumentException("Ambiguous program: '" + name +
                        "'. Use a full project path from list_project_files.");
                }
                return matches.get(0);
            }
        }
        return null;
    }

    private static DomainFolder resolveFolder(DomainFolder root, String path) {
        if (path == null || path.isBlank() || "/".equals(path)) {
            return root;
        }
        DomainFolder current = root;
        for (String component : path.split("/")) {
            if (component.isEmpty()) {
                continue;
            }
            current = current.getFolder(component);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private void collectFiles(DomainFolder folder, List<DomainFile> result) {
        for (DomainFile df : folder.getFiles()) {
            if (Program.class.isAssignableFrom(df.getDomainObjectClass())) {
                result.add(df);
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, result);
        }
    }

    private static McpSchema.CallToolResult errorResult(String message) {
        return McpSchema.CallToolResult.builder().isError(true).addContent(McpSchema.TextContent.builder(message).build()).build();
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(message).build())
            .build();
    }
}
