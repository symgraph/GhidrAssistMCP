package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class ProjectFilesTool implements McpTool {

    @Override
    public String getName() {
        return "project_files";
    }

    @Override
    public String getDescription() {
        return "List or delete files/folders in the active Ghidra project. " +
            "Deletion requires confirm=true and removes Ghidra project database entries, not original imported files.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "delete")
                )),
                Map.entry("path", Map.of(
                    "type", "string",
                    "description", "Project path for action='delete' (e.g. '/banks/bank00.bin' or '/banks')"
                )),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Project folder to list. Default: '/'"
                )),
                Map.entry("target_type", Map.of(
                    "type", "string",
                    "description", "For delete: file, folder, or auto. Default: auto",
                    "enum", List.of("auto", "file", "folder"),
                    "default", "auto"
                )),
                Map.entry("recursive", Map.of(
                    "type", "boolean",
                    "description", "For list/delete folder: include/delete children recursively. Default: false",
                    "default", false
                )),
                Map.entry("confirm", Map.of(
                    "type", "boolean",
                    "description", "Required true for action='delete'"
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, ghidra.program.model.listing.Program currentProgram) {
        return textResult("This tool requires backend context (project access).");
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments,
                                            ghidra.program.model.listing.Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        Project project = getProject();
        if (project == null) {
            return textResult("No Ghidra project is open.");
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isBlank()) {
            return textResult("action is required: list or delete.");
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        return switch (action.trim().toLowerCase()) {
            case "list" -> list(root, arguments);
            case "delete" -> delete(root, arguments, backend);
            default -> textResult("Invalid action: " + action + ". Use list or delete.");
        };
    }

    private Project getProject() {
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool pluginTool = manager.getActiveTool();
        return pluginTool != null ? pluginTool.getProject() : null;
    }

    private McpSchema.CallToolResult list(DomainFolder root, Map<String, Object> arguments) {
        String folderPath = stringArg(arguments.get("folder"), "/");
        boolean recursive = Boolean.TRUE.equals(arguments.get("recursive"));

        DomainFolder folder = resolveFolder(root, folderPath);
        if (folder == null) {
            return textResult("Folder not found: " + folderPath);
        }

        List<String> rows = new ArrayList<>();
        collect(folder, recursive, rows);
        rows.sort(String.CASE_INSENSITIVE_ORDER);

        StringBuilder sb = new StringBuilder();
        sb.append("Project entries under ").append(folder.getPathname()).append("\n\n");
        for (String row : rows) {
            sb.append(row).append("\n");
        }
        sb.append("\nTotal: ").append(rows.size()).append(" entr").append(rows.size() == 1 ? "y" : "ies");
        return textResult(sb.toString());
    }

    private McpSchema.CallToolResult delete(DomainFolder root, Map<String, Object> arguments,
                                            GhidrAssistMCPBackend backend) {
        if (!Boolean.TRUE.equals(arguments.get("confirm"))) {
            return textResult("Refusing to delete. Pass confirm=true to delete a project file or folder.");
        }

        String path = stringArg(arguments.get("path"), null);
        if (path == null || path.isBlank()) {
            return textResult("path is required for action='delete'.");
        }

        String normalizedPath = normalizePath(path);
        if ("/".equals(normalizedPath)) {
            return textResult("Refusing to delete the project root folder.");
        }

        String targetType = stringArg(arguments.get("target_type"), "auto").toLowerCase();
        boolean recursive = Boolean.TRUE.equals(arguments.get("recursive"));

        try {
            if ("file".equals(targetType) || "auto".equals(targetType)) {
                DomainFile file = resolveFile(root, normalizedPath);
                if (file != null) {
                    String deletedPath = file.getPathname();
                    file.delete();
                    if (backend != null) {
                        backend.clearCache();
                    }
                    return textResult("Deleted project file: " + deletedPath);
                }
                if ("file".equals(targetType)) {
                    return textResult("Project file not found: " + normalizedPath);
                }
            }

            if ("folder".equals(targetType) || "auto".equals(targetType)) {
                DomainFolder folder = resolveFolder(root, normalizedPath);
                if (folder == null) {
                    return textResult("Project folder not found: " + normalizedPath);
                }
                int deleted = deleteFolder(folder, recursive);
                if (backend != null) {
                    backend.clearCache();
                }
                return textResult("Deleted project folder: " + normalizedPath +
                    " (" + deleted + " entr" + (deleted == 1 ? "y" : "ies") + ")");
            }

            return textResult("Invalid target_type: " + targetType + ". Use auto, file, or folder.");
        } catch (Exception e) {
            Msg.error(this, "Failed to delete project entry: " + normalizedPath, e);
            return textResult("Failed to delete '" + normalizedPath + "': " +
                e.getClass().getSimpleName() + ": " + e.getMessage() +
                "\nIf the file is open in CodeBrowser, close it and try again.");
        }
    }

    private int deleteFolder(DomainFolder folder, boolean recursive) throws Exception {
        if (!recursive && !folder.isEmpty()) {
            throw new IllegalArgumentException("Folder is not empty. Pass recursive=true to delete children.");
        }

        int deleted = 0;
        if (recursive) {
            for (DomainFile file : folder.getFiles()) {
                file.delete();
                deleted++;
            }

            List<DomainFolder> children = new ArrayList<>(List.of(folder.getFolders()));
            children.sort(Comparator.comparing(DomainFolder::getPathname).reversed());
            for (DomainFolder child : children) {
                deleted += deleteFolder(child, true);
            }
        }

        folder.delete();
        return deleted + 1;
    }

    private void collect(DomainFolder folder, boolean recursive, List<String> rows) {
        for (DomainFolder child : folder.getFolders()) {
            rows.add("[folder] " + child.getPathname());
            if (recursive) {
                collect(child, true, rows);
            }
        }
        for (DomainFile file : folder.getFiles()) {
            rows.add("[file]   " + file.getPathname() + " (" + file.getContentType() + ")");
        }
    }

    private DomainFolder resolveFolder(DomainFolder root, String path) {
        String normalized = normalizePath(path);
        if ("/".equals(normalized)) {
            return root;
        }

        DomainFolder folder = root;
        for (String part : normalized.substring(1).split("/")) {
            if (part.isEmpty()) {
                continue;
            }
            folder = folder.getFolder(part);
            if (folder == null) {
                return null;
            }
        }
        return folder;
    }

    private DomainFile resolveFile(DomainFolder root, String path) {
        String normalized = normalizePath(path);
        int slash = normalized.lastIndexOf('/');
        String folderPath = slash <= 0 ? "/" : normalized.substring(0, slash);
        String fileName = normalized.substring(slash + 1);
        DomainFolder folder = resolveFolder(root, folderPath);
        return folder != null ? folder.getFile(fileName) : null;
    }

    private String normalizePath(String path) {
        String normalized = path != null ? path.trim().replace('\\', '/') : "/";
        if (normalized.isEmpty()) {
            normalized = "/";
        }
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        while (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String stringArg(Object value, String defaultValue) {
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return defaultValue;
    }

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
