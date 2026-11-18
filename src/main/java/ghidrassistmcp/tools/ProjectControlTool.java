package ghidrassistmcp.tools;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.project.GhidraProjectController;
import ghidrassistmcp.project.ProjectController;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/** Explicit project lifecycle contracts over the application-owned project controller. */
public final class ProjectControlTool implements McpTool {
    public enum Operation { CREATE, OPEN, SAVE, CLOSE }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final Operation operation;
    private final Supplier<ProjectController> controllers;

    public ProjectControlTool(Operation operation) {
        this(operation, () -> new GhidraProjectController(() -> {
            GhidrAssistMCPManager manager = GhidrAssistMCPManager.findInstance();
            return manager == null ? null : manager.getFrontEndTool();
        }));
    }

    public ProjectControlTool(Operation operation, Supplier<ProjectController> controllers) {
        this.operation = Objects.requireNonNull(operation);
        this.controllers = Objects.requireNonNull(controllers);
    }

    @Override public String getName() {
        return switch (operation) {
            case CREATE -> "create_project";
            case OPEN -> "open_project";
            case SAVE -> "save_project";
            case CLOSE -> "close_project";
        };
    }
    @Override public boolean supportsProgramSelection() { return false; }
    @Override public boolean requiresProgramContext() { return false; }
    @Override public boolean isProjectLifecycleOperation() { return true; }
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isDestructive() { return operation == Operation.CLOSE; }
    @Override public boolean isIdempotent() { return operation != Operation.CREATE; }
    @Override public boolean isOpenWorld() { return operation == Operation.CREATE || operation == Operation.OPEN; }

    @Override public String getDescription() {
        return switch (operation) {
            case CREATE -> "Create and activate a local Ghidra project in an existing absolute parent directory. name is a project stem without .gpr/.rep. Existing projects are never overwritten; close the active project first.";
            case OPEN -> "Open a local Ghidra project by its absolute .gpr marker path. restore_state defaults to false. Opening the same active project succeeds without reopening it; a different active project must be closed first.";
            case SAVE -> "Save changed open project files and the active project's session state. Reports saved_files. Fails while tools are running commands or files are busy, read-only, or cannot be saved; requires Ghidra's project manager, but no CodeBrowser.";
            case CLOSE -> "Close the active Ghidra project and its tools while keeping MCP reachable in the project manager. Unsaved changes require save=true or discard_changes=true; both default to false and are mutually exclusive. Unsaved tool configuration or plugin data may need saving in Ghidra first. Running commands or busy files prevent closure even with discard. Closing with no active project succeeds.";
        };
    }

    @Override public JsonSchema getInputSchema() {
        Map<String, Object> properties = switch (operation) {
            case CREATE -> Map.of(
                "location", Map.of("type", "string", "minLength", 1,
                    "description", "Absolute path to an existing parent directory for the new project"),
                "name", Map.of("type", "string", "minLength", 1,
                    "description", "Simple project stem, without path separators or .gpr/.rep suffixes"));
            case OPEN -> Map.of(
                "path", Map.of("type", "string", "minLength", 1,
                    "description", "Absolute path to an existing .gpr project marker file"),
                "restore_state", Map.of("type", "boolean", "default", false,
                    "description", "Restore saved session tools and views when opening the project"));
            case SAVE -> Map.of();
            case CLOSE -> Map.of(
                "save", Map.of("type", "boolean", "default", false,
                    "description", "Save changed project files and session state before closing"),
                "discard_changes", Map.of("type", "boolean", "default", false,
                    "description", "Explicitly discard unsaved changes when closing; cannot be combined with save"));
        };
        List<String> required = switch (operation) {
            case CREATE -> List.of("location", "name");
            case OPEN -> List.of("path");
            case SAVE, CLOSE -> List.of();
        };
        return new JsonSchema("object", properties, required, false, null, null);
    }

    @Override public Map<String, Object> getOutputSchema() {
        return Map.of("type", "object", "properties", Map.of(
                "status", Map.of("type", "string"),
                "name", Map.of("type", "string"),
                "location", Map.of("type", "string"),
                "project_path", Map.of("type", "string"),
                "saved_files", Map.of("type", "integer", "minimum", 0),
                "discarded_changes", Map.of("type", "boolean")),
            "required", List.of("status"), "additionalProperties", false);
    }

    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        try {
            if (arguments == null) throw new IllegalArgumentException("Arguments must be an object");
            Set<String> allowed = getInputSchema().properties().keySet();
            for (String key : arguments.keySet()) {
                if (!allowed.contains(key)) throw new IllegalArgumentException("Unknown parameter: " + key);
            }
            // Validate before resolving the application controller, including in direct Java calls.
            String location = null, name = null;
            boolean restoreState = false, save = false, discardChanges = false;
            switch (operation) {
                case CREATE -> {
                    Path directory = absolutePath(requiredString(arguments, "location"), "location");
                    if (!Files.isDirectory(directory)) throw new IllegalArgumentException("location must be an existing directory");
                    location = directory.toString();
                    name = projectStem(requiredString(arguments, "name"));
                    // Reuse Ghidra's platform-specific project/path character validation.
                    new ProjectLocator(location, name);
                }
                case OPEN -> {
                    Path marker = absolutePath(requiredString(arguments, "path"), "path");
                    String filename = marker.getFileName() == null ? "" : marker.getFileName().toString();
                    if (!filename.endsWith(".gpr")) throw new IllegalArgumentException("path must identify a .gpr project marker file");
                    if (!Files.isRegularFile(marker)) throw new IllegalArgumentException("Project marker file does not exist: " + marker);
                    name = filename.substring(0, filename.length() - 4);
                    if (name.isBlank()) throw new IllegalArgumentException("path must identify a named .gpr project marker file");
                    location = marker.getParent().toString();
                    new ProjectLocator(location, name);
                    restoreState = booleanArgument(arguments, "restore_state");
                }
                case SAVE -> { }
                case CLOSE -> {
                    save = booleanArgument(arguments, "save");
                    discardChanges = booleanArgument(arguments, "discard_changes");
                    if (save && discardChanges) throw new IllegalArgumentException("save and discard_changes are mutually exclusive");
                }
            }
            ProjectController controller = Objects.requireNonNull(controllers.get(), "Project controller is unavailable");
            Map<String, Object> result = switch (operation) {
                case CREATE -> controller.createProject(location, name);
                case OPEN -> controller.openProject(location, name, restoreState);
                case SAVE -> controller.saveProject();
                case CLOSE -> controller.closeProject(save, discardChanges);
            };
            if (result == null || !(result.get("status") instanceof String)) {
                throw new IllegalStateException("Project controller returned no operation status");
            }
            return McpSchema.CallToolResult.builder().structuredContent(result)
                .addContent(McpSchema.TextContent.builder(JSON.writeValueAsString(result)).build()).build();
        } catch (Exception e) {
            String detail = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            return McpSchema.CallToolResult.builder().isError(true)
                .addContent(McpSchema.TextContent.builder("Error in " + getName() + ": " + detail).build()).build();
        }
    }

    private static String requiredString(Map<String, Object> arguments, String key) {
        if (!(arguments.get(key) instanceof String value) || value.isBlank()) {
            throw new IllegalArgumentException("Missing or invalid required parameter: " + key);
        }
        return value;
    }

    private static Path absolutePath(String value, String key) {
        Path path = Path.of(value);
        if (!path.isAbsolute()) throw new IllegalArgumentException(key + " must be an absolute path");
        return path.normalize();
    }

    private static String projectStem(String value) {
        if (value.isBlank() || !value.equals(value.trim()) || value.equals(".") || value.equals("..") ||
            value.contains("/") || value.contains("\\") || value.endsWith(".gpr") || value.endsWith(".rep") ||
            value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("name must be a simple project stem without path separators or .gpr/.rep suffixes");
        }
        return value;
    }

    private static boolean booleanArgument(Map<String, Object> arguments, String key) {
        if (!arguments.containsKey(key)) return false;
        if (!(arguments.get(key) instanceof Boolean value)) throw new IllegalArgumentException(key + " must be a boolean");
        return value;
    }
}
