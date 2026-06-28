package ghidrassistmcp.tools;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

public class GhidraScriptsTool implements McpTool {

    @Override
    public String getName() {
        return "scripts";
    }

    @Override
    public String getDescription() {
        return "List, read, create, delete, and run Ghidra scripts. " +
            "Create/delete are restricted to the user script directory; run uses Ghidra's script providers.";
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
    public boolean isOpenWorld() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "get", "create", "delete", "run")
                )),
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "Script file name or relative path, e.g. 'MyScript.java'"
                )),
                Map.entry("source", Map.of(
                    "type", "string",
                    "description", "For action='create': script source text. If omitted, provider template is used."
                )),
                Map.entry("overwrite", Map.of(
                    "type", "boolean",
                    "description", "For action='create': overwrite an existing user script. Default: false",
                    "default", false
                )),
                Map.entry("confirm", Map.of(
                    "type", "boolean",
                    "description", "Required true for action='delete'"
                )),
                Map.entry("filter", Map.of(
                    "type", "string",
                    "description", "For action='list': case-insensitive substring filter"
                )),
                Map.entry("user_only", Map.of(
                    "type", "boolean",
                    "description", "For action='list': only list scripts in the user script directory. Default: false",
                    "default", false
                )),
                Map.entry("offset", Map.of(
                    "type", "integer",
                    "description", "For action='list': number of matching scripts to skip. Default: 0",
                    "default", 0,
                    "minimum", 0
                )),
                Map.entry("limit", Map.of(
                    "type", "integer",
                    "description", "For action='list': maximum scripts to return. Default: 200",
                    "default", 200,
                    "minimum", 1
                )),
                Map.entry("max_bytes", Map.of(
                    "type", "integer",
                    "description", "For action='get': maximum source bytes to return. Default: 65536",
                    "default", 65536,
                    "minimum", 1
                )),
                Map.entry("args", Map.of(
                    "type", "array",
                    "description", "For action='run': script arguments",
                    "items", Map.of("type", "string")
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        String action = stringArg(arguments.get("action"), null);
        if (action == null) {
            return textResult("action is required: list, get, create, delete, or run.");
        }

        try {
            return switch (action.trim().toLowerCase()) {
                case "list" -> listScripts(arguments);
                case "get" -> getScript(arguments);
                case "create" -> createScript(arguments);
                case "delete" -> deleteScript(arguments);
                case "run" -> submitRun(arguments, currentProgram, backend);
                default -> textResult("Invalid action: " + action + ". Use list, get, create, delete, or run.");
            };
        } catch (Exception e) {
            Msg.error(this, "scripts tool failed", e);
            return textResult("scripts " + action + " failed: " +
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult listScripts(Map<String, Object> arguments) {
        String filter = stringArg(arguments.get("filter"), null);
        String normalizedFilter = filter != null ? filter.toLowerCase() : null;
        boolean userOnly = Boolean.TRUE.equals(arguments.get("user_only"));
        int offset = numberArg(arguments.get("offset"), 0);
        int limit = numberArg(arguments.get("limit"), 200);

        ResourceFile userDir = getUserScriptDirectory();
        List<ResourceFile> roots = userOnly ? List.of(userDir) :
            GhidraScriptUtil.getEnabledScriptSourceDirectories();

        List<ScriptRow> rows = new ArrayList<>();
        for (ResourceFile root : roots) {
            collectScripts(root, userDir, normalizedFilter, rows);
        }
        rows.sort(Comparator.comparing(row -> row.name, String.CASE_INSENSITIVE_ORDER));

        int end = Math.min(rows.size(), offset + limit);
        StringBuilder sb = new StringBuilder();
        sb.append("Ghidra Scripts\n\n");
        for (int i = offset; i < end; i++) {
            ScriptRow row = rows.get(i);
            sb.append("- ").append(row.name).append("\n");
            sb.append("  Runtime: ").append(row.runtime).append("\n");
            sb.append("  Scope: ").append(row.userScript ? "user" : "system").append("\n");
            sb.append("  Path: ").append(row.path).append("\n");
            if (!row.category.isBlank()) {
                sb.append("  Category: ").append(row.category).append("\n");
            }
            if (!row.description.isBlank()) {
                sb.append("  Description: ").append(row.description).append("\n");
            }
        }
        sb.append("\nShowing ").append(Math.max(0, end - offset))
          .append(" of ").append(rows.size()).append(" matching script(s)");
        if (offset > 0) {
            sb.append(" (offset ").append(offset).append(")");
        }
        sb.append("\nUser script directory: ").append(userDir.getAbsolutePath());
        return textResult(sb.toString());
    }

    private McpSchema.CallToolResult getScript(Map<String, Object> arguments) throws IOException {
        String name = requiredName(arguments);
        ResourceFile script = resolveExistingScript(name, true);
        int maxBytes = numberArg(arguments.get("max_bytes"), 65536);
        if (maxBytes < 1) {
            maxBytes = 65536;
        }

        byte[] bytes;
        boolean truncated;
        try (InputStream input = script.getInputStream()) {
            bytes = readUpTo(input, maxBytes + 1);
            truncated = bytes.length > maxBytes;
        }
        if (truncated) {
            byte[] trimmed = new byte[maxBytes];
            System.arraycopy(bytes, 0, trimmed, 0, maxBytes);
            bytes = trimmed;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Script: ").append(script.getName()).append("\n");
        sb.append("Path: ").append(script.getAbsolutePath()).append("\n");
        sb.append("Provider: ").append(providerName(script)).append("\n");
        sb.append("Truncated: ").append(truncated).append("\n\n");
        sb.append(new String(bytes, StandardCharsets.UTF_8));
        return textResult(sb.toString());
    }

    private McpSchema.CallToolResult createScript(Map<String, Object> arguments) throws IOException {
        String name = requiredName(arguments);
        ResourceFile script = resolveUserScriptPath(name, true);
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
        if (provider == null) {
            return textResult("No Ghidra script provider for: " + script.getName());
        }

        File file = script.getFile(false);
        if (file.exists() && !Boolean.TRUE.equals(arguments.get("overwrite"))) {
            return textResult("User script already exists: " + file.getAbsolutePath() +
                "\nPass overwrite=true to replace it.");
        }

        Files.createDirectories(file.toPath().getParent());
        String source = stringArg(arguments.get("source"), null);
        if (source != null) {
            Files.writeString(file.toPath(), source, StandardCharsets.UTF_8);
        } else {
            provider.createNewScript(script, "");
        }

        return textResult("Created user script: " + file.getAbsolutePath() +
            "\nProvider: " + provider.getDescription());
    }

    private McpSchema.CallToolResult deleteScript(Map<String, Object> arguments) throws IOException {
        if (!Boolean.TRUE.equals(arguments.get("confirm"))) {
            return textResult("Refusing to delete. Pass confirm=true to delete a user script.");
        }

        String name = requiredName(arguments);
        ResourceFile script = resolveUserScriptPath(name, false);
        if (!script.exists() || !script.isFile()) {
            return textResult("User script not found: " + script.getAbsolutePath());
        }

        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
        boolean deleted = provider != null ? provider.deleteScript(script) : script.delete();
        if (!deleted && script.exists()) {
            return textResult("Failed to delete user script: " + script.getAbsolutePath());
        }
        return textResult("Deleted user script: " + script.getAbsolutePath());
    }

    private McpSchema.CallToolResult submitRun(Map<String, Object> arguments, Program currentProgram,
                                               GhidrAssistMCPBackend backend) {
        if (backend != null && backend.getTaskManager() != null) {
            McpTask task = backend.getTaskManager().submitTask(
                getName(), arguments, () -> runScript(arguments, currentProgram, backend));
            return textResult("Script task submitted: " + task.getTaskId() +
                "\nUse get_task_status with this task_id to retrieve the result.");
        }
        return runScript(arguments, currentProgram, backend);
    }

    private McpSchema.CallToolResult runScript(Map<String, Object> arguments, Program currentProgram,
                                               GhidrAssistMCPBackend backend) {
        StringWriter output = new StringWriter();
        PrintWriter writer = new PrintWriter(output, true);

        try {
            String name = requiredName(arguments);
            ResourceFile scriptFile = resolveExistingScript(name, true);
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
            if (provider == null) {
                return textResult("No Ghidra script provider for: " + scriptFile.getName());
            }

            GhidraScript script = provider.getScriptInstance(scriptFile, writer);
            script.setSourceFile(scriptFile);
            List<String> args = AnalysisUtils.stringList(arguments.get("args"));
            if (args != null) {
                script.setScriptArgs(args.toArray(String[]::new));
            }

            GhidraState state = buildState(currentProgram, backend);
            script.execute(state, TaskMonitor.DUMMY, writer);

            if (backend != null) {
                backend.clearCache();
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Script completed: ").append(scriptFile.getName()).append("\n");
            sb.append("Provider: ").append(provider.getDescription()).append("\n\n");
            sb.append(output);
            return textResult(sb.toString().trim());
        } catch (Exception e) {
            Msg.error(this, "Failed to run script", e);
            return textResult("Script failed: " + e.getClass().getSimpleName() + ": " +
                e.getMessage() + "\n\nOutput before failure:\n" + output);
        }
    }

    private GhidraState buildState(Program currentProgram, GhidrAssistMCPBackend backend) {
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool tool = manager.getActiveTool();
        Project project = tool != null ? tool.getProject() : null;
        Address currentAddress = null;
        if (backend != null && backend.getActivePlugin() != null) {
            currentAddress = backend.getActivePlugin().getCurrentAddress();
        }
        ProgramLocation location =
            currentProgram != null && currentAddress != null ? new ProgramLocation(currentProgram, currentAddress) : null;
        return new GhidraState(tool, project, currentProgram, location, null, null);
    }

    private void collectScripts(ResourceFile root, ResourceFile userDir, String filter, List<ScriptRow> rows) {
        ResourceFile[] children = root.listFiles();
        if (children == null) {
            return;
        }
        for (ResourceFile child : children) {
            if (child.isDirectory()) {
                collectScripts(child, userDir, filter, rows);
                continue;
            }
            if (!GhidraScriptUtil.hasScriptProvider(child)) {
                continue;
            }
            if (filter != null && !child.getName().toLowerCase().contains(filter)) {
                continue;
            }
            ScriptInfo info = GhidraScriptUtil.newScriptInfo(child);
            rows.add(new ScriptRow(
                info.getName(),
                info.getRuntimeEnvironmentName(),
                String.join("/", info.getCategory()),
                nullToEmpty(info.getDescription()),
                child.getAbsolutePath(),
                userDir.containsPath(child)));
        }
    }

    private ResourceFile resolveExistingScript(String name, boolean allowSystem) throws IOException {
        ResourceFile userScript = resolveUserScriptPath(name, false);
        if (userScript.exists() && userScript.isFile()) {
            return userScript;
        }
        if (allowSystem) {
            ResourceFile found = GhidraScriptUtil.findScriptByName(name);
            if (found != null) {
                return found;
            }
        }
        throw new IOException("Script not found: " + name);
    }

    private ResourceFile resolveUserScriptPath(String name, boolean defaultJavaExtension) throws IOException {
        String normalizedName = name.trim().replace('\\', '/');
        if (normalizedName.isBlank() || normalizedName.startsWith("/") || normalizedName.contains(":")) {
            throw new IOException("Script name must be a relative path inside the user script directory.");
        }
        if (defaultJavaExtension && !normalizedName.contains(".")) {
            normalizedName += ".java";
        }

        ResourceFile userDir = getUserScriptDirectory();
        Path root = userDir.getFile(false).toPath().toAbsolutePath().normalize();
        Path target = root.resolve(normalizedName).normalize();
        if (!target.startsWith(root)) {
            throw new IOException("Script path escapes the user script directory: " + name);
        }
        return new ResourceFile(target.toFile());
    }

    private ResourceFile getUserScriptDirectory() {
        ResourceFile userDir = GhidraScriptUtil.getUserScriptDirectory();
        if (!userDir.exists()) {
            userDir.mkdir();
        }
        return userDir;
    }

    private String providerName(ResourceFile script) {
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
        return provider != null ? provider.getDescription() : "unknown";
    }

    private byte[] readUpTo(InputStream input, int maxBytes) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int remaining = maxBytes;
        while (remaining > 0) {
            int read = input.read(buffer, 0, Math.min(buffer.length, remaining));
            if (read < 0) {
                break;
            }
            output.write(buffer, 0, read);
            remaining -= read;
        }
        return output.toByteArray();
    }

    private String requiredName(Map<String, Object> arguments) {
        String name = stringArg(arguments.get("name"), null);
        if (name == null) {
            throw new IllegalArgumentException("name is required.");
        }
        return name;
    }

    private String stringArg(Object value, String defaultValue) {
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return defaultValue;
    }

    private int numberArg(Object value, int defaultValue) {
        if (value instanceof Number number) {
            return Math.max(0, number.intValue());
        }
        return defaultValue;
    }

    private String nullToEmpty(String value) {
        return value != null ? value : "";
    }

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }

    private record ScriptRow(String name, String runtime, String category, String description,
                             String path, boolean userScript) {
    }
}
