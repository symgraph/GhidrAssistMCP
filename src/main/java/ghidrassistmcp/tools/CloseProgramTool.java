package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

public class CloseProgramTool implements McpTool {

    @Override
    public String getName() {
        return "close_program";
    }

    @Override
    public String getDescription() {
        return "Close an open program in CodeBrowser. If name is omitted, closes the current program. " +
            "Changed programs require save=true or ignore_changes=true.";
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
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "Open program name or project path to close. If omitted, closes the current program."
                )),
                Map.entry("save", Map.of(
                    "type", "boolean",
                    "description", "Save the program before closing if it has changes. Default: false.",
                    "default", false
                )),
                Map.entry("ignore_changes", Map.of(
                    "type", "boolean",
                    "description", "Close without saving even if the program has changes. Default: false.",
                    "default", false
                ))
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.findInstance();
        if (manager == null) {
            return errorResult("Closing GUI programs requires the Ghidra application.");
        }
        return SystemUtilities.runSwingNow(() -> closeProgram(arguments, currentProgram, backend, manager));
    }

    private McpSchema.CallToolResult closeProgram(Map<String, Object> arguments,
                                                 Program currentProgram,
                                                 GhidrAssistMCPBackend backend,
                                                 GhidrAssistMCPManager manager) {
        String name = stringArg(arguments.get("name"), null);
        boolean save = Boolean.TRUE.equals(arguments.get("save"));
        boolean ignoreChanges = Boolean.TRUE.equals(arguments.get("ignore_changes"));
        Program target;
        try {
            target = name == null ? currentProgram : manager.getProgramByName(name);
        } catch (IllegalArgumentException e) {
            return errorResult(e.getMessage());
        }
        if (target == null) {
            return errorResult(name == null ? "No current program is open." :
                "Open program not found: " + name);
        }
        PluginTool owner = manager.getToolForProgram(target);
        ProgramManager programManager = owner == null ? null : owner.getService(ProgramManager.class);
        if (programManager == null) {
            return errorResult("No CodeBrowser owns the requested program.");
        }

        String label = describeProgram(target);
        boolean changedBefore = target.isChanged();
        if (changedBefore && save) {
            try {
                programManager.saveProgram(target);
            } catch (Exception e) {
                Msg.error(this, "Failed to save program before close: " + label, e);
                return errorResult("Failed to save before closing " + label + ": " +
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        boolean changedAfterSave = target.isChanged();
        if (changedAfterSave && !ignoreChanges) {
            return errorResult("Refusing to close changed program without saving: " + label +
                "\nPass save=true to save first, or ignore_changes=true to close without saving.");
        }

        boolean closed;
        try {
            closed = programManager.closeProgram(target, ignoreChanges);
        } catch (Exception e) {
            Msg.error(this, "Failed to close program: " + label, e);
            return errorResult("Failed to close " + label + ": " +
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        if (!closed) {
            return errorResult("Program was not closed: " + label);
        }

        if (backend != null) {
            backend.clearCache();
        }

        return textResult("Closed program: " + label + "\n" +
            "Changed Before Close: " + changedBefore + "\n" +
            "Saved Before Close: " + (changedBefore && save) + "\n" +
            "Ignored Unsaved Changes: " + (changedAfterSave && ignoreChanges) + "\n" +
            "Open Programs Remaining: " + programManager.getAllOpenPrograms().length);
    }


    private String describeProgram(Program program) {
        String path = projectPath(program);
        if (!path.isBlank()) {
            return program.getName() + " (" + path + ")";
        }
        return program.getName();
    }

    private String projectPath(Program program) {
        DomainFile domainFile = program.getDomainFile();
        return domainFile != null ? domainFile.getPathname() : "";
    }

    private String stringArg(Object value, String defaultValue) {
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return defaultValue;
    }

    private static McpSchema.CallToolResult errorResult(String message) {
        return McpSchema.CallToolResult.builder().isError(true).addContent(McpSchema.TextContent.builder(message).build()).build();
    }

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(message).build())
            .build();
    }
}
