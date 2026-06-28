package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

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
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
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
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool pluginTool = manager.getActiveTool();
        if (pluginTool == null) {
            return textResult("No active Ghidra tool/window available.");
        }

        ProgramManager programManager = pluginTool.getService(ProgramManager.class);
        if (programManager == null) {
            return textResult("ProgramManager service not available. Is CodeBrowser open?");
        }

        String name = stringArg(arguments.get("name"), null);
        boolean save = Boolean.TRUE.equals(arguments.get("save"));
        boolean ignoreChanges = Boolean.TRUE.equals(arguments.get("ignore_changes"));

        Program target = name == null ? programManager.getCurrentProgram() :
            resolveOpenProgram(programManager.getAllOpenPrograms(), name);
        if (target == null) {
            if (name == null) {
                return textResult("No current program is open.");
            }
            return textResult("Open program not found: " + name);
        }

        String label = describeProgram(target);
        boolean changedBefore = target.isChanged();
        if (changedBefore && save) {
            try {
                programManager.saveProgram(target);
            } catch (Exception e) {
                Msg.error(this, "Failed to save program before close: " + label, e);
                return textResult("Failed to save before closing " + label + ": " +
                    e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }

        boolean changedAfterSave = target.isChanged();
        if (changedAfterSave && !ignoreChanges) {
            return textResult("Refusing to close changed program without saving: " + label +
                "\nPass save=true to save first, or ignore_changes=true to close without saving.");
        }

        boolean closed;
        try {
            closed = programManager.closeProgram(target, ignoreChanges);
        } catch (Exception e) {
            Msg.error(this, "Failed to close program: " + label, e);
            return textResult("Failed to close " + label + ": " +
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        if (!closed) {
            return textResult("Program was not closed: " + label);
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

    private Program resolveOpenProgram(Program[] openPrograms, String name) {
        List<Program> exactMatches = new ArrayList<>();
        List<Program> caseInsensitiveMatches = new ArrayList<>();
        List<Program> partialMatches = new ArrayList<>();
        String lowerName = name.toLowerCase();

        for (Program program : openPrograms) {
            String programName = program.getName();
            String path = projectPath(program);
            if (programName.equals(name) || name.equals(path)) {
                exactMatches.add(program);
            }
            else if (programName.equalsIgnoreCase(name) || path.equalsIgnoreCase(name)) {
                caseInsensitiveMatches.add(program);
            }
            else if (programName.toLowerCase().contains(lowerName) ||
                     path.toLowerCase().contains(lowerName)) {
                partialMatches.add(program);
            }
        }

        if (exactMatches.size() == 1) {
            return exactMatches.get(0);
        }
        if (caseInsensitiveMatches.size() == 1) {
            return caseInsensitiveMatches.get(0);
        }
        if (partialMatches.size() == 1) {
            return partialMatches.get(0);
        }
        return null;
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

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
