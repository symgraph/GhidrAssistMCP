package ghidrassistmcp.tools;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class AnalysisOptionsTool implements McpTool {

    private static final String PRESET_PREFIX = "GhidrAssistMCP.AnalysisPreset.";

    @Override
    public String getName() {
        return "analysis_options";
    }

    @Override
    public String getDescription() {
        return "List, set, reset, save, and apply Ghidra Auto Analysis options. " +
            "Plugin-provided Auto Analyzers appear here when their analyzers are registered for the program.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
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
                    "enum", List.of("list", "set", "reset", "save_preset", "apply_preset", "list_presets", "delete_preset")
                )),
                Map.entry("filter", Map.of(
                    "type", "string",
                    "description", "For action='list': optional case-insensitive substring filter for option names"
                )),
                Map.entry("offset", Map.of(
                    "type", "integer",
                    "description", "For action='list': number of matching options to skip. Default: 0",
                    "default", 0,
                    "minimum", 0
                )),
                Map.entry("limit", Map.of(
                    "type", "integer",
                    "description", "For action='list': maximum options to return. Default: 200",
                    "default", 200,
                    "minimum", 1
                )),
                Map.entry("options", Map.of(
                    "type", "object",
                    "description", "For action='set' or 'save_preset': mapping of analysis option names to values"
                )),
                Map.entry("option_names", Map.of(
                    "type", "array",
                    "description", "For action='reset' or 'save_preset': list of analysis option names",
                    "items", Map.of("type", "string")
                )),
                Map.entry("preset_name", Map.of(
                    "type", "string",
                    "description", "Preset name for save_preset/apply_preset/delete_preset"
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
        String action = (String) arguments.get("action");
        if (action == null || action.isBlank()) {
            return textResult("action is required.");
        }

        String normalizedAction = action.trim().toLowerCase();
        if ("list_presets".equals(normalizedAction)) {
            return listPresets();
        }

        if (currentProgram == null) {
            return textResult("No program currently loaded.");
        }

        return switch (normalizedAction) {
            case "list" -> listOptions(arguments, currentProgram);
            case "set" -> setOptions(arguments, currentProgram, backend);
            case "reset" -> resetOptions(arguments, currentProgram, backend);
            case "save_preset" -> savePreset(arguments, currentProgram);
            case "apply_preset" -> applyPreset(arguments, currentProgram, backend);
            case "delete_preset" -> deletePreset(arguments);
            default -> textResult("Invalid action: " + action +
                ". Use list, set, reset, save_preset, apply_preset, list_presets, or delete_preset.");
        };
    }

    private McpSchema.CallToolResult listOptions(Map<String, Object> arguments, Program program) {
        String filter = (String) arguments.get("filter");
        String normalizedFilter = filter != null ? filter.toLowerCase() : null;
        int offset = numberArg(arguments.get("offset"), 0);
        int limit = numberArg(arguments.get("limit"), 200);

        List<AnalysisUtils.OptionSnapshot> allOptions = AnalysisUtils.listAnalysisOptions(program);
        List<AnalysisUtils.OptionSnapshot> matches = allOptions.stream()
            .filter(o -> normalizedFilter == null || o.name.toLowerCase().contains(normalizedFilter))
            .toList();

        StringBuilder sb = new StringBuilder();
        sb.append("Auto Analysis Options for ").append(program.getName()).append("\n\n");
        sb.append("Analyzed Flag: ").append(AnalysisUtils.isAnalyzed(program)).append("\n");
        sb.append("Should Ask To Analyze: ").append(AnalysisUtils.shouldAskToAnalyze(program)).append("\n\n");

        int end = Math.min(matches.size(), offset + limit);
        for (int i = offset; i < end; i++) {
            AnalysisUtils.OptionSnapshot option = matches.get(i);
            sb.append("- ").append(option.name).append("\n");
            sb.append("  Type: ").append(option.type).append("\n");
            sb.append("  Value: ").append(option.value);
            if (option.isDefault) {
                sb.append(" (default)");
            }
            sb.append("\n");
            sb.append("  Default: ").append(option.defaultValue).append("\n");
            if (!option.description.isBlank()) {
                sb.append("  Description: ").append(option.description).append("\n");
            }
        }

        sb.append("\nShowing ").append(Math.max(0, end - offset))
          .append(" of ").append(matches.size()).append(" matching option(s)");
        if (offset > 0) {
            sb.append(" (offset ").append(offset).append(")");
        }
        sb.append("\nTotal registered analysis options: ").append(allOptions.size());

        return textResult(sb.toString());
    }

    private McpSchema.CallToolResult setOptions(Map<String, Object> arguments, Program program,
                                                GhidrAssistMCPBackend backend) {
        Map<String, Object> options = AnalysisUtils.objectMap(arguments.get("options"));
        if (options == null || options.isEmpty()) {
            return textResult("options object is required for action='set'.");
        }

        List<String> errors = AnalysisUtils.applyAnalysisOptions(program, options);
        if (!errors.isEmpty()) {
            return textResult("Failed to set analysis options:\n- " + String.join("\n- ", errors));
        }
        if (backend != null) {
            backend.clearCache();
        }
        return textResult("Set " + options.size() + " analysis option(s) for " + program.getName() + ".");
    }

    private McpSchema.CallToolResult resetOptions(Map<String, Object> arguments, Program program,
                                                  GhidrAssistMCPBackend backend) {
        List<String> names = AnalysisUtils.stringList(arguments.get("option_names"));
        List<String> errors = AnalysisUtils.resetAnalysisOptions(program, names);
        if (!errors.isEmpty()) {
            return textResult("Failed to reset analysis options:\n- " + String.join("\n- ", errors));
        }
        if (backend != null) {
            backend.clearCache();
        }
        if (names == null || names.isEmpty()) {
            return textResult("Reset all analysis options to defaults for " + program.getName() + ".");
        }
        return textResult("Reset " + names.size() + " analysis option(s) for " + program.getName() + ".");
    }

    private McpSchema.CallToolResult savePreset(Map<String, Object> arguments, Program program) {
        String presetName = normalizePresetName(arguments.get("preset_name"));
        if (presetName == null) {
            return textResult("preset_name is required and may not contain ',' or newlines.");
        }

        Map<String, Object> explicitOptions = AnalysisUtils.objectMap(arguments.get("options"));
        List<String> optionNames = AnalysisUtils.stringList(arguments.get("option_names"));
        Map<String, String> values = new LinkedHashMap<>();

        if (explicitOptions != null && !explicitOptions.isEmpty()) {
            for (Map.Entry<String, Object> entry : explicitOptions.entrySet()) {
                values.put(entry.getKey(), entry.getValue() != null ? entry.getValue().toString() : "");
            }
        } else {
            List<AnalysisUtils.OptionSnapshot> snapshots = AnalysisUtils.listAnalysisOptions(program);
            for (AnalysisUtils.OptionSnapshot snapshot : snapshots) {
                if (optionNames == null || optionNames.isEmpty() || optionNames.contains(snapshot.name)) {
                    values.put(snapshot.name, snapshot.value);
                }
            }
        }

        if (values.isEmpty()) {
            return textResult("No analysis options selected for preset '" + presetName + "'.");
        }

        Properties properties = new Properties();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            properties.setProperty(entry.getKey(), entry.getValue());
        }

        try {
            StringWriter writer = new StringWriter();
            properties.store(writer, "GhidrAssistMCP analysis preset");
            Preferences.setProperty(PRESET_PREFIX + presetName, writer.toString());
            Preferences.store();
            return textResult("Saved analysis preset '" + presetName + "' with " + values.size() + " option(s).");
        } catch (IOException e) {
            return textResult("Failed to save preset '" + presetName + "': " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult applyPreset(Map<String, Object> arguments, Program program,
                                                 GhidrAssistMCPBackend backend) {
        String presetName = normalizePresetName(arguments.get("preset_name"));
        if (presetName == null) {
            return textResult("preset_name is required.");
        }

        Properties properties = loadPreset(presetName);
        if (properties == null) {
            return textResult("Analysis preset not found: " + presetName);
        }

        Map<String, Object> options = new LinkedHashMap<>();
        for (String name : properties.stringPropertyNames()) {
            options.put(name, properties.getProperty(name));
        }

        List<String> errors = AnalysisUtils.applyAnalysisOptions(program, options);
        if (!errors.isEmpty()) {
            return textResult("Failed to apply analysis preset '" + presetName + "':\n- " +
                String.join("\n- ", errors));
        }
        if (backend != null) {
            backend.clearCache();
        }
        return textResult("Applied analysis preset '" + presetName + "' to " + program.getName() +
            " (" + options.size() + " option(s)).");
    }

    private McpSchema.CallToolResult listPresets() {
        Set<String> names = presetNames();
        if (names.isEmpty()) {
            return textResult("No analysis presets saved.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Saved analysis presets:\n\n");
        for (String name : names) {
            Properties properties = loadPreset(name);
            sb.append("- ").append(name);
            if (properties != null) {
                sb.append(" (").append(properties.size()).append(" option(s))");
            }
            sb.append("\n");
        }
        return textResult(sb.toString());
    }

    private McpSchema.CallToolResult deletePreset(Map<String, Object> arguments) {
        String presetName = normalizePresetName(arguments.get("preset_name"));
        if (presetName == null) {
            return textResult("preset_name is required.");
        }

        String removed = Preferences.removeProperty(PRESET_PREFIX + presetName);
        Preferences.store();
        if (removed == null) {
            return textResult("Analysis preset not found: " + presetName);
        }
        return textResult("Deleted analysis preset '" + presetName + "'.");
    }

    private Set<String> presetNames() {
        Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (String key : Preferences.getPropertyNames()) {
            if (key.startsWith(PRESET_PREFIX)) {
                names.add(key.substring(PRESET_PREFIX.length()));
            }
        }
        return names;
    }

    private Properties loadPreset(String presetName) {
        String value = Preferences.getProperty(PRESET_PREFIX + presetName);
        if (value == null) {
            return null;
        }
        Properties properties = new Properties();
        try {
            properties.load(new StringReader(value));
            return properties;
        } catch (IOException e) {
            return null;
        }
    }

    private String normalizePresetName(Object value) {
        if (!(value instanceof String text)) {
            return null;
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty() || trimmed.contains(",") || trimmed.contains("\n") || trimmed.contains("\r")) {
            return null;
        }
        return trimmed;
    }

    private int numberArg(Object value, int defaultValue) {
        if (value instanceof Number number) {
            return Math.max(0, number.intValue());
        }
        return defaultValue;
    }

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
