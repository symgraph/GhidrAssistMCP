package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class AnalysisControlTool implements McpTool {

    @Override
    public String getName() {
        return "analysis_control";
    }

    @Override
    public String getDescription() {
        return "Check Auto Analysis status or request cancellation of queued analysis for current/specified/all open programs. " +
            "Use MCP task tools (get_task_status/cancel_task) for analyze_program task tracking.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("status", "cancel")
                )),
                Map.entry("scope", Map.of(
                    "type", "string",
                    "description", "Program scope. Default: current",
                    "enum", List.of("current", "all_open"),
                    "default", "current"
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
            return textResult("action is required: status or cancel.");
        }

        List<Program> programs = resolvePrograms(arguments, currentProgram, backend);
        if (programs.isEmpty()) {
            return textResult("No program currently loaded.");
        }

        String normalizedAction = action.trim().toLowerCase();
        return switch (normalizedAction) {
            case "status" -> status(programs);
            case "cancel" -> cancel(programs);
            default -> textResult("Invalid action: " + action + ". Use status or cancel.");
        };
    }

    private McpSchema.CallToolResult status(List<Program> programs) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auto Analysis Status\n\n");
        for (Program program : programs) {
            boolean hasManager = AutoAnalysisManager.hasAutoAnalysisManager(program);
            boolean analyzing = hasManager && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
            sb.append("- ").append(program.getName()).append("\n");
            sb.append("  Analysis Manager Initialized: ").append(hasManager).append("\n");
            sb.append("  Is Analyzing: ").append(analyzing).append("\n");
            sb.append("  Analyzed Flag: ").append(AnalysisUtils.isAnalyzed(program)).append("\n");
            sb.append("  Should Ask To Analyze: ").append(AnalysisUtils.shouldAskToAnalyze(program)).append("\n");
        }
        return textResult(sb.toString().trim());
    }

    private McpSchema.CallToolResult cancel(List<Program> programs) {
        StringBuilder sb = new StringBuilder();
        sb.append("Auto Analysis Cancellation\n\n");
        for (Program program : programs) {
            if (!AutoAnalysisManager.hasAutoAnalysisManager(program)) {
                sb.append("- ").append(program.getName()).append(": analysis manager not initialized\n");
                continue;
            }
            AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
            manager.cancelQueuedTasks();
            sb.append("- ").append(program.getName())
              .append(": requested cancellation of queued analysis tasks. ")
              .append("An active analyzer may continue until its current monitor observes cancellation.\n");
        }
        return textResult(sb.toString().trim());
    }

    private List<Program> resolvePrograms(Map<String, Object> arguments, Program currentProgram,
                                          GhidrAssistMCPBackend backend) {
        String scope = (String) arguments.get("scope");
        if ("all_open".equalsIgnoreCase(scope) && backend != null) {
            return backend.getAllOpenPrograms();
        }
        List<Program> result = new ArrayList<>();
        if (currentProgram != null) {
            result.add(currentProgram);
        }
        return result;
    }

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
