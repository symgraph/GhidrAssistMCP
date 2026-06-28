package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

public class AnalyzeProgramTool implements McpTool {

    @Override
    public String getName() {
        return "analyze_program";
    }

    @Override
    public String getDescription() {
        return "Run Ghidra Auto Analysis on the current/specified program or all open programs. " +
            "Supports full re-analysis, pending-changes analysis, optional address range restriction, " +
            "and per-call analysis option overrides.";
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
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("scope", Map.of(
                    "type", "string",
                    "description", "Program scope to analyze. Default: current",
                    "enum", List.of("current", "all_open"),
                    "default", "current"
                )),
                Map.entry("mode", Map.of(
                    "type", "string",
                    "description", "Analysis mode. 'full' schedules all program bytes/range for re-analysis; 'changes' waits for pending analysis only. Default: full",
                    "enum", List.of("full", "changes"),
                    "default", "full"
                )),
                Map.entry("start_address", Map.of(
                    "type", "string",
                    "description", "Optional range start address for mode='full' on a single program"
                )),
                Map.entry("end_address", Map.of(
                    "type", "string",
                    "description", "Optional range end address for mode='full' on a single program"
                )),
                Map.entry("options", Map.of(
                    "type", "object",
                    "description", "Optional analysis option overrides to apply before analysis"
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
        return executeInternal(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend, McpTask task) {
        return executeInternal(arguments, currentProgram, backend, task);
    }

    private McpSchema.CallToolResult executeInternal(Map<String, Object> arguments, Program currentProgram,
                                                    GhidrAssistMCPBackend backend, McpTask task) {
        List<Program> programs = resolvePrograms(arguments, currentProgram, backend);
        if (programs.isEmpty()) {
            return textResult("No program currently loaded.");
        }

        String mode = (String) arguments.get("mode");
        Map<String, Object> options = AnalysisUtils.objectMap(arguments.get("options"));
        String startAddress = (String) arguments.get("start_address");
        String endAddress = (String) arguments.get("end_address");

        if (programs.size() > 1 &&
            ((startAddress != null && !startAddress.isBlank()) || (endAddress != null && !endAddress.isBlank()))) {
            return textResult("Address range analysis is only supported for a single target program.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Auto Analysis Results\n\n");
        int total = programs.size();
        for (int i = 0; i < total; i++) {
            Program program = programs.get(i);
            TaskMonitor monitor = monitorForProgram(task, program, i, total);
            try {
                publishProgramProgress(task, program, i, total, "Preparing");
                AddressSet range = AnalysisUtils.parseRange(program, startAddress, endAddress);
                sb.append(AnalysisUtils.runAnalysis(program, mode, range, options, monitor));
                sb.append("\n\n");
                publishProgramProgress(task, program, i, total, "Completed");
            } catch (Exception e) {
                Msg.error(this, "Analysis failed for " + program.getName(), e);
                sb.append("Analysis failed for ").append(program.getName()).append(": ")
                  .append(e.getMessage()).append("\n\n");
            }
        }

        if (backend != null) {
            backend.clearCache();
        }
        return textResult(sb.toString().trim());
    }

    private TaskMonitor monitorForProgram(McpTask task, Program program, int index, int total) {
        if (task == null) {
            return TaskMonitor.DUMMY;
        }
        return new McpTaskMonitor(task, startPercent(index, total), endPercent(index, total),
            "Analyzing " + program.getName() + " (" + (index + 1) + "/" + total + ")");
    }

    private void publishProgramProgress(McpTask task, Program program, int index, int total, String status) {
        if (task == null) {
            return;
        }
        int percent = "Completed".equals(status) ? endPercent(index, total) : startPercent(index, total);
        task.updateProgress(percent, status + " " + program.getName() +
            " (" + (index + 1) + "/" + total + ")");
    }

    private int startPercent(int index, int total) {
        return (index * 99) / total;
    }

    private int endPercent(int index, int total) {
        return ((index + 1) * 99) / total;
    }

    private List<Program> resolvePrograms(Map<String, Object> arguments, Program currentProgram,
                                          GhidrAssistMCPBackend backend) {
        String scope = (String) arguments.get("scope");
        if ("all_open".equalsIgnoreCase(scope)) {
            if (backend != null) {
                return backend.getAllOpenPrograms();
            }
            return currentProgram != null ? List.of(currentProgram) : List.of();
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
