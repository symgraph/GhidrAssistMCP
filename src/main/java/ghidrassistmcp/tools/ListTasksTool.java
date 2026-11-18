/*
 * MCP tool for listing async tasks.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that lists all async tasks and their status.
 */
public class ListTasksTool implements McpTool {

    @Override
    public String getName() {
        return "list_tasks";
    }

    @Override
    public String getDescription() {
        return "List all async tasks with their status";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "status", Map.of(
                    "type", "string",
                    "description", "Optional: filter tasks by status",
                    "enum", List.of("PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")
                )
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder("Task listing requires backend reference. Use execute with backend parameter.").build())
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        var taskManager = backend.getTaskManager();
        if (taskManager == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Task manager not available").build())
                .build();
        }

        // Check for optional status filter
        String statusStr = (String) arguments.get("status");
        McpTask.Status statusFilter = null;

        if (statusStr != null && !statusStr.trim().isEmpty()) {
            try {
                statusFilter = McpTask.Status.valueOf(statusStr.toUpperCase());
            } catch (IllegalArgumentException e) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Invalid status filter: " + statusStr +
                        ". Valid values: PENDING, RUNNING, COMPLETED, FAILED, CANCELLED").build())
                    .build();
            }
        }

        // Get tasks summary or filtered list
        if (statusFilter != null) {
            List<McpTask> tasks = taskManager.listTasks(statusFilter);
            StringBuilder sb = new StringBuilder();
            sb.append("Tasks with status ").append(statusFilter).append(":\n\n");

            if (tasks.isEmpty()) {
                sb.append("No tasks found with this status.");
            } else {
                for (McpTask task : tasks) {
                    sb.append("---\n").append(task.toSummary()).append("\n");
                }
            }

            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder(sb.toString()).build())
                .build();
        }

        // Return full summary
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder(taskManager.getTasksSummary()).build())
            .build();
    }
}
