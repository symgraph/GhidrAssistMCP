/*
 * MCP tool for getting task status.
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
 * MCP tool that gets the status of an async task or retrieves its result.
 */
public class GetTaskStatusTool implements McpTool {

    @Override
    public String getName() {
        return "get_task_status";
    }

    @Override
    public String getDescription() {
        return "Get the status of an async task, or retrieve its result if completed";
    }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "task_id", new JsonSchema("string", null, null, null, null, null)
            ),
            List.of("task_id"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder("Task status requires backend reference. Use execute with backend parameter.").build())
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String taskId = (String) arguments.get("task_id");

        if (taskId == null || taskId.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addContent(McpSchema.TextContent.builder("task_id parameter is required").build())
                .build();
        }

        var taskManager = backend.getTaskManager();
        if (taskManager == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addContent(McpSchema.TextContent.builder("Task manager not available").build())
                .build();
        }

        McpTask task = taskManager.getTask(taskId);
        if (task == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addContent(McpSchema.TextContent.builder("Task not found: " + taskId).build())
                .build();
        }

        return taskManager.getTaskResult(taskId);
    }
}
