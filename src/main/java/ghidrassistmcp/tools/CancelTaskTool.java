/*
 * MCP tool for cancelling async tasks.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/**
 * MCP tool that cancels a running async task.
 */
public class CancelTaskTool implements McpTool {

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public String getName() {
        return "cancel_task";
    }

    @Override
    public String getDescription() {
        return "Cancel a running async task";
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
            .addContent(McpSchema.TextContent.builder("Task cancellation requires backend reference. Use execute with backend parameter.").build())
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        String taskId = (String) arguments.get("task_id");

        if (taskId == null || taskId.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("task_id parameter is required").build())
                .build();
        }

        var taskManager = backend.getTaskManager();
        if (taskManager == null) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Task manager not available").build())
                .build();
        }

        boolean cancelled = taskManager.cancelTask(taskId);

        if (cancelled) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Successfully cancelled task: " + taskId).build())
                .build();
        }
        return McpSchema.CallToolResult.builder()
            .addContent(McpSchema.TextContent.builder("Could not cancel task: " + taskId +
                ". Task may have already completed or does not exist.").build())
            .build();
    }
}
