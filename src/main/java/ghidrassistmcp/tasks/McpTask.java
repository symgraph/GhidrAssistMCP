/*
 * MCP Task state object for async task management.
 */
package ghidrassistmcp.tasks;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import io.modelcontextprotocol.spec.McpSchema;

/**
 * Represents an asynchronous MCP task with its state and result.
 */
public class McpTask {

    /**
     * Task status enumeration
     */
    public enum Status {
        PENDING,    // Task is queued but not yet started
        RUNNING,    // Task is currently executing
        COMPLETED,  // Task completed successfully
        FAILED,     // Task failed with an error
        CANCELLED   // Task was cancelled
    }

    private final String taskId;
    private final String toolName;
    private final Map<String, Object> arguments;
    private final McpProgramContext programContext;
    private final Instant createdAt;
    private final CountDownLatch completion = new CountDownLatch(1);
    private volatile Status status;
    private volatile Instant startedAt;
    private volatile Instant completedAt;
    private volatile McpSchema.CallToolResult result;
    private volatile String errorMessage;
    private volatile int progressPercent;
    private volatile String progressMessage;

    /**
     * Create a new task
     */
    public McpTask(String toolName, Map<String, Object> arguments) {
        this(toolName, arguments, McpProgramContext.empty());
    }

    /**
     * Create a new task with an immutable snapshot of its target program.
     */
    public McpTask(String toolName, Map<String, Object> arguments,
                   McpProgramContext programContext) {
        this.taskId = UUID.randomUUID().toString();
        this.toolName = toolName;
        this.arguments = arguments == null ? Map.of() :
            java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(arguments));
        this.programContext = programContext != null
                ? programContext
                : McpProgramContext.empty();
        this.createdAt = Instant.now();
        this.status = Status.PENDING;
        this.progressPercent = 0;
        this.progressMessage = "Waiting to start...";
    }

    // Getters

    public String getTaskId() {
        return taskId;
    }

    public String getToolName() {
        return toolName;
    }

    public Map<String, Object> getArguments() {
        return arguments;
    }

    public McpProgramContext getProgramContext() {
        return programContext;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public McpSchema.CallToolResult getResult() {
        return result;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public int getProgressPercent() {
        return progressPercent;
    }

    public String getProgressMessage() {
        return progressMessage;
    }

    // State transition methods

    /**
     * Mark task as started
     */
    public synchronized void markStarted() {
        if (this.status == Status.PENDING) {
            this.status = Status.RUNNING;
            this.startedAt = Instant.now();
            this.progressMessage = "Running...";
        }
    }

    /**
     * Update task progress
     */
    public synchronized void updateProgress(int percent, String message) {
        if (this.status == Status.RUNNING) {
            this.progressPercent = Math.max(0, Math.min(100, percent));
            this.progressMessage = message;
        }
    }

    /**
     * Mark task as completed with result
     */
    public synchronized void markCompleted(McpSchema.CallToolResult taskResult) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING) {
            boolean failed = Boolean.TRUE.equals(taskResult.isError());
            if (failed) {
                this.errorMessage = taskResult.content().stream()
                    .filter(McpSchema.TextContent.class::isInstance)
                    .map(McpSchema.TextContent.class::cast)
                    .map(McpSchema.TextContent::text)
                    .findFirst().orElse("Tool execution failed");
            }
            this.completedAt = Instant.now();
            this.result = taskResult;
            this.progressPercent = 100;
            this.progressMessage = failed ? "Failed: " + errorMessage : "Completed";
            this.status = failed ? Status.FAILED : Status.COMPLETED;
            completion.countDown();
        }
    }

    /**
     * Mark task as failed with error
     */
    public synchronized void markFailed(String taskErrorMessage) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING) {
            this.completedAt = Instant.now();
            this.errorMessage = taskErrorMessage;
            this.progressMessage = "Failed: " + taskErrorMessage;
            this.status = Status.FAILED;
            completion.countDown();
        }
    }

    /**
     * Mark task as cancelled
     */
    public synchronized void markCancelled() {
        if (this.status == Status.PENDING || this.status == Status.RUNNING) {
            this.completedAt = Instant.now();
            this.progressMessage = "Cancelled";
            this.status = Status.CANCELLED;
            completion.countDown();
        }
    }

    /** Observe completion without cancelling or otherwise changing the running task. */
    public boolean awaitCompletion(long timeoutMillis) throws InterruptedException {
        return completion.await(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    /** Compact handle shared by submission and nonterminal status polling. */
    public McpSchema.CallToolResult toPendingResult() {
        String taskStatus = status.name().toLowerCase(java.util.Locale.ROOT);
        return McpSchema.CallToolResult.builder()
            .addTextContent("task_id=" + taskId + " status=" + taskStatus)
            .structuredContent(Map.of("task_id", taskId, "tool", toolName,
                "status", taskStatus,
                "poll_interval_ms", 1000))
            .build();
    }

    /**
     * Check if task is terminal (completed, failed, or cancelled)
     */
    public boolean isTerminal() {
        Status s = this.status;
        return s == Status.COMPLETED || s == Status.FAILED || s == Status.CANCELLED;
    }

    /**
     * Get duration in milliseconds (or elapsed time if still running)
     */
    public long getDurationMillis() {
        if (startedAt == null) {
            return 0;
        }
        Instant end = completedAt != null ? completedAt : Instant.now();
        return end.toEpochMilli() - startedAt.toEpochMilli();
    }

    /**
     * Generate a summary string for display
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Task ID: ").append(taskId).append("\n");
        sb.append("Tool: ").append(toolName).append("\n");
        sb.append("Status: ").append(status).append("\n");
        sb.append("Progress: ").append(progressPercent).append("% - ").append(progressMessage).append("\n");
        sb.append("Created: ").append(createdAt).append("\n");

        if (startedAt != null) {
            sb.append("Started: ").append(startedAt).append("\n");
        }

        if (completedAt != null) {
            sb.append("Completed: ").append(completedAt).append("\n");
            sb.append("Duration: ").append(getDurationMillis()).append("ms\n");
        }

        if (errorMessage != null) {
            sb.append("Error: ").append(errorMessage).append("\n");
        }

        return sb.toString();
    }
}
