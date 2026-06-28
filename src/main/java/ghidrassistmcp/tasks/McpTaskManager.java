/*
 * MCP Task Manager for async task execution and tracking.
 */
package ghidrassistmcp.tasks;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Manages asynchronous MCP task execution and tracking.
 * Provides task submission, status tracking, and cancellation capabilities.
 */
public class McpTaskManager {

    private static final int DEFAULT_THREAD_POOL_SIZE = 4;
    private static final int TASK_RETENTION_HOURS = 1;

    private final Map<String, McpTask> tasks = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> taskFutures = new ConcurrentHashMap<>();
    private final ExecutorService executor;

    /**
     * Create a new task manager with default thread pool size
     */
    public McpTaskManager() {
        this(DEFAULT_THREAD_POOL_SIZE);
    }

    /**
     * Create a new task manager with specified thread pool size
     */
    public McpTaskManager(int threadPoolSize) {
        this.executor = Executors.newFixedThreadPool(threadPoolSize, r -> {
            Thread t = new Thread(r);
            t.setName("MCP-Task-" + t.threadId());
            t.setDaemon(true);
            return t;
        });
        Msg.info(this, "McpTaskManager initialized with " + threadPoolSize + " threads");
    }

    /**
     * Submit a new async task for execution
     *
     * @param toolName The name of the tool being executed
     * @param arguments The tool arguments
     * @param taskExecutor A supplier that executes the tool and returns the result
     * @return The created task
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               Supplier<McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, task -> taskExecutor.get());
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        // Clean up old tasks before creating new ones
        cleanupOldTasks();

        McpTask task = new McpTask(toolName, arguments);
        tasks.put(task.getTaskId(), task);

        Future<?> future = executor.submit(() -> {
            try {
                task.markStarted();
                Msg.info(this, "Task started: " + task.getTaskId() + " for tool: " + toolName);

                McpSchema.CallToolResult result = taskExecutor.apply(task);
                task.markCompleted(result);

                Msg.info(this, "Task completed: " + task.getTaskId() + " in " + task.getDurationMillis() + "ms");

            } catch (Exception e) {
                task.markFailed(e.getMessage());
                Msg.error(this, "Task failed: " + task.getTaskId() + " - " + e.getMessage(), e);
            }
        });

        taskFutures.put(task.getTaskId(), future);
        Msg.info(this, "Task submitted: " + task.getTaskId() + " for tool: " + toolName);

        return task;
    }

    /**
     * Get a task by ID
     */
    public McpTask getTask(String taskId) {
        return tasks.get(taskId);
    }

    /**
     * Get task status summary
     */
    public String getTaskStatus(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return "Task not found: " + taskId;
        }
        return task.toSummary();
    }

    /**
     * Get the result of a completed task
     */
    public McpSchema.CallToolResult getTaskResult(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task not found: " + taskId)
                .build();
        }

        if (!task.isTerminal()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task is still running.\n" + task.toSummary())
                .build();
        }

        if (task.getStatus() == McpTask.Status.COMPLETED && task.getResult() != null) {
            return task.getResult();
        }

        if (task.getStatus() == McpTask.Status.FAILED) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task failed: " + task.getErrorMessage())
                .build();
        }

        if (task.getStatus() == McpTask.Status.CANCELLED) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task was cancelled")
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Unknown task state: " + task.getStatus())
            .build();
    }

    /**
     * Cancel a running task
     */
    public boolean cancelTask(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return false;
        }

        if (task.isTerminal()) {
            return false; // Can't cancel a completed task
        }

        Future<?> future = taskFutures.get(taskId);
        if (future != null) {
            future.cancel(true);
        }

        task.markCancelled();
        Msg.info(this, "Task cancelled: " + taskId);
        return true;
    }

    /**
     * List all tasks with optional status filter
     */
    public List<McpTask> listTasks(McpTask.Status statusFilter) {
        if (statusFilter == null) {
            return new ArrayList<>(tasks.values());
        }

        return tasks.values().stream()
            .filter(t -> t.getStatus() == statusFilter)
            .collect(Collectors.toList());
    }

    /**
     * Get a summary of all active tasks
     */
    public String getTasksSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("MCP Tasks Summary:\n\n");

        long pending = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.PENDING).count();
        long running = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.RUNNING).count();
        long completed = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.COMPLETED).count();
        long failed = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.FAILED).count();
        long cancelled = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.CANCELLED).count();

        sb.append("Total: ").append(tasks.size()).append("\n");
        sb.append("  Pending: ").append(pending).append("\n");
        sb.append("  Running: ").append(running).append("\n");
        sb.append("  Completed: ").append(completed).append("\n");
        sb.append("  Failed: ").append(failed).append("\n");
        sb.append("  Cancelled: ").append(cancelled).append("\n\n");

        if (!tasks.isEmpty()) {
            sb.append("Tasks:\n");
            tasks.values().stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt())) // Most recent first
                .limit(20) // Limit to 20 most recent
                .forEach(task -> {
                    sb.append("  - ").append(task.getTaskId().substring(0, 8)).append("...")
                      .append(" | ").append(task.getToolName())
                      .append(" | ").append(task.getStatus())
                      .append(" | ").append(task.getProgressPercent()).append("%")
                      .append("\n");
                });
        }

        return sb.toString();
    }

    /**
     * Clean up old completed tasks
     */
    private void cleanupOldTasks() {
        Instant cutoff = Instant.now().minus(TASK_RETENTION_HOURS, ChronoUnit.HOURS);

        List<String> toRemove = tasks.entrySet().stream()
            .filter(e -> e.getValue().isTerminal())
            .filter(e -> e.getValue().getCompletedAt() != null && e.getValue().getCompletedAt().isBefore(cutoff))
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());

        for (String taskId : toRemove) {
            tasks.remove(taskId);
            taskFutures.remove(taskId);
        }

        if (!toRemove.isEmpty()) {
            Msg.info(this, "Cleaned up " + toRemove.size() + " old tasks");
        }
    }

    /**
     * Shutdown the task manager
     */
    public void shutdown() {
        Msg.info(this, "Shutting down McpTaskManager...");
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        Msg.info(this, "McpTaskManager shut down");
    }
}
