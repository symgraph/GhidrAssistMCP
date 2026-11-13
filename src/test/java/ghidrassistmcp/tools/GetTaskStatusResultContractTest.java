package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

class GetTaskStatusResultContractTest {
    private final GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
    private final GetTaskStatusTool tool = new GetTaskStatusTool();
    private final CountDownLatch releaseWorker = new CountDownLatch(1);

    @AfterEach
    void shutdown() {
        releaseWorker.countDown();
        backend.shutdown();
    }

    @Test
    void pendingPollReturnsTheStructuredHandleInsteadOfAProgressSummary() throws Exception {
        McpTask task = startBlockedTask();

        var response = poll(task);
        assertFalse(Boolean.TRUE.equals(response.isError()));
        assertEquals(Map.of("task_id", task.getTaskId(), "tool", "blocked",
            "status", "running", "poll_interval_ms", 1000), response.structuredContent());
        assertEquals("task_id=" + task.getTaskId() + " status=running", text(response));
        assertEquals(backend.getTaskManager().getTaskResult(task.getTaskId()), response);
    }

    @Test
    void cancelledPollMatchesTheTaskManagersCancellationResult() throws Exception {
        McpTask task = startBlockedTask();
        assertTrue(backend.getTaskManager().cancelTask(task.getTaskId()));

        var response = poll(task);
        assertTrue(response.isError());
        assertEquals("Task was cancelled", text(response));
        assertEquals(backend.getTaskManager().getTaskResult(task.getTaskId()), response);
    }

    @Test
    void failedPollRetainsTheOriginalToolResultAndStructuredErrorDetails() throws Exception {
        var failure = McpSchema.CallToolResult.builder()
            .addTextContent("Original tool failure")
            .structuredContent(Map.of("code", "fixture_failure", "detail", "original detail"))
            .isError(true).build();
        McpTask task = backend.getTaskManager().submitTask("failed", Map.of(), ignored -> failure);
        assertTrue(task.awaitCompletion(2000));

        assertSame(failure, poll(task));
    }

    private McpTask startBlockedTask() throws InterruptedException {
        CountDownLatch entered = new CountDownLatch(1);
        McpTask task = backend.getTaskManager().submitTask("blocked", Map.of(), ignored -> {
            entered.countDown();
            try {
                releaseWorker.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            return McpSchema.CallToolResult.builder().addTextContent("Completed").build();
        });
        assertTrue(entered.await(2, TimeUnit.SECONDS), "The task did not start");
        return task;
    }

    private McpSchema.CallToolResult poll(McpTask task) {
        return tool.execute(Map.of("task_id", task.getTaskId()), null, backend);
    }

    private static String text(McpSchema.CallToolResult response) {
        assertEquals(1, response.content().size());
        return assertInstanceOf(McpSchema.TextContent.class, response.content().get(0)).text();
    }
}
