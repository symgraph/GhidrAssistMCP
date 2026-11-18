package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

class McpToolProgressTest {
    @Test void bridgesExistingTaskAwareExecutionWithStoredProgressAndProgramSnapshot() {
        Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[] {Program.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> "original-program";
                case "getDomainFile" -> null;
                default -> throw new UnsupportedOperationException(method.getName());
            });
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        Probe tool = new Probe(); RecordingMonitor monitor = new RecordingMonitor();
        try {
            var result = tool.executeMonitored(Map.of("value", "original"), program, backend, monitor);
            assertSame(tool.result, result);
            assertEquals(McpTask.Status.RUNNING, tool.seen.getStatus());
            assertEquals("original-program", tool.seen.getProgramContext().programName());
            assertEquals(Map.of("value", "original"), tool.seen.getArguments());
            assertEquals(31, tool.seen.getProgressPercent());
            assertEquals("Analyzing", tool.seen.getProgressMessage());
            assertEquals(100, monitor.getMaximum());
            assertEquals(List.of(0L, 31L, 100L), monitor.values);
            assertEquals("Completed", monitor.getMessage());
            assertTrue(backend.getTaskManager().listTasks(null).isEmpty(), "Request progress must not register a job");
            tool.seen.updateProgress(99, "Late callback");
            assertEquals(31, tool.seen.getProgressPercent());
            assertEquals(List.of(0L, 31L, 100L), monitor.values);
        } finally { backend.shutdown(); }
    }

    @Test void preservesReturnedToolErrorWithoutReplacingItOrReportingSuccess() {
        Probe tool = new Probe();
        tool.result = McpSchema.CallToolResult.builder().isError(true).addTextContent("Original analysis error").build();
        RecordingMonitor monitor = new RecordingMonitor();
        assertSame(tool.result, tool.executeMonitored(Map.of(), null, null, monitor));
        assertEquals(List.of(0L, 31L, 100L), monitor.values);
        assertEquals("Finished with errors", monitor.getMessage());
    }

    @Test void thrownExceptionAndNullResultAreNotTurnedIntoCompletionOrNewFailures() {
        Probe tool = new Probe(); RecordingMonitor monitor = new RecordingMonitor();
        IllegalStateException original = new IllegalStateException("Original failure");
        tool.failure = original;
        assertSame(original, assertThrows(IllegalStateException.class,
            () -> tool.executeMonitored(Map.of(), null, null, monitor)));
        assertEquals(List.of(0L, 31L), monitor.values);
        tool.seen.updateProgress(100, "After exception");
        assertEquals(List.of(0L, 31L), monitor.values);

        tool.failure = null; tool.result = null; RecordingMonitor emptyMonitor = new RecordingMonitor();
        assertNull(tool.executeMonitored(Map.of(), null, null, emptyMonitor));
        assertEquals(List.of(0L, 31L), emptyMonitor.values);
    }

    private static final class Probe implements McpTool {
        McpTask seen;
        RuntimeException failure;
        McpSchema.CallToolResult result = McpSchema.CallToolResult.builder().addTextContent("Original result").build();
        @Override public String getName() { return "task_aware_probe"; }
        @Override public String getDescription() { return "Existing task-aware implementation"; }
        @Override public McpSchema.JsonSchema getInputSchema() { return null; }
        @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
            throw new AssertionError("Task-aware overload was bypassed");
        }
        @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
                GhidrAssistMCPBackend backend, McpTask task) {
            seen = task;
            assertEquals(McpTask.Status.RUNNING, task.getStatus());
            task.updateProgress(31, "Analyzing");
            if (failure != null) throw failure;
            return result;
        }
    }

    private static final class RecordingMonitor extends TaskMonitorAdapter {
        final List<Long> values = new ArrayList<>();
        long maximum;
        String message;
        @Override public void initialize(long value) { maximum = value; setProgress(0); }
        @Override public long getMaximum() { return maximum; }
        @Override public void setProgress(long value) { values.add(value); }
        @Override public void setMessage(String value) { message = value; }
        @Override public String getMessage() { return message; }
    }
}
