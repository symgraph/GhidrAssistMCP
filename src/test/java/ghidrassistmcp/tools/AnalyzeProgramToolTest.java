package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrassistmcp.GhidrAssistMCPBackend;
import io.modelcontextprotocol.spec.McpSchema;

class AnalyzeProgramToolTest {
    private final TestBackend backend = new TestBackend();
    @AfterEach void shutdown() { backend.shutdown(); }

    @Test void allOpenScopeDoesNotRequireAnActiveBrowserProgram() {
        backend.setAsyncExecutionEnabled(false);
        AtomicInteger acquired = new AtomicInteger();
        backend.programs = List.of(program("closed", false, acquired, new AtomicInteger(), () -> {}));
        var result = backend.callTool("analyze_program", Map.of("scope", "all_open"));
        assertTrue(result.isError());
        assertTrue(text(result).contains("Program is already closed: closed"), text(result));
        assertEquals(1, acquired.get());
    }

    @Test void retainsEveryTargetBeforeAnalysisAndReleasesAllAfterFailures() {
        backend.setAsyncExecutionEnabled(false);
        AtomicInteger acquired = new AtomicInteger();
        AtomicInteger firstReleased = new AtomicInteger();
        AtomicInteger secondReleased = new AtomicInteger();
        Runnable assertBothRetained = () -> assertEquals(2, acquired.get());
        backend.programs = List.of(program("first", true, acquired, firstReleased, assertBothRetained),
            program("second", true, acquired, secondReleased, assertBothRetained));
        var result = backend.callTool("analyze_program", Map.of("scope", "all_open",
            "options", Map.of("fixture", true)));
        assertTrue(result.isError());
        assertTrue(text(result).contains("Analysis failed for first"), text(result));
        assertTrue(text(result).contains("Analysis failed for second"), text(result));
        assertEquals(1, firstReleased.get());
        assertEquals(1, secondReleased.get());
    }

    @Test void partialLeaseAcquisitionReleasesAlreadyRetainedPrograms() {
        backend.setAsyncExecutionEnabled(false);
        AtomicInteger acquired = new AtomicInteger();
        AtomicInteger released = new AtomicInteger();
        backend.programs = List.of(program("first", true, acquired, released, () -> fail("No analysis expected")),
            program("closed", false, acquired, new AtomicInteger(), () -> fail("No analysis expected")));
        var result = backend.callTool("analyze_program", Map.of("scope", "all_open"));
        assertTrue(result.isError());
        assertEquals(2, acquired.get());
        assertEquals(1, released.get());
    }

    @Test void canonicalAnalysisPublishesExistingTaskProgressWithoutRegisteringJobsAndRetainsFailureOutcomes() {
        AtomicInteger acquired = new AtomicInteger(), firstReleased = new AtomicInteger(), secondReleased = new AtomicInteger();
        Runnable bothRetained = () -> assertEquals(2, acquired.get());
        backend.programs = List.of(program("first", true, acquired, firstReleased, bothRetained),
            program("second", true, acquired, secondReleased, bothRetained));
        Map<String, Object> args = Map.of("scope", "all_open", "options", Map.of("fixture", true));
        backend.setAsyncExecutionEnabled(false);
        var original = backend.callTool("analyze_program", args);
        acquired.set(0); firstReleased.set(0); secondReleased.set(0);
        backend.setAsyncExecutionEnabled(true);
        List<Long> progress = new ArrayList<>();
        var monitored = backend.callToolMonitored("analyze_program", args, new TaskMonitorAdapter() {
            @Override public void initialize(long maximum) { assertEquals(100, maximum); progress.add(0L); }
            @Override public void setProgress(long value) { progress.add(value); }
        });
        assertTrue(backend.supportsRequestMonitoring("analyze_program"), "The canonical wrapper must retain opt-in");
        assertFalse(backend.supportsRequestMonitoring("get_pseudocode"));
        assertTrue(monitored.isError());
        assertEquals(text(original), text(monitored));
        assertTrue(progress.contains(49L), "Existing per-program task progress must reach the native monitor");
        assertEquals(0L, progress.getFirst()); assertEquals(100L, progress.getLast());
        assertEquals(1, firstReleased.get()); assertEquals(1, secondReleased.get());
        assertTrue(backend.getTaskManager().listTasks(null).isEmpty());
    }

    private static Program program(String name, boolean open, AtomicInteger acquired,
            AtomicInteger released, Runnable beforeAnalysis) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[]{Program.class},
            (proxy, method, args) -> switch(method.getName()) {
                case "getName" -> name;
                case "addConsumer" -> { acquired.incrementAndGet(); yield open; }
                case "release" -> { released.incrementAndGet(); yield null; }
                case "getOptions" -> { beforeAnalysis.run(); throw new IllegalStateException("Fixture analysis failure"); }
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> name;
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }
    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().getFirst()).text();
    }
    private static class TestBackend extends GhidrAssistMCPBackend {
        List<Program> programs = List.of();
        @Override public Program getCurrentProgram() { return null; }
        @Override public List<Program> getAllOpenPrograms() { return programs; }
    }
}
