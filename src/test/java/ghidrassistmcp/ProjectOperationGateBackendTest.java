package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

class ProjectOperationGateBackendTest {
    private final TestBackend backend = new TestBackend();
    private final CountDownLatch releaseWorker = new CountDownLatch(1);
    private final ExecutorService client = Executors.newSingleThreadExecutor();
    private final AtomicInteger transitions = new AtomicInteger();

    ProjectOperationGateBackendTest() {
        backend.registerTool(new ProbeTool("transition_probe", true, false,
            () -> { transitions.incrementAndGet(); return success(); }));
    }

    @AfterEach
    void shutdown() throws Exception {
        releaseWorker.countDown();
        client.shutdownNow();
        assertTrue(client.awaitTermination(2, TimeUnit.SECONDS));
        backend.shutdown();
    }

    @Test
    void synchronousCallBlocksTransitionsUntilItReturns() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        backend.registerTool(blockingTool("operation_probe", false, false, entered));
        var running = client.submit(() -> backend.callTool("operation_probe", Map.of()));
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        assertTrue(backend.callTool("transition_probe", Map.of()).isError());
        assertEquals(0, transitions.get());

        releaseWorker.countDown();
        assertSuccessful(running.get(2, TimeUnit.SECONDS));
        assertSuccessful(backend.callTool("transition_probe", Map.of()));
        assertEquals(1, transitions.get());
    }

    @Test
    void programLeaseIsReleasedBeforeNormalAdmissionEnds() throws Exception {
        CountDownLatch releasingProgram = new CountDownLatch(1);
        backend.current = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> "leased-program";
                case "getDomainFile" -> null;
                case "isClosed" -> false;
                case "addConsumer" -> true;
                case "release" -> {
                    releasingProgram.countDown();
                    awaitUninterruptibly(releaseWorker);
                    yield null;
                }
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "FakeProgram[leased-program]";
                default -> throw new UnsupportedOperationException(method.getName());
            });
        backend.registerTool(new ProbeTool("leased_probe", false, false,
            ProjectOperationGateBackendTest::success) {
                @Override public boolean requiresProgramContext() { return true; }
            });
        var running = client.submit(() -> backend.callTool("leased_probe", Map.of()));
        assertTrue(releasingProgram.await(2, TimeUnit.SECONDS));
        assertTrue(backend.callTool("transition_probe", Map.of()).isError());
        releaseWorker.countDown();
        assertSuccessful(running.get(2, TimeUnit.SECONDS));
        assertSuccessful(backend.callTool("transition_probe", Map.of()));
    }

    @Test
    void runningCancellationBlocksTransitionsUntilTheWorkerPhysicallyStops() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        backend.registerTool(blockingTool("async_probe", false, true, entered));
        assertSuccessful(backend.callTool("async_probe", Map.of()));
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        McpTask task = backend.getTaskManager().listTasks(null).stream()
            .filter(candidate -> candidate.getToolName().equals("async_probe"))
            .findFirst().orElseThrow();
        assertTrue(backend.getTaskManager().cancelTask(task.getTaskId()));
        assertEquals(McpTask.Status.CANCELLED, task.getStatus());
        assertTrue(backend.callTool("transition_probe", Map.of()).isError());
        assertEquals(0, transitions.get());

        releaseWorker.countDown();
        backend.getTaskManager().shutdown();
        assertSuccessful(backend.callTool("transition_probe", Map.of()));
    }

    @Test
    void queuedCancellationReleasesTheAdditionalAdmissionPermit() throws Exception {
        CountDownLatch entered = new CountDownLatch(4);
        for (int i = 0; i < 4; i++) {
            backend.submitTask("blocking_worker", Map.of(), null, task -> {
                entered.countDown();
                awaitUninterruptibly(releaseWorker);
                return success();
            });
        }
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        AtomicInteger queuedExecutions = new AtomicInteger();
        McpTask queued = backend.submitTask("queued_worker", Map.of(), null, task -> {
            queuedExecutions.incrementAndGet();
            return success();
        });
        assertTrue(backend.getTaskManager().cancelTask(queued.getTaskId()));
        assertTrue(backend.callTool("transition_probe", Map.of()).isError());
        releaseWorker.countDown();
        backend.getTaskManager().shutdown();

        assertEquals(0, queuedExecutions.get());
        assertSuccessful(backend.callTool("transition_probe", Map.of()));
    }

    @Test
    void rejectedSubmissionDoesNotLeakItsAdmissionPermit() {
        backend.getTaskManager().shutdown();
        assertThrows(RejectedExecutionException.class, () -> backend.submitTask(
            "rejected_worker", Map.of(), null, task -> success()));
        assertSuccessful(backend.callTool("transition_probe", Map.of()));
    }

    @Test
    void activeTransitionRejectsToolTaskResourceAndPromptWorkWithoutWaiting() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        backend.registerTool(blockingTool("blocking_transition", true, false, entered));
        backend.registerTool(new ProbeTool("operation_probe", false, false,
            ProjectOperationGateBackendTest::success));
        backend.getResourceRegistry().registerResource(new ProbeResource());
        var running = client.submit(() -> backend.callTool("blocking_transition", Map.of()));
        assertTrue(entered.await(2, TimeUnit.SECONDS));

        assertTrue(backend.callTool("operation_probe", Map.of()).isError());
        assertTrue(backend.callTool("transition_probe", Map.of()).isError());
        assertThrows(IllegalStateException.class, () -> backend.submitTask(
            "task_probe", Map.of(), null, task -> success()));
        assertThrows(IllegalStateException.class, () -> backend.readResource("ghidra://test/gate"));
        assertThrows(IllegalStateException.class, () -> backend.generatePrompt(new ProbePrompt(), Map.of()));

        releaseWorker.countDown();
        assertSuccessful(running.get(2, TimeUnit.SECONDS));
        assertSuccessful(backend.callTool("operation_probe", Map.of()));
        assertEquals("resource", backend.readResource("ghidra://test/gate"));
        assertEquals("prompt", backend.generatePrompt(new ProbePrompt(), Map.of()).description());
    }

    @Test
    void failureAndInvalidArgumentsReleaseExclusiveAdmission() {
        backend.registerTool(new ProbeTool("failing_transition", true, false,
            () -> { throw new IllegalStateException("expected failure"); }));
        assertTrue(backend.callTool("failing_transition", Map.of()).isError());
        assertTrue(backend.callTool("transition_probe", Map.of("typo", true)).isError());
        assertSuccessful(backend.callTool("transition_probe", Map.of()));
        assertEquals(1, transitions.get());
    }

    private ProbeTool blockingTool(String name, boolean transition, boolean async,
            CountDownLatch entered) {
        return new ProbeTool(name, transition, async, () -> {
            entered.countDown();
            awaitUninterruptibly(releaseWorker);
            return success();
        });
    }

    private static void assertSuccessful(McpSchema.CallToolResult result) {
        assertFalse(Boolean.TRUE.equals(result.isError()));
    }

    private static McpSchema.CallToolResult success() {
        return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("complete").build()).build();
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        try {
            while (true) {
                try {
                    latch.await();
                    return;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static class TestBackend extends GhidrAssistMCPBackend {
        private volatile Program current;
        @Override public Program getCurrentProgram() { return current; }
    }

    private static class ProbeTool implements McpTool {
        private final String name;
        private final boolean transition;
        private final boolean async;
        private final Supplier<McpSchema.CallToolResult> executor;

        ProbeTool(String name, boolean transition, boolean async,
                Supplier<McpSchema.CallToolResult> executor) {
            this.name = name;
            this.transition = transition;
            this.async = async;
            this.executor = executor;
        }
        @Override public String getName() { return name; }
        @Override public String getDescription() { return "Lifecycle concurrency test fixture"; }
        @Override public boolean requiresProgramContext() { return false; }
        @Override public boolean supportsProgramSelection() { return false; }
        @Override public boolean isProjectLifecycleOperation() { return transition; }
        @Override public boolean isLongRunning() { return async; }
        @Override public JsonSchema getInputSchema() {
            return new JsonSchema("object", Map.of(), List.of(), false, null, null);
        }
        @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
            return executor.get();
        }
    }

    private static class ProbeResource implements McpResource {
        @Override public String getUriPattern() { return "ghidra://test/gate"; }
        @Override public String getName() { return "gate_resource"; }
        @Override public String getDescription() { return "Lifecycle resource test fixture"; }
        @Override public String getMimeType() { return "text/plain"; }
        @Override public boolean canHandle(String uri) { return getUriPattern().equals(uri); }
        @Override public Map<String, String> extractParams(String uri) { return Map.of(); }
        @Override public String readContent(Program program, Map<String, String> params) { return "resource"; }
    }

    private static class ProbePrompt implements McpPrompt {
        @Override public String getName() { return "gate_prompt"; }
        @Override public String getDescription() { return "Lifecycle prompt test fixture"; }
        @Override public List<McpSchema.PromptArgument> getArguments() { return List.of(); }
        @Override public McpSchema.GetPromptResult generatePrompt(Map<String, String> arguments, Program program) {
            return McpSchema.GetPromptResult.builder(List.of()).description("prompt").build();
        }
    }
}
