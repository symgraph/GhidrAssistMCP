package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

import org.junit.jupiter.api.Test;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;

class GetPseudocodeBatchToolTest {
    @Test void synchronousBackendBatchMatchesTheActualAdvertisedFinalSchema() {
        Fixture fixture = new Fixture();
        GhidrAssistMCPBackend backend = backend(fixture);
        try {
            // Capture the built-in catalog contract before replacing its native decompiler seam.
            Map<String, Object> schema = advertisedSchema(backend);
            backend.setAsyncExecutionEnabled(false);
            backend.registerTool(tool(fixture, success("void backendBatch() {}\n"), new AtomicInteger()));
            var response = backend.callTool("get_pseudocode_batch",
                Map.of("functions", List.of("0x1000"), "program_name", Fixture.PROJECT_PATH));

            assertFalse(Boolean.TRUE.equals(response.isError()), text(response));
            assertFalse(metadata(response).containsKey("task_id"));
            assertEquals(1, metadata(response).get("succeeded"));
            assertEquals(true, items(response).get(0).get("complete"));
            assertTrue(text(response).contains("void backendBatch() {}"));
            var validation = McpJsonDefaults.getSchemaValidator().validate(schema, metadata(response));
            assertTrue(validation.valid(), validation.errorMessage());
        } finally { backend.shutdown(); }
    }

    @Test void slowBackendHandleAndPolledBatchMatchTheActualAdvertisedSchema() throws Exception {
        Fixture fixture = new Fixture();
        GhidrAssistMCPBackend backend = backend(fixture);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        FakeSession session = new FakeSession((function, monitor) -> {
            entered.countDown();
            try {
                if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Test session was not released");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted test session", interrupted);
            }
            return GetPseudocodeBatchTool.Decompilation.success("void delayedBatch() {}\n");
        });
        try {
            Map<String, Object> schema = advertisedSchema(backend);
            backend.registerTool(tool(fixture, session, new AtomicInteger()));
            var submitted = backend.callTool("get_pseudocode_batch",
                Map.of("functions", List.of("0x1000"), "program_name", Fixture.PROJECT_PATH));
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            Map<String, Object> handle = metadata(submitted);
            assertTrue(handle.containsKey("task_id"), handle.toString());
            assertFalse(handle.containsKey("results"));
            var validation = McpJsonDefaults.getSchemaValidator().validate(schema, handle);
            assertTrue(validation.valid(), validation.errorMessage());

            McpTask task = backend.getTaskManager().getTask((String) handle.get("task_id"));
            release.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (task.getResult() == null && System.nanoTime() < deadline) LockSupport.parkNanos(1_000_000);
            assertNotNull(task.getResult(), "The asynchronous batch did not finish");
            assertEquals(McpTask.Status.COMPLETED, task.getStatus());
            var completed = backend.callTool("get_task_status", Map.of("task_id", task.getTaskId()));
            assertFalse(Boolean.TRUE.equals(completed.isError()), text(completed));
            assertFalse(metadata(completed).containsKey("task_id"));
            assertEquals(1, metadata(completed).get("succeeded"));
            assertTrue(text(completed).contains("void delayedBatch() {}"));
            validation = McpJsonDefaults.getSchemaValidator().validate(schema, metadata(completed));
            assertTrue(validation.valid(), validation.errorMessage());
        } finally { release.countDown(); backend.shutdown(); }
    }

    @Test void defaultsToCompleteCodeOnceWithProgramIdentityAndOneSession() {
        Fixture fixture = new Fixture();
        String first = "int first() {\n  return 123456789; /* SOURCE_ONE */\n}\n";
        String second = "int second() { return 42; /* SOURCE_TWO */ }\n";
        FakeSession session = new FakeSession((function, monitor) ->
            GetPseudocodeBatchTool.Decompilation.success(function.getEntryPoint().getOffset() == 0x1000 ? first : second));
        AtomicInteger opens = new AtomicInteger();
        GetPseudocodeBatchTool tool = tool(fixture, session, opens);

        var response = tool.execute(Map.of("functions", List.of("0x1000", "0x2000")), fixture.program);

        assertFalse(response.isError());
        assertEquals(1, opens.get());
        assertEquals(1, session.closes);
        assertEquals(List.of(0x1000L, 0x2000L), session.calls);
        assertEquals(1, response.content().size());
        String text = text(response);
        assertEquals(1, occurrences(text, first));
        assertEquals(1, occurrences(text, second));
        assertEquals(1, occurrences(text, Fixture.PROJECT_PATH));
        assertEquals("test-program", metadata(response).get("program") instanceof Map<?, ?> identity ? identity.get("name") : null);
        assertFalse(metadata(response).toString().contains("SOURCE_ONE"));
        assertFalse(metadata(response).toString().contains("SOURCE_TWO"));
        assertEquals(2, metadata(response).get("succeeded"));
        assertEquals(0, metadata(response).get("failed"));
        assertEquals("demo::first", items(response).get(0).get("name"));
        assertEquals("00001000", items(response).get(0).get("address"));
        assertPage(items(response).get(0), 1, 3, 3, true);
        assertTrue(McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), metadata(response)).valid());
    }

    @Test void preservesOrderAndReportsMissingTimeoutAndThrownErrorsAlongsideSuccess() {
        Fixture fixture = new Fixture();
        FakeSession session = new FakeSession((function, monitor) -> {
            long address = function.getEntryPoint().getOffset();
            if (address == 0x1000) return GetPseudocodeBatchTool.Decompilation.failure("timeout", "Decompilation timed out");
            if (address == 0x3000) throw new IllegalStateException("native failure");
            return GetPseudocodeBatchTool.Decompilation.success("void good() {}\n");
        });
        var response = tool(fixture, session, new AtomicInteger()).execute(Map.of("functions",
            List.of("0x9999", "0x1000", "0x3000", "0x2000")), fixture.program);

        assertFalse(response.isError(), "A partial failure must not discard later successful source");
        assertEquals(List.of("0x9999", "0x1000", "0x3000", "0x2000"),
            items(response).stream().map(item -> item.get("identifier")).toList());
        assertEquals("not_found", failure(items(response).get(0)).get("code"));
        assertEquals("timeout", failure(items(response).get(1)).get("code"));
        assertEquals("decompilation_error", failure(items(response).get(2)).get("code"));
        assertEquals("native failure", failure(items(response).get(2)).get("message"));
        assertEquals("success", items(response).get(3).get("status"));
        assertEquals(1, metadata(response).get("succeeded"));
        assertEquals(3, metadata(response).get("failed"));
        assertTrue(text(response).contains("void good() {}"));
        assertEquals(1, session.closes);
    }

    @Test void reusesDecompilationForRepeatedEntryAndContainingAddress() {
        Fixture fixture = new Fixture();
        FakeSession session = success("void one() {}\n");
        var response = tool(fixture, session, new AtomicInteger()).execute(Map.of("functions",
            List.of("0x1000", "0x1004", "0x1000")), fixture.program);

        assertEquals(List.of(0x1000L), session.calls);
        assertEquals(3, items(response).size());
        assertEquals(3, metadata(response).get("succeeded"));
        assertTrue(items(response).stream().allMatch(item -> "00001000".equals(item.get("address"))));
    }

    @Test void pagesByOneBasedLinesAndPreservesCrLfAndExplicitCompleteness() {
        Fixture fixture = new Fixture();
        String source = "first-line\r\nsecond-line\r\nthird-line\r\n";
        var response = tool(fixture, success(source), new AtomicInteger()).execute(Map.of(
            "functions", List.of("0x1000"), "start_line", 2, "max_lines", 1), fixture.program);

        assertFalse(response.isError());
        assertPage(items(response).get(0), 2, 2, 3, false);
        assertTrue(text(response).contains("second-line\r\n"));
        assertFalse(text(response).contains("first-line"));
        assertFalse(text(response).contains("third-line"));
        assertTrue(text(response).contains("lines 2-2/3; truncated"));
    }

    @Test void pageAtLastLineAndUnlimitedRemainingLinesHaveAccurateBounds() {
        Fixture fixture = new Fixture();
        GetPseudocodeBatchTool tool = tool(fixture, success("one\ntwo\nthree"), new AtomicInteger());
        var last = tool.execute(Map.of("functions", List.of("0x1000"), "start_line", 3, "max_lines", 1), fixture.program);
        assertPage(items(last).get(0), 3, 3, 3, false);
        var tail = tool.execute(Map.of("functions", List.of("0x1000"), "start_line", 2), fixture.program);
        assertPage(items(tail).get(0), 2, 3, 3, false);
        var oversized = tool.execute(Map.of("functions", List.of("0x1000"), "start_line", 2,
            "max_lines", Integer.MAX_VALUE), fixture.program);
        assertPage(items(oversized).get(0), 2, 3, 3, false);
        var whole = tool.execute(Map.of("functions", List.of("0x1000"), "max_lines", 3), fixture.program);
        assertPage(items(whole).get(0), 1, 3, 3, true);
    }

    @Test void startPastEndIsExplicitPerItemErrorRatherThanSilentEmptyCode() {
        Fixture fixture = new Fixture();
        var response = tool(fixture, success("one\ntwo\n"), new AtomicInteger()).execute(Map.of(
            "functions", List.of("0x1000"), "start_line", 3), fixture.program);
        Map<String, Object> item = items(response).get(0);
        assertTrue(response.isError());
        assertEquals("line_out_of_range", failure(item).get("code"));
        assertEquals(2, item.get("total_lines"));
        assertEquals(0, item.get("returned_lines"));
        assertEquals(true, item.get("decompilation_complete"));
        assertEquals(false, item.get("complete"));
        assertEquals(true, item.get("truncated"));
        assertTrue(text(response).contains("start_line 3 exceeds total_lines 2"));
    }

    @Test void malformedBatchAndPagingAreRejectedBeforeOpeningAnyDecompiler() {
        Fixture fixture = new Fixture();
        AtomicInteger opens = new AtomicInteger();
        GetPseudocodeBatchTool tool = tool(fixture, success("unused"), opens);
        List<Map<String, Object>> invalid = new ArrayList<>();
        invalid.add(Map.of());
        invalid.add(Map.of("functions", "0x1000"));
        invalid.add(Map.of("functions", List.of()));
        invalid.add(Map.of("functions", List.of(" ")));
        invalid.add(Map.of("functions", List.of(42)));
        for (Object bad : List.of(0, -1, 1.5, "2", 2147483648L, Double.NaN)) {
            invalid.add(Map.of("functions", List.of("0x1000"), "start_line", bad));
            invalid.add(Map.of("functions", List.of("0x1000"), "max_lines", bad));
        }
        for (var arguments : invalid) assertTrue(tool.execute(arguments, fixture.program).isError(), arguments.toString());
        assertEquals(0, opens.get());
    }

    @Test void largeBatchReturnsEveryFunctionInOrderWithOneSessionAndNoCountCeilings() {
        Fixture fixture = new Fixture(40);
        AtomicInteger opens = new AtomicInteger();
        FakeSession session = new FakeSession((function, monitor) ->
            GetPseudocodeBatchTool.Decompilation.success("void batch_" + function.getEntryPoint() + "() {\n}\n"));
        GetPseudocodeBatchTool tool = tool(fixture, session, opens);
        List<String> requested = new ArrayList<>();
        List<Long> expectedCalls = new ArrayList<>();
        for (int index = 40; index >= 1; index--) {
            long address = index * 0x1000L;
            requested.add("0x" + Long.toHexString(address));
            expectedCalls.add(address);
        }

        var response = tool.execute(Map.of("functions", requested), fixture.program);

        assertFalse(response.isError());
        assertEquals(1, opens.get());
        assertEquals(1, session.closes);
        assertEquals(expectedCalls, session.calls);
        assertEquals(40, metadata(response).get("total"));
        assertEquals(40, metadata(response).get("succeeded"));
        assertEquals(0, metadata(response).get("failed"));
        assertEquals(requested, items(response).stream().map(item -> item.get("identifier")).toList());
        for (int index = 0; index < requested.size(); index++) {
            Map<String, Object> item = items(response).get(index);
            assertEquals(index, item.get("index"));
            assertPage(item, 1, 2, 2, true);
            String code = "void batch_" + item.get("address") + "() {\n}\n";
            assertEquals(1, occurrences(text(response), code));
        }
        assertFalse(((Map<?, ?>) tool.getInputSchema().properties().get("functions")).containsKey("maxItems"));
        Map<?, ?> outputProperties = (Map<?, ?>) tool.getOutputSchema().get("properties");
        assertFalse(((Map<?, ?>) outputProperties.get("total")).containsKey("maximum"));
        assertFalse(((Map<?, ?>) outputProperties.get("results")).containsKey("maxItems"));
        var validation = McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), metadata(response));
        assertTrue(validation.valid(), validation.errorMessage());
    }

    @Test void missingOrClosedProgramIsClearError() {
        Fixture fixture = new Fixture();
        AtomicInteger opens = new AtomicInteger();
        GetPseudocodeBatchTool tool = tool(fixture, success("void f() {}"), opens);
        var arguments = Map.<String, Object>of("functions", List.of("0x1000"));
        assertTrue(tool.execute(arguments, null).isError());
        fixture.closed = true;
        assertTrue(tool.execute(arguments, fixture.program).isError());
        assertEquals(0, opens.get());
    }

    @Test void cancellationBeforeStartingReturnsOneExplicitResultPerRequestWithoutSession() {
        Fixture fixture = new Fixture();
        AtomicInteger opens = new AtomicInteger();
        GetPseudocodeBatchTool tool = tool(fixture, success("unused"), opens);
        McpTask task = new McpTask(tool.getName(), Map.of());
        task.markCancelled();
        var response = tool.execute(Map.of("functions", List.of("0x1000", "0x2000")), fixture.program, null, task);
        assertTrue(response.isError());
        assertEquals(2, items(response).size());
        assertTrue(items(response).stream().allMatch(item -> "cancelled".equals(item.get("status"))));
        assertEquals(2, metadata(response).get("cancelled"));
        assertEquals(0, opens.get());
    }

    @Test void cancellationDuringBatchRetainsPriorCodeAndMarksRemainingItems() {
        Fixture fixture = new Fixture();
        McpTask task = new McpTask("get_pseudocode_batch", Map.of());
        FakeSession session = new FakeSession((function, monitor) -> {
            if (function.getEntryPoint().getOffset() == 0x2000) task.markCancelled();
            return GetPseudocodeBatchTool.Decompilation.success("PRESERVED_SOURCE\n");
        });
        var response = tool(fixture, session, new AtomicInteger()).execute(Map.of("functions",
            List.of("0x1000", "0x2000", "0x3000")), fixture.program, null, task);
        assertTrue(response.isError());
        assertEquals(List.of("success", "cancelled", "cancelled"),
            items(response).stream().map(item -> item.get("status")).toList());
        assertEquals(1, metadata(response).get("succeeded"));
        assertEquals(2, metadata(response).get("cancelled"));
        assertEquals(1, occurrences(text(response), "PRESERVED_SOURCE"));
        assertEquals(List.of(0x1000L, 0x2000L), session.calls);
        assertEquals(1, session.closes);
    }

    @Test void initializationFailureIsReportedForEveryResolvedItemWithoutRepeatedOpen() {
        Fixture fixture = new Fixture();
        AtomicInteger opens = new AtomicInteger();
        GetPseudocodeBatchTool tool = new GetPseudocodeBatchTool(program -> {
            opens.incrementAndGet();
            throw new IllegalStateException("native startup failed");
        });
        var response = tool.execute(Map.of("functions", List.of("0x1000", "0x2000")), fixture.program);
        assertTrue(response.isError());
        assertEquals(1, opens.get());
        assertTrue(items(response).stream().allMatch(item ->
            "decompiler_initialization".equals(failure(item).get("code"))));
    }

    @Test void blankDecompilerOutputIsNeverMarkedCompleteAndBatchCacheIsDisabled() {
        Fixture fixture = new Fixture();
        GetPseudocodeBatchTool tool = new GetPseudocodeBatchTool(program -> success(" \n"));
        var response = tool.execute(Map.of("functions", List.of("0x1000")), fixture.program);
        assertTrue(response.isError());
        assertEquals("empty_code", failure(items(response).get(0)).get("code"));
        assertEquals(false, items(response).get(0).get("complete"));
        assertFalse(tool.isCacheable(), "Partial failures must not be replayed from a cross-request cache");
        assertTrue(tool.isReadOnly());
        assertTrue(tool.isLongRunning());
        assertTrue(tool.supportsRequestMonitoring());
    }

    @Test void monitoredProgressCountsAliasesAndErrorsWithoutNativeCounterResets() {
        Fixture fixture = new Fixture();
        RecordingMonitor monitor = new RecordingMonitor();
        FakeSession session = new FakeSession((function, nativeMonitor) -> {
            nativeMonitor.initialize(999);
            nativeMonitor.setProgress(800);
            nativeMonitor.setMessage("native phase");
            return function.getEntryPoint().getOffset() == 0x2000
                ? GetPseudocodeBatchTool.Decompilation.failure("timeout", "timed out")
                : GetPseudocodeBatchTool.Decompilation.success("void complete() {}\n");
        });
        AtomicInteger opens = new AtomicInteger();
        var response = tool(fixture, session, opens).executeMonitored(Map.of("functions",
            List.of("0x1000", "0x1004", "0x9999", "0x2000")), fixture.program, null, monitor);

        assertFalse(response.isError());
        assertEquals(List.of(4L), monitor.initializations);
        assertEquals(List.of(0L, 1L, 2L, 3L, 4L), monitor.progress);
        assertEquals(List.of("Decompiling 1/4: 0x1000", "Decompiling 2/4: 0x1004",
            "Decompiling 3/4: 0x9999", "Decompiling 4/4: 0x2000"), monitor.messages);
        assertEquals(List.of(0x1000L, 0x2000L), session.calls);
        assertEquals(2, metadata(response).get("succeeded"));
        assertEquals(2, metadata(response).get("failed"));
        assertEquals(1, opens.get());
        assertEquals(1, session.closes);
        assertEquals(0, monitor.listeners.size());
    }

    private static GetPseudocodeBatchTool tool(Fixture fixture, FakeSession session, AtomicInteger opens) {
        return new GetPseudocodeBatchTool(program -> {
            assertSame(fixture.program, program);
            opens.incrementAndGet();
            return session;
        });
    }
    private static GhidrAssistMCPBackend backend(Fixture fixture) {
        return new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return fixture.program; }
            @Override public List<Program> getAllOpenPrograms() { return List.of(fixture.program); }
        };
    }
    private static Map<String, Object> advertisedSchema(GhidrAssistMCPBackend backend) {
        var schema = backend.getAvailableTools().stream()
            .filter(tool -> tool.name().equals("get_pseudocode_batch"))
            .findFirst().orElseThrow().outputSchema();
        assertNotNull(schema, "The native batch output schema must survive catalog registration");
        assertEquals(2, ((List<?>) schema.get("oneOf")).size(), "Advertise final output and async handles");
        return schema;
    }
    private static FakeSession success(String code) {
        return new FakeSession((function, monitor) -> GetPseudocodeBatchTool.Decompilation.success(code));
    }
    private static final class FakeSession implements GetPseudocodeBatchTool.BatchSession {
        final BiFunction<Function, TaskMonitor, GetPseudocodeBatchTool.Decompilation> operation;
        final List<Long> calls = new ArrayList<>();
        int closes;
        FakeSession(BiFunction<Function, TaskMonitor, GetPseudocodeBatchTool.Decompilation> operation) { this.operation = operation; }
        @Override public GetPseudocodeBatchTool.Decompilation decompile(Function function, TaskMonitor monitor) {
            calls.add(function.getEntryPoint().getOffset());
            return operation.apply(function, monitor);
        }
        @Override public void close() { closes++; }
    }
    private static final class RecordingMonitor extends TaskMonitorAdapter {
        final List<CancelledListener> listeners = new CopyOnWriteArrayList<>();
        final List<Long> initializations = new ArrayList<>();
        final List<Long> progress = new ArrayList<>();
        final List<String> messages = new ArrayList<>();
        volatile boolean cancelled;
        @Override public void initialize(long max) { initializations.add(max); }
        @Override public void setProgress(long value) { progress.add(value); }
        @Override public void setMessage(String message) { messages.add(message); }
        @Override public boolean isCancelled() { return cancelled; }
        @Override public void addCancelledListener(CancelledListener listener) { listeners.add(listener); }
        @Override public void removeCancelledListener(CancelledListener listener) { listeners.remove(listener); }
        @Override public void cancel() { cancelled = true; listeners.forEach(CancelledListener::cancelled); }
    }
    private static void assertPage(Map<String, Object> item, int first, int last, int total, boolean complete) {
        assertEquals(true, item.get("decompilation_complete"));
        assertEquals(first, item.get("start_line"));
        assertEquals(last, item.get("end_line"));
        assertEquals(total, item.get("total_lines"));
        assertEquals(last - first + 1, item.get("returned_lines"));
        assertEquals(complete, item.get("complete"));
        assertEquals(!complete, item.get("truncated"));
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> metadata(McpSchema.CallToolResult response) {
        return (Map<String, Object>) response.structuredContent();
    }
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> items(McpSchema.CallToolResult response) {
        return (List<Map<String, Object>>) metadata(response).get("results");
    }
    @SuppressWarnings("unchecked")
    private static Map<String, String> failure(Map<String, Object> item) { return (Map<String, String>) item.get("error"); }
    private static String text(McpSchema.CallToolResult response) {
        return ((McpSchema.TextContent) response.content().get(0)).text();
    }
    private static int occurrences(String text, String needle) {
        return (text.length() - text.replace(needle, "").length()) / needle.length();
    }

    private static final class Fixture {
        static final String PROJECT_PATH = "/test-architecture/test-program";
        final AddressSpace space = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        final Map<Long, Function> functions = new java.util.HashMap<>();
        boolean closed;
        final Program program;
        Fixture() { this(3); }
        Fixture(int functionCount) {
            SymbolIterator empty = fake(SymbolIterator.class, (method, args) -> switch (method) {
                case "hasNext" -> false;
                case "iterator" -> null;
                default -> throw new UnsupportedOperationException(method);
            });
            SymbolTable symbols = fake(SymbolTable.class, (method, args) -> empty);
            FunctionManager manager = fake(FunctionManager.class, (method, args) -> {
                long offset = ((Address) args[0]).getOffset();
                return functions.get(method.equals("getFunctionContaining") && offset == 0x1004 ? 0x1000 : offset);
            });
            AddressFactory addresses = fake(AddressFactory.class, (method, args) -> {
                if (method.equals("getDefaultAddressSpace")) return space;
                if (method.equals("getAddressSpace")) return null;
                if (!method.equals("getAddress")) throw new UnsupportedOperationException(method);
                try { return space.getAddress(Long.parseUnsignedLong(((String) args[0]).replaceFirst("^0[xX]", ""), 16)); }
                catch (NumberFormatException e) { return null; }
            });
            DomainFile file = fake(DomainFile.class, (method, args) -> method.equals("getPathname") ? PROJECT_PATH : null);
            program = fake(Program.class, (method, args) -> switch (method) {
                case "getName" -> "test-program";
                case "getDomainFile" -> file;
                case "getFunctionManager" -> manager;
                case "getAddressFactory" -> addresses;
                case "getSymbolTable" -> symbols;
                case "isClosed" -> closed;
                case "addConsumer" -> true;
                case "release" -> null;
                default -> throw new UnsupportedOperationException(method);
            });
            for (int i = 1; i <= functionCount; i++) {
                long offset = i * 0x1000L;
                String name = i == 1 ? "demo::first" : i == 2 ? "demo::second"
                    : i == 3 ? "demo::third" : "demo::function" + i;
                functions.put(offset, fake(Function.class, (method, args) -> switch (method) {
                    case "getEntryPoint" -> space.getAddress(offset);
                    case "getName" -> name;
                    default -> throw new UnsupportedOperationException(method);
                }));
            }
        }
    }
    private interface Answer { Object invoke(String method, Object[] args) throws Throwable; }
    private static <T> T fake(Class<T> type, Answer answer) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
            (proxy, method, args) -> {
                if (method.getDeclaringClass() == Object.class) {
                    return switch (method.getName()) {
                        case "equals" -> proxy == args[0];
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "toString" -> "Fake" + type.getSimpleName();
                        default -> throw new UnsupportedOperationException(method.getName());
                    };
                }
                return answer.invoke(method.getName(), args);
            }));
    }
}
