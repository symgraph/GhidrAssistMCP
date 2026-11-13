package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** SDK-native progress over both HTTP transports, without opening a Ghidra database. */
@Timeout(40)
class NativeProgressIntegrationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int STEPS = 3;
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    enum Transport { STREAMABLE_HTTP, LEGACY_SSE }

    @ParameterizedTest
    @EnumSource(Transport.class)
    void progressKeepsTokenTypesAndFullResultsOnInitialAndRefreshedTools(Transport transport)
            throws Exception {
        try (Fixture fixture = new Fixture(); WireClient wire = fixture.connect(transport)) {
            fixture.addProbe("refreshed_probe");
            for (int index = 0; index < 2; index++) {
                Object token = index == 0 ? "source-progress" : 0;
                String id = "success-" + index;
                Run run = fixture.run(id);
                wire.call(id, index == 1 ? "refreshed_probe" : "monitored_probe", id, token);
                await(run.entered, "The progress operation did not start");
                wire.awaitProgress(token, 0);
                assertEquals(1, fixture.activeConsumers());
                assertEquals(0, run.closes.get());
                assertTrue(Boolean.TRUE.equals(fixture.backend.callTool("transition_probe", Map.of()).isError()),
                    "Project admission must remain held while native work is active");

                run.release.countDown();
                JsonNode response = wire.response(id);
                assertFullResult(response, id);
                await(run.closed, "The operation did not close its native resource");
                awaitReleased(fixture, index + 1);
                assertEquals(1, run.closes.get());
                assertEquals(1, run.monitoredCalls.get());
                assertEquals(0, run.unmonitoredCalls.get());
                assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty(),
                    "Native progress requests must not spawn detached tasks");

                // A new terminal value would bypass rate limiting if this monitor
                // were still open, so coalescing cannot hide an unwanted late event.
                run.monitor.setMaximum(STEPS + 1);
                run.monitor.setProgress(STEPS + 1);
                wire.fence("after-" + id);
                assertEquals(List.of(response), wire.responses(id));
                assertProgress(wire, token, response);
            }
            assertEquals(2, fixture.adds.get());
            assertEquals(2, fixture.releases.get());
            assertFalse(Boolean.TRUE.equals(fixture.backend.callTool("transition_probe", Map.of()).isError()));
        }
    }

    @ParameterizedTest
    @EnumSource(Transport.class)
    void noProgressTokenReturnsFullInFlightResultWithoutJobsOrNotifications(Transport transport)
            throws Exception {
        try (Fixture fixture = new Fixture(); WireClient wire = fixture.connect(transport)) {
            assertTrue(fixture.backend.isAsyncExecutionEnabled(), "This must exercise the normal job-enabled configuration");
            Run run = fixture.run("untokened-work");
            wire.call("untokened-call", "monitored_probe", run.name, null);
            await(run.entered, "The in-flight operation did not start");
            assertTrue(wire.responses("untokened-call").isEmpty(), "The response must wait for the complete result");
            assertEquals(0, run.unmonitoredCalls.get());
            assertEquals(1, run.monitoredCalls.get());
            assertSame(TaskMonitor.DUMMY, run.monitor, "Tokenless requests use the monitored path without a notification sender");
            assertEquals(1, fixture.activeConsumers());
            assertEquals(0, run.closes.get());
            assertTrue(wire.allProgress().isEmpty());
            assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty(), "No progress token must not create a polling job");

            run.release.countDown();
            JsonNode response = wire.response("untokened-call");
            assertFullResult(response, run.name);
            await(run.closed, "The in-flight operation did not close its native resource");
            awaitNoConsumers(fixture);
            wire.fence("after-untokened-work");
            assertEquals(List.of(response), wire.responses("untokened-call"));
            assertTrue(wire.allProgress().isEmpty(), "A call without a progress token must emit no progress");
            assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty());
            assertEquals(1, run.closes.get());
            assertEquals(fixture.adds.get(), fixture.releases.get());
            assertFalse(Boolean.TRUE.equals(fixture.backend.callTool("transition_probe", Map.of()).isError()));
        }
    }

    @ParameterizedTest
    @EnumSource(Transport.class)
    void canonicalAnalyzeProgramReportsProgressWithoutChangingItsHeadlessFailure(Transport transport)
            throws Exception {
        try (Fixture fixture = new Fixture(); WireClient wire = fixture.connect(transport)) {
            Map<String, Object> arguments = Map.of("options", Map.of("fixture", true));
            fixture.backend.setAsyncExecutionEnabled(false);
            McpSchema.CallToolResult baseline = fixture.backend.callTool("analyze_program", arguments);
            fixture.backend.setAsyncExecutionEnabled(true);
            assertTrue(Boolean.TRUE.equals(baseline.isError()));
            assertTrue(((McpSchema.TextContent) baseline.content().getFirst()).text()
                .contains("Analysis failed for monitored-program: Headless fixture analysis failure"));
            assertEquals(0, fixture.activeConsumers());
            int priorAdds = fixture.adds.get();

            fixture.blockAnalysis = true;
            wire.toolCall("canonical-analysis", "analyze_program", arguments, "analysis-progress");
            await(fixture.analysisEntered, "The canonical analysis tool did not enter its existing implementation");
            wire.awaitProgress("analysis-progress", 0);
            assertEquals(2, fixture.activeConsumers(), "Backend and analysis-tool leases must both remain live");
            assertTrue(Boolean.TRUE.equals(fixture.backend.callTool("transition_probe", Map.of()).isError()));
            assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty());

            fixture.analysisRelease.countDown();
            JsonNode response = wire.response("canonical-analysis");
            assertEquals(JSON.valueToTree(baseline), response.path("result"),
                "Adding progress must preserve the canonical tool's original result");
            awaitNoConsumers(fixture);
            wire.fence("after-canonical-analysis");
            assertProgress(wire, "analysis-progress", response, 100);
            assertEquals(priorAdds + 2, fixture.adds.get());
            assertEquals(fixture.adds.get(), fixture.releases.get());
            assertEquals(2, fixture.analysisAttempts.get());
            assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty());
            assertFalse(Boolean.TRUE.equals(fixture.backend.callTool("transition_probe", Map.of()).isError()));
        }
    }

    @ParameterizedTest
    @EnumSource(Transport.class)
    void canonicalRenameBatchPreservesDeferredFailureReportWithAndWithoutTokens(Transport transport) throws Exception {
        try (Fixture fixture = new Fixture(); WireClient wire = fixture.connect(transport)) {
            List<Map<String, Object>> requests = List.of(
                Map.of("target_type", "variable", "identifier", "missingVariables", "variable_name", "first", "new_name", "renamedFirst"),
                Map.of("target_type", "function", "identifier", "", "new_name", "ignored"),
                Map.of("target_type", "variable", "identifier", "missingVariables", "variable_name", "second", "new_name", "renamedSecond"),
                Map.of("target_type", "variable", "identifier", "missingVariables", "new_name", "unused"));
            Map<String, Object> arguments = Map.of("renames", requests);
            assertTrue(fixture.backend.supportsRequestMonitoring("rename_symbols_batch"),
                "The canonical batch wrapper must retain the production opt-in");
            McpSchema.CallToolResult baseline = fixture.backend.callTool("rename_symbols_batch", arguments);
            JsonNode baselineJson = JSON.valueToTree(baseline);
            JsonNode report = renameReport(baselineJson);
            assertEquals(4, report.path("total").asInt());
            assertEquals(0, report.path("succeeded").asInt());
            assertEquals(4, report.path("failed").asInt());
            for (int i = 0; i < requests.size(); i++) {
                JsonNode item = report.path("results").get(i);
                assertEquals(i, item.path("index").asInt());
                assertEquals(requests.get(i).get("new_name"), item.path("new_name").asText());
                assertFalse(item.path("success").asBoolean());
            }
            assertEquals("Function not found: missingVariables", report.path("results").get(0).path("message").asText());
            assertEquals("Function not found: missingVariables", report.path("results").get(2).path("message").asText());

            // Tokenless requests return the same full report without progress notifications.
            wire.toolCall("untokened-rename", "rename_symbols_batch", arguments, null);
            assertEquals(baselineJson, wire.response("untokened-rename").path("result"));
            wire.fence("after-untokened-rename");
            assertTrue(wire.allProgress().isEmpty());
            assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty());

            int priorAdds = fixture.adds.get();
            for (int index = 0; index < 2; index++) {
                Object token = index == 0 ? "rename-progress" : 0;
                String id = "monitored-rename-" + index;
                fixture.renameEntered = new CountDownLatch(1);
                fixture.renameRelease = new CountDownLatch(1);
                fixture.blockRenames = true;
                wire.toolCall(id, "rename_symbols_batch", arguments, token);
                await(fixture.renameEntered, "The canonical tool did not reach its deferred variable group");
                wire.awaitProgress(token, 0);
                assertEquals(1, fixture.activeConsumers(), "The backend lease must survive deferred processing");
                assertTrue(wire.responses(id).isEmpty(), "The full report must wait for deferred variable results");
                assertTrue(wire.progress(token).stream().allMatch(message ->
                    message.path("params").path("progress").asDouble() < 100),
                    "Queued variable renames must not count as completed work");
                assertTrue(Boolean.TRUE.equals(fixture.backend.callTool("transition_probe", Map.of()).isError()));

                fixture.renameRelease.countDown();
                JsonNode response = wire.response(id);
                assertEquals(baselineJson, response.path("result"), "Progress must not change any per-item outcome or order");
                assertEquals(report, renameReport(response.path("result")));
                awaitNoConsumers(fixture);
                wire.fence("after-" + id);
                assertProgress(wire, token, response, 100);
                assertEquals(List.of(response), wire.responses(id));
                assertTrue(fixture.backend.getTaskManager().listTasks(null).isEmpty());
            }
            assertEquals(priorAdds + 2, fixture.adds.get());
            assertEquals(fixture.adds.get(), fixture.releases.get());
        }
    }

    private static JsonNode renameReport(JsonNode result) throws Exception {
        String text = result.path("content").get(0).path("text").asText();
        int start = text.indexOf('{');
        assertTrue(start >= 0, "Missing complete JSON rename report: " + text);
        return JSON.readTree(text.substring(start));
    }

    private static void assertFullResult(JsonNode response, String name) {
        assertFalse(response.has("error"), response.toString());
        JsonNode result = response.path("result");
        assertFalse(result.path("isError").asBoolean(), response.toString());
        assertEquals(name, result.path("structuredContent").path("run").asText());
        assertEquals(STEPS, result.path("structuredContent").path("total").asInt());
        assertTrue(result.path("structuredContent").path("complete").asBoolean());
        assertFalse(result.path("structuredContent").has("task_id"));
        assertEquals(1, result.path("content").size());
        assertTrue(result.path("content").get(0).path("text").asText().endsWith("FULL_SOURCE_" + name));
    }

    private static void assertProgress(WireClient wire, Object token, JsonNode response) {
        assertProgress(wire, token, response, STEPS);
    }

    private static void assertProgress(WireClient wire, Object token, JsonNode response, int total) {
        List<JsonNode> progress = wire.progress(token);
        assertTrue(progress.size() >= 2, "Initial and terminal progress are required: " + progress);
        assertEquals(0.0, progress.getFirst().path("params").path("progress").asDouble());
        assertEquals((double) total, progress.getLast().path("params").path("progress").asDouble());
        int finalPosition = wire.messages.indexOf(response);
        double previous = -1;
        for (JsonNode message : progress) {
            assertEquals(JSON.valueToTree(token), message.path("params").path("progressToken"));
            assertEquals(total, message.path("params").path("total").asInt());
            double value = message.path("params").path("progress").asDouble();
            assertTrue(value > previous && value <= total, "Progress must increase within 0..N");
            previous = value;
            assertTrue(wire.messages.indexOf(message) < finalPosition, "Progress appeared after the final response");
        }
    }

    private static void await(CountDownLatch latch, String failure) throws InterruptedException {
        assertTrue(latch.await(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS), failure);
    }

    private static void awaitReleased(Fixture fixture, int count) throws InterruptedException {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (fixture.releases.get() != count && System.nanoTime() < deadline) {
            fixture.releaseEvents.poll(20, TimeUnit.MILLISECONDS);
        }
        assertEquals(count, fixture.releases.get(), "Program lease was not released after worker cleanup");
    }

    private static void awaitNoConsumers(Fixture fixture) throws InterruptedException {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (fixture.activeConsumers() != 0 && System.nanoTime() < deadline) {
            fixture.releaseEvents.poll(20, TimeUnit.MILLISECONDS);
        }
        assertEquals(0, fixture.activeConsumers(), "Worker must release its program after completion");
    }

    private static final class Run {
        final String name;
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch closed = new CountDownLatch(1);
        final AtomicInteger closes = new AtomicInteger();
        final AtomicInteger monitoredCalls = new AtomicInteger();
        final AtomicInteger unmonitoredCalls = new AtomicInteger();
        volatile TaskMonitor monitor;
        Run(String name) { this.name = name; }
    }

    private static final class Fixture implements AutoCloseable {
        final Map<String, Run> runs = new ConcurrentHashMap<>();
        final AtomicInteger adds = new AtomicInteger();
        final AtomicInteger releases = new AtomicInteger();
        final LinkedBlockingQueue<Boolean> releaseEvents = new LinkedBlockingQueue<>();
        final AtomicInteger analysisAttempts = new AtomicInteger();
        final CountDownLatch analysisEntered = new CountDownLatch(1);
        final CountDownLatch analysisRelease = new CountDownLatch(1);
        volatile boolean blockAnalysis;
        volatile boolean blockRenames;
        volatile CountDownLatch renameEntered = new CountDownLatch(1);
        volatile CountDownLatch renameRelease = new CountDownLatch(1);
        final AddressFactory addresses = (AddressFactory) Proxy.newProxyInstance(AddressFactory.class.getClassLoader(),
            new Class<?>[] {AddressFactory.class}, (proxy, method, args) -> {
                if (method.getName().equals("getAddress")) return null;
                throw new UnsupportedOperationException(method.getName());
            });
        final FunctionManager functions = (FunctionManager) Proxy.newProxyInstance(FunctionManager.class.getClassLoader(),
            new Class<?>[] {FunctionManager.class}, (proxy, method, args) -> {
                throw new UnsupportedOperationException("No real function access: " + method.getName());
            });
        final SymbolTable symbols = (SymbolTable) Proxy.newProxyInstance(SymbolTable.class.getClassLoader(),
            new Class<?>[] {SymbolTable.class}, (proxy, method, args) -> {
                if (method.getName().equals("getSymbols")) {
                    assertEquals("missingVariables", args[0]);
                    if (blockRenames) {
                        renameEntered.countDown();
                        assertTrue(renameRelease.await(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                            "The deferred variable fixture was not released");
                    }
                    return (SymbolIterator) Proxy.newProxyInstance(SymbolIterator.class.getClassLoader(),
                        new Class<?>[] {SymbolIterator.class}, (iterator, operation, parameters) -> {
                            if (operation.getName().equals("hasNext")) return false;
                            throw new UnsupportedOperationException(operation.getName());
                        });
                }
                throw new UnsupportedOperationException(method.getName());
            });
        final Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] {Program.class}, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> "monitored-program";
                case "getDomainFile" -> null;
                case "getAddressFactory" -> addresses;
                case "getFunctionManager" -> functions;
                case "getSymbolTable" -> symbols;
                case "isClosed" -> false;
                case "addConsumer" -> { adds.incrementAndGet(); yield true; }
                case "release" -> { releases.incrementAndGet(); releaseEvents.offer(true); yield null; }
                // Fail before an actual analysis manager or native analyzer is created.
                case "createPrivateEventQueue", "getOptions" -> {
                    analysisAttempts.incrementAndGet();
                    if (blockAnalysis) {
                        analysisEntered.countDown();
                        assertTrue(analysisRelease.await(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS),
                            "The analysis fixture was not released");
                    }
                    throw new IllegalStateException("Headless fixture analysis failure");
                }
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "MonitoredProgram";
                default -> throw new UnsupportedOperationException(method.getName());
            });
        final GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return program; }
            @Override public List<Program> getAllOpenPrograms() { return List.of(program); }
        };
        final GhidrAssistMCPServer server;

        Fixture() throws Exception {
            addProbe("monitored_probe");
            backend.registerTool(new McpTool() {
                @Override public String getName() { return "transition_probe"; }
                @Override public boolean requiresProgramContext() { return false; }
                @Override public boolean supportsProgramSelection() { return false; }
                @Override public boolean isProjectLifecycleOperation() { return true; }
                @Override public String getDescription() { return "Test exclusive project admission"; }
                @Override public McpSchema.JsonSchema getInputSchema() { return emptySchema(); }
                @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program ignored) {
                    return McpSchema.CallToolResult.builder().addTextContent("Transition admitted").build();
                }
            });
            server = new GhidrAssistMCPServer("127.0.0.1", 0, backend);
            server.start();
        }

        Run run(String name) { Run run = new Run(name); runs.put(name, run); return run; }
        int activeConsumers() { return adds.get() - releases.get(); }
        WireClient connect(Transport transport) throws Exception {
            return new WireClient(URI.create("http://127.0.0.1:" + server.getBoundPort()), transport);
        }
        void addProbe(String toolName) {
            backend.registerTool(new McpTool() {
                @Override public String getName() { return toolName; }
                @Override public String getDescription() { return "Controlled monitored native operation"; }
                @Override public boolean isLongRunning() { return true; }
                @Override public boolean supportsRequestMonitoring() { return true; }
                @Override public McpSchema.JsonSchema getInputSchema() {
                    return new McpSchema.JsonSchema("object", Map.of("run", Map.of("type", "string")),
                        List.of("run"), false, null, null);
                }
                @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program selected) {
                    return work(args, selected, TaskMonitor.DUMMY, false);
                }
                @Override public McpSchema.CallToolResult executeMonitored(Map<String, Object> args,
                        Program selected, GhidrAssistMCPBackend ignored, TaskMonitor monitor) {
                    return work(args, selected, monitor, true);
                }
                private McpSchema.CallToolResult work(Map<String, Object> args, Program selected,
                        TaskMonitor monitor, boolean monitored) {
                    assertSame(program, selected);
                    Run run = runs.get((String) args.get("run"));
                    assertNotNull(run);
                    (monitored ? run.monitoredCalls : run.unmonitoredCalls).incrementAndGet();
                    run.monitor = monitor;
                    try {
                        monitor.initialize(STEPS);
                        run.entered.countDown();
                        try { run.release.await(); }
                        catch (InterruptedException interrupted) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException("Test native operation interrupted", interrupted);
                        }
                        for (int step = 1; step <= STEPS; step++) monitor.setProgress(step);
                        return McpSchema.CallToolResult.builder().addTextContent("FULL_SOURCE_" + run.name)
                            .structuredContent(Map.of("run", run.name, "total", STEPS, "complete", true)).build();
                    } finally {
                        run.closes.incrementAndGet();
                        run.closed.countDown();
                    }
                }
            });
        }
        @Override public void close() throws Exception {
            runs.values().forEach(run -> run.release.countDown());
            analysisRelease.countDown();
            renameRelease.countDown();
            try { server.stop(); } finally { backend.shutdown(); }
        }
    }

    private static McpSchema.JsonSchema emptySchema() {
        return new McpSchema.JsonSchema("object", Map.of(), List.of(), false, null, null);
    }

    /** Preserve every notification and response instead of selecting the last SSE data event. */
    private static final class WireClient implements AutoCloseable {
        final Transport transport;
        final HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
        final ExecutorService readers = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "native-progress-wire-reader");
            thread.setDaemon(true);
            return thread;
        });
        final List<JsonNode> messages = new CopyOnWriteArrayList<>();
        final LinkedBlockingQueue<JsonNode> arrivals = new LinkedBlockingQueue<>();
        final List<InputStream> streams = new CopyOnWriteArrayList<>();
        final List<CompletableFuture<?>> requests = new CopyOnWriteArrayList<>();
        final URI endpoint;
        volatile Throwable readerError;
        volatile String session;

        WireClient(URI origin, Transport transport) throws Exception {
            this.transport = transport;
            if (transport == Transport.LEGACY_SSE) {
                HttpResponse<InputStream> connected = client.send(HttpRequest.newBuilder(origin.resolve("/sse"))
                    .timeout(TIMEOUT).header("Accept", "text/event-stream").GET().build(),
                    HttpResponse.BodyHandlers.ofInputStream());
                assertEquals(200, connected.statusCode());
                streams.add(connected.body());
                BufferedReader reader = new BufferedReader(new InputStreamReader(connected.body(), StandardCharsets.UTF_8));
                String address = readers.submit(() -> readData(reader)).get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
                endpoint = origin.resolve(address);
                readers.execute(() -> pump(reader));
            } else endpoint = origin.resolve("/mcp");
            send(message("initialize", "init", Map.of("protocolVersion",
                transport == Transport.LEGACY_SSE ? "2024-11-05" : "2025-11-25",
                "capabilities", Map.of(), "clientInfo", Map.of("name", "native-progress-test", "version", "1.0"))));
            assertFalse(response("init").has("error"));
            notify("notifications/initialized", Map.of());
        }

        void call(Object id, String tool, String run, Object token) throws Exception {
            toolCall(id, tool, Map.of("run", run), token);
        }
        void toolCall(Object id, String tool, Map<String, ?> arguments, Object token) throws Exception {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("name", tool);
            params.put("arguments", arguments);
            if (token != null) params.put("_meta", Map.of("progressToken", token));
            send(message("tools/call", id, params));
        }
        void fence(String id) throws Exception {
            send(message("ping", id, Map.of()));
            response(id);
            // An SSE response can precede its POST's HTTP acknowledgement. Join
            // the acknowledgements too, including any status/transport failures.
            CompletableFuture.allOf(requests.toArray(CompletableFuture[]::new))
                .get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        }
        void awaitProgress(Object token, int progress) throws Exception {
            awaitMessage(message -> isProgress(message, token) &&
                message.path("params").path("progress").asDouble() == progress);
        }
        JsonNode response(Object id) throws Exception { return awaitMessage(message -> isResponse(message, id)); }
        List<JsonNode> responses(Object id) { return messages.stream().filter(message -> isResponse(message, id)).toList(); }
        List<JsonNode> progress(Object token) { return messages.stream().filter(message -> isProgress(message, token)).toList(); }
        List<JsonNode> allProgress() { return messages.stream()
            .filter(message -> "notifications/progress".equals(message.path("method").asText())).toList(); }

        private JsonNode awaitMessage(Predicate<JsonNode> wanted) throws Exception {
            long deadline = System.nanoTime() + TIMEOUT.toNanos();
            while (System.nanoTime() < deadline) {
                for (JsonNode message : messages) if (wanted.test(message)) return message;
                if (readerError != null) throw new AssertionError("Wire reader failed", readerError);
                arrivals.poll(20, TimeUnit.MILLISECONDS);
            }
            fail("Expected protocol message was not received: " + messages);
            return null;
        }
        private static boolean isResponse(JsonNode message, Object id) {
            return message.has("id") && message.path("id").equals(JSON.valueToTree(id)) &&
                (message.has("result") || message.has("error"));
        }
        private static boolean isProgress(JsonNode message, Object token) {
            return "notifications/progress".equals(message.path("method").asText()) &&
                message.path("params").path("progressToken").equals(JSON.valueToTree(token));
        }
        private static Map<String, Object> message(String method, Object id, Map<String, ?> params) {
            Map<String, Object> message = new LinkedHashMap<>();
            message.put("jsonrpc", "2.0");
            if (id != null) message.put("id", id);
            message.put("method", method);
            message.put("params", params);
            return message;
        }
        private HttpRequest request(Map<String, ?> message) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(message)));
            if (transport == Transport.STREAMABLE_HTTP) {
                request.header("MCP-Protocol-Version", "2025-11-25");
                if (session != null) request.header("Mcp-Session-Id", session);
            }
            return request.build();
        }
        private void notify(String method, Map<String, ?> params) throws Exception {
            HttpResponse<String> accepted = client.send(request(message(method, null, params)),
                HttpResponse.BodyHandlers.ofString());
            assertTrue(accepted.statusCode() == 200 || accepted.statusCode() == 202, accepted.body());
        }
        private void send(Map<String, ?> message) throws Exception {
            if (transport == Transport.LEGACY_SSE) {
                // A foreground tool can keep this POST open while progress flows
                // on the separate SSE connection. Do not block the latch owner.
                CompletableFuture<Void> pending = client.sendAsync(request(message), HttpResponse.BodyHandlers.ofString())
                    .thenAccept(accepted -> assertTrue(accepted.statusCode() == 200 || accepted.statusCode() == 202,
                        accepted.body()))
                    .whenComplete((ignored, failure) -> {
                        if (failure != null) readerError = failure;
                    });
                requests.add(pending);
                return;
            }
            CompletableFuture<Void> pending = client.sendAsync(request(message), HttpResponse.BodyHandlers.ofInputStream())
                .thenAccept(response -> {
                    if (response.statusCode() != 200) {
                        readerError = new AssertionError("Unexpected HTTP status: " + response.statusCode());
                        return;
                    }
                    response.headers().firstValue("Mcp-Session-Id").ifPresent(value -> session = value);
                    streams.add(response.body());
                    readers.execute(() -> {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(response.body(), StandardCharsets.UTF_8));
                        if (response.headers().firstValue("Content-Type").orElse("").startsWith("text/event-stream")) {
                            pump(reader);
                        } else {
                            try { record(JSON.readTree(reader)); }
                            catch (Exception failure) { readerError = failure; }
                        }
                    });
                }).exceptionally(failure -> { readerError = failure; return null; });
            requests.add(pending);
        }
        private void pump(BufferedReader reader) {
            try {
                for (String data; (data = readData(reader)) != null;) record(JSON.readTree(data));
            } catch (Exception failure) { readerError = failure; }
        }
        private static String readData(BufferedReader reader) throws Exception {
            StringBuilder data = new StringBuilder();
            for (String line; (line = reader.readLine()) != null;) {
                if (line.isEmpty() && !data.isEmpty()) return data.toString();
                if (line.startsWith("data:")) {
                    if (!data.isEmpty()) data.append('\n');
                    data.append(line.substring(5).stripLeading());
                }
            }
            return data.isEmpty() ? null : data.toString();
        }
        private void record(JsonNode message) {
            if (message != null) { messages.add(message); arrivals.offer(message); }
        }
        @Override public void close() throws Exception {
            for (InputStream stream : streams) stream.close();
            requests.forEach(request -> request.cancel(true));
            client.shutdownNow();
            readers.shutdownNow();
            assertTrue(readers.awaitTermination(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS));
        }
    }
}
