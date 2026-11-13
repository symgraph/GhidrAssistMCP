package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import javax.swing.SwingUtilities;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.protocol.McpProgressMonitor;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/** Progress is an observation of existing per-item rename outcomes, not a new transaction policy. */
@Timeout(15)
class RenameSymbolBatchProgressTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final RenameSymbolBatchTool tool = new RenameSymbolBatchTool(null);

    @Test
    void malformedAndValidationFailuresCountOnceAndKeepTheExactLegacyResponse() throws Exception {
        Fixture fixture = new Fixture();
        Map<String, Object> arguments = Map.of("renames", List.of("not an object",
            Map.of("target_type", "function"),
            Map.of("target_type", "other", "identifier", "item", "new_name", "new")));
        var baseline = tool.execute(arguments, fixture.program);
        RecordingTask task = new RecordingTask();
        var monitored = tool.execute(arguments, fixture.program, null, task);

        assertEquals(baseline, monitored);
        assertEquals(List.of(0, 33, 67, 100), distinct(task.percentages));
        assertTrue(task.messages.getLast().contains("Completed 3 of 3 renames (item 3) (3/3)"));
        JsonNode output = result(monitored);
        assertEquals(3, output.path("failed").asInt());
        assertEquals("Item is not an object/map", output.path("results").get(0).path("message").asText());
        assertEquals(output.toString(), text(monitored), "Progress must preserve compact JSON serialization");
        assertTrue(fixture.commits.isEmpty(), "Input failures must not open database transactions");
    }

    @Test
    void successfulAndRejectedNativeRenamesKeepIndependentEdtTransactions() throws Exception {
        Fixture fixture = new Fixture();
        fixture.function(0x100, "first");
        fixture.function(0x200, "second");
        Map<String, Object> arguments = Map.of("renames", List.of(
            rename("function", "0x100", "accepted"), rename("function", "0x200", "reject"),
            Map.of("target_type", "data")));
        var baseline = tool.execute(arguments, fixture.program);
        RecordingTask task = new RecordingTask();
        var monitored = tool.execute(arguments, fixture.program, null, task);

        assertEquals(baseline, monitored);
        assertEquals(List.of(true, false, true, false), fixture.commits);
        assertEquals(4, fixture.transactions.get(), "There must be no enclosing batch transaction");
        assertEquals("accepted", fixture.names.get(fixture.space.getAddress(0x100)));
        assertEquals("second", fixture.names.get(fixture.space.getAddress(0x200)));
        JsonNode output = result(monitored);
        assertEquals(1, output.path("succeeded").asInt());
        assertEquals(2, output.path("failed").asInt());
        assertTrue(output.path("results").get(0).path("success").asBoolean());
        assertFalse(output.path("results").get(1).path("success").asBoolean());
        assertEquals(List.of(0, 33, 67, 100), distinct(task.percentages));
    }

    @Test
    void deferredVariablesWaitForTheirSharedLookupAndKeepRequestIndexOrder() throws Exception {
        Fixture fixture = new Fixture();
        Map<String, Object> arguments = Map.of("renames", List.of(
            variable("missing", "old0", "new0"), "invalid",
            variable("missing", "old2", "new2"), variable("missing", "old3", "new3")));
        var baseline = tool.execute(arguments, fixture.program);
        fixture.lookups.set(0);
        CountDownLatch groupEntered = new CountDownLatch(1);
        CountDownLatch releaseGroup = new CountDownLatch(1);
        fixture.beforeLookup = name -> {
            assertEquals("missing", name);
            groupEntered.countDown();
            try { assertTrue(releaseGroup.await(5, TimeUnit.SECONDS)); }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError(interrupted);
            }
        };
        RecordingTask task = new RecordingTask();
        try (var worker = Executors.newSingleThreadExecutor()) {
            var running = worker.submit(() -> tool.execute(arguments, fixture.program, null, task));
            try {
                assertTrue(groupEntered.await(5, TimeUnit.SECONDS));
                assertEquals(25, task.getProgressPercent(), "Queued variables are not completed operations");
                assertEquals(List.of(0, 25), distinct(task.percentages));
                assertTrue(task.getProgressMessage().contains("Renaming variables in missing (1/4)"));
                assertFalse(running.isDone());
            } finally { releaseGroup.countDown(); }
            var monitored = running.get(5, TimeUnit.SECONDS);
            assertEquals(baseline, monitored);
            assertEquals(List.of(0, 25, 50, 75, 100), distinct(task.percentages));
            assertEquals(1, fixture.lookups.get(), "One function group must resolve its variables together");
            JsonNode output = result(monitored);
            assertEquals(4, output.path("failed").asInt());
            for (int index = 0; index < 4; index++) {
                assertEquals(index, output.path("results").get(index).path("index").asInt());
            }
            assertEquals("Function not found: missing", output.path("results").get(0).path("message").asText());
            assertEquals("Function not found: missing", output.path("results").get(2).path("message").asText());
            assertTrue(task.messages.stream().anyMatch(message -> message.contains("Completed 2 of 4 renames (item 1)")),
                "Completion messages must count finished work, not the original request index");
            assertTrue(task.getProgressMessage().contains("Completed 4 of 4 renames (item 4) (4/4)"));
            assertTrue(fixture.commits.isEmpty());
        }
    }

    @Test
    void largeBatchCannotReachTerminalProgressWhileItsLastVariableGroupIsBlocked() throws Exception {
        Fixture fixture = new Fixture();
        List<Object> requests = new ArrayList<>();
        for (int index = 0; index < 200; index++) requests.add(Map.of("target_type", "function"));
        requests.add(variable("missing-last", "old", "new"));
        Map<String, Object> arguments = Map.of("renames", requests);
        var baseline = tool.execute(arguments, fixture.program);
        CountDownLatch groupEntered = new CountDownLatch(1);
        CountDownLatch releaseGroup = new CountDownLatch(1);
        fixture.beforeLookup = name -> {
            assertEquals("missing-last", name);
            groupEntered.countDown();
            try { assertTrue(releaseGroup.await(5, TimeUnit.SECONDS)); }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError(interrupted);
            }
        };
        RecordingTask task = new RecordingTask();
        try (var worker = Executors.newSingleThreadExecutor()) {
            var running = worker.submit(() -> tool.execute(arguments, fixture.program, null, task));
            try {
                assertTrue(groupEntered.await(5, TimeUnit.SECONDS));
                assertEquals(99, task.getProgressPercent(), "200/201 is unfinished work, even if rounded to 100");
                assertFalse(task.percentages.contains(100), "Terminal progress must wait for the final group");
                assertTrue(task.getProgressMessage().contains("(200/201)"));
                assertFalse(running.isDone());
            } finally { releaseGroup.countDown(); }
            var monitored = running.get(5, TimeUnit.SECONDS);
            assertEquals(baseline, monitored);
            assertEquals(100, task.getProgressPercent());
            assertEquals(201, result(monitored).path("failed").asInt());
            assertTrue(task.getProgressMessage().contains("Completed 201 of 201 renames (item 201)"));
            assertTrue(fixture.commits.isEmpty());
        }
    }

    @Test
    void failedSdkProgressSenderCannotPreventASuccessfulNativeRename() throws Exception {
        Fixture fixture = new Fixture();
        fixture.function(0x100, "original");
        Map<String, Object> arguments = Map.of("renames", List.of(rename("function", "0x100", "accepted")));
        var baseline = tool.execute(arguments, fixture.program);
        assertEquals(1, result(baseline).path("succeeded").asInt());
        AtomicInteger attempts = new AtomicInteger();
        try (McpProgressMonitor monitor = new McpProgressMonitor("rename-progress", notification -> {
            attempts.incrementAndGet();
            if (notification.progress() == 100.0) {
                assertEquals(List.of(true, true), fixture.commits, "The rename must commit before terminal progress");
                throw new IllegalStateException("Progress channel unavailable after commit");
            }
            assertEquals(0.0, notification.progress().doubleValue());
        })) {
            var monitored = tool.executeMonitored(arguments, fixture.program, null, monitor);
            assertEquals(baseline, monitored);
            assertEquals(1, result(monitored).path("succeeded").asInt());
            assertEquals("accepted", fixture.names.get(fixture.space.getAddress(0x100)));
            assertEquals(List.of(true, true), fixture.commits);
            monitor.setMaximum(101);
            monitor.setProgress(101);
            assertEquals(2, attempts.get(), "Initial progress succeeds and the failing terminal channel is then disabled");
        }
    }

    @Test
    void canonicalAliasUsesTheGenericMonitoringBridgeAndPreservesItsOutput() {
        Fixture fixture = new Fixture();
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return fixture.program; }
            @Override public List<Program> getAllOpenPrograms() { return List.of(fixture.program); }
        };
        try {
            assertTrue(backend.supportsRequestMonitoring("rename_symbols_batch"));
            Map<String, Object> arguments = Map.of("renames", List.of(
                rename("function", "absent", "newFunction"), variable("absent", "old", "newLocal")));
            var baseline = backend.callTool("rename_symbols_batch", arguments);
            RecordingMonitor monitor = new RecordingMonitor();
            var monitored = backend.callToolMonitored("rename_symbols_batch", arguments, monitor);
            assertEquals(baseline, monitored);
            assertEquals(100, monitor.maximum);
            assertEquals(List.of(0L, 50L, 100L), distinct(monitor.percentages));
            assertTrue(monitor.messages.stream().anyMatch(message -> message.contains("(2/2)")));
            assertEquals(2, fixture.adds.get());
            assertEquals(2, fixture.releases.get());
            assertTrue(backend.getTaskManager().listTasks(null).isEmpty());
        } finally { backend.shutdown(); }
    }

    @Test
    void emptyBatchNullTaskAndWholeRequestErrorsKeepTheirExistingResults() throws Exception {
        Fixture fixture = new Fixture();
        Map<String, Object> empty = Map.of("renames", List.of());
        RecordingTask task = new RecordingTask();
        var response = tool.execute(empty, fixture.program, null, task);
        assertEquals(tool.execute(empty, fixture.program), response);
        assertEquals(0, result(response).path("total").asInt());
        assertEquals(List.of(0), distinct(task.percentages));
        assertEquals(response, tool.execute(empty, fixture.program, null, null));

        for (Map<String, Object> arguments : List.<Map<String, Object>>of(Map.of(), Map.of("renames", "bad"))) {
            task = new RecordingTask();
            assertEquals(tool.execute(arguments, fixture.program), tool.execute(arguments, fixture.program, null, task));
            assertEquals(0, task.getProgressPercent());
        }
        assertEquals(tool.execute(empty, null), tool.execute(empty, null, null, new RecordingTask()));
        assertTrue(fixture.commits.isEmpty());
    }

    private static Map<String, Object> rename(String type, String identifier, String name) {
        return Map.of("target_type", type, "identifier", identifier, "new_name", name);
    }
    private static Map<String, Object> variable(String function, String oldName, String newName) {
        return Map.of("target_type", "variable", "identifier", function, "variable_name", oldName, "new_name", newName);
    }
    private static String text(McpSchema.CallToolResult response) {
        return ((McpSchema.TextContent) response.content().getFirst()).text();
    }
    private static JsonNode result(McpSchema.CallToolResult response) throws Exception { return JSON.readTree(text(response)); }
    private static <T> List<T> distinct(List<T> values) {
        List<T> result = new ArrayList<>();
        for (T value : values) if (result.isEmpty() || !result.getLast().equals(value)) result.add(value);
        return result;
    }

    private static final class RecordingTask extends McpTask {
        final List<Integer> percentages = new CopyOnWriteArrayList<>();
        final List<String> messages = new CopyOnWriteArrayList<>();
        RecordingTask() { super("batch_rename", Map.of()); markStarted(); }
        @Override public synchronized void updateProgress(int percent, String message) {
            super.updateProgress(percent, message);
            percentages.add(getProgressPercent());
            messages.add(getProgressMessage());
        }
    }
    private static final class RecordingMonitor extends TaskMonitorAdapter {
        final List<Long> percentages = new ArrayList<>();
        final List<String> messages = new ArrayList<>();
        long maximum;
        @Override public void initialize(long total) { maximum = total; setProgress(0); }
        @Override public void setProgress(long value) { percentages.add(value); }
        @Override public void setMessage(String message) { messages.add(message); }
    }

    private static final class Fixture {
        final AddressSpace space = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
        final Map<Address, Function> functions = new HashMap<>();
        final Map<Address, String> names = new HashMap<>();
        final AtomicInteger transactions = new AtomicInteger();
        final AtomicInteger lookups = new AtomicInteger();
        final AtomicInteger adds = new AtomicInteger();
        final AtomicInteger releases = new AtomicInteger();
        final List<Boolean> commits = new ArrayList<>();
        volatile Consumer<String> beforeLookup = ignored -> { };
        final Namespace global = fake(Namespace.class, (method, args) -> switch (method.getName()) {
            case "isGlobal" -> true;
            case "getName" -> "Global";
            default -> unsupported(method);
        });
        final AddressFactory addresses = fake(AddressFactory.class, (method, args) -> switch (method.getName()) {
            case "getAddress" -> ((String) args[0]).startsWith("0x")
                ? space.getAddress(Long.parseLong(((String) args[0]).substring(2), 16)) : null;
            case "getDefaultAddressSpace" -> space;
            case "getAddressSpace" -> null;
            default -> unsupported(method);
        });
        final FunctionManager manager = fake(FunctionManager.class, (method, args) -> switch (method.getName()) {
            case "getFunctionAt", "getFunctionContaining" -> functions.get(args[0]);
            default -> unsupported(method);
        });
        final SymbolTable symbols = fake(SymbolTable.class, (method, args) -> {
            if (!method.getName().equals("getSymbols")) return unsupported(method);
            lookups.incrementAndGet();
            beforeLookup.accept((String) args[0]);
            Iterator<?> empty = List.of().iterator();
            return fake(SymbolIterator.class, (iteratorMethod, ignored) -> switch (iteratorMethod.getName()) {
                case "hasNext" -> empty.hasNext();
                case "next" -> empty.next();
                default -> unsupported(iteratorMethod);
            });
        });
        final Program program = fake(Program.class, (method, args) -> switch (method.getName()) {
            case "getName" -> "rename-program";
            case "getGlobalNamespace" -> global;
            case "getAddressFactory" -> addresses;
            case "getFunctionManager" -> manager;
            case "getSymbolTable" -> symbols;
            case "getDomainFile" -> null;
            case "isClosed" -> false;
            case "addConsumer" -> { adds.incrementAndGet(); yield true; }
            case "release" -> { releases.incrementAndGet(); yield null; }
            case "startTransaction" -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                yield transactions.incrementAndGet();
            }
            case "endTransaction" -> {
                assertTrue(SwingUtilities.isEventDispatchThread());
                commits.add((Boolean) args[1]);
                yield (Boolean) args[1];
            }
            default -> unsupported(method);
        });
        void function(long offset, String name) {
            Address address = space.getAddress(offset);
            names.put(address, name);
            functions.put(address, fake(Function.class, (method, args) -> switch (method.getName()) {
                case "getName" -> names.get(address);
                case "getEntryPoint" -> address;
                case "getParentNamespace" -> global;
                case "setName" -> {
                    assertTrue(SwingUtilities.isEventDispatchThread());
                    if ("reject".equals(args[0])) throw new InvalidInputException("Rejected test name");
                    names.put(address, (String) args[0]);
                    yield null;
                }
                default -> unsupported(method);
            }));
        }
    }

    @FunctionalInterface private interface Answer { Object invoke(Method method, Object[] args) throws Throwable; }
    private static <T> T fake(Class<T> type, Answer answer) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
            (proxy, method, args) -> switch (method.getName()) {
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "Fake" + type.getSimpleName();
                default -> answer.invoke(method, args);
            }));
    }
    private static Object unsupported(Method method) { throw new UnsupportedOperationException(method.toString()); }
}
