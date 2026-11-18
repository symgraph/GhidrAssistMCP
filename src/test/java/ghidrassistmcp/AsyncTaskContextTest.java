package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpProgramContext;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

class AsyncTaskContextTest {

    private final TestBackend backend = new TestBackend();

    @AfterEach
    void shutDownTaskManager() {
        backend.getTaskManager().shutdown();
    }

    @Test
    void completedTaskUsesOriginalProgramContextExactlyOnce() {
        Program originalProgram = program("program-a", "/binaries/program-a", "file-a");
        Program activeProgram = program("program-b", "/binaries/program-b", "file-b");
        backend.setCurrentProgram(originalProgram);
        backend.registerTool(new AsyncTextTool());

        backend.callTool("async_test", Map.of());
        McpTask task = backend.getTaskManager().listTasks(null).stream()
            .filter(candidate -> candidate.getToolName().equals("async_test"))
            .findFirst()
            .orElseThrow();
        awaitTerminal(task);

        assertEquals(McpTask.Status.COMPLETED, task.getStatus());
        assertEquals(new McpProgramContext(
            "program-a", "/binaries/program-a", "file-a"), task.getProgramContext());
        assertFalse(text(task.getResult()).contains("[Context]"),
            "task manager should retain the raw tool result");

        backend.setCurrentProgram(activeProgram);
        McpSchema.CallToolResult statusResult = backend.callTool("get_task_status",
            Map.of("task_id", task.getTaskId()));
        String response = text(statusResult);

        assertTrue(response.startsWith(
            "[Context] Operating on: program-a | Active window: program-b\n\n"));
        assertEquals(1, occurrences(response, "[Context]"));
        assertTrue(response.endsWith("Result for program-a"));
    }

    private static void awaitTerminal(McpTask task) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (!task.isTerminal() && System.nanoTime() < deadline) {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
        }
        assertTrue(task.isTerminal(), "async task did not finish before the test timeout");
    }

    private static String text(McpSchema.CallToolResult result) {
        McpSchema.TextContent content =
            assertInstanceOf(McpSchema.TextContent.class, result.content().get(0));
        return content.text();
    }

    private static int occurrences(String value, String search) {
        int count = 0;
        int offset = 0;
        while ((offset = value.indexOf(search, offset)) >= 0) {
            count++;
            offset += search.length();
        }
        return count;
    }

    private static Program program(String name, String projectPath, String fileId) {
        DomainFile domainFile = (DomainFile) Proxy.newProxyInstance(
            DomainFile.class.getClassLoader(), new Class<?>[] { DomainFile.class },
            (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getPathname" -> projectPath;
                case "getFileID" -> fileId;
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "FakeDomainFile[" + projectPath + "]";
                default -> throw new UnsupportedOperationException(method.getName());
            });

        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getDomainFile" -> domainFile;
                case "isClosed" -> false;
                case "addConsumer" -> true;
                case "release" -> null;
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "FakeProgram[" + name + "]";
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    private static final class TestBackend extends GhidrAssistMCPBackend {
        private volatile Program currentProgram;

        void setCurrentProgram(Program program) {
            currentProgram = program;
        }

        @Override
        public Program getCurrentProgram() {
            return currentProgram;
        }
    }

    private static final class AsyncTextTool implements McpTool {
        @Override
        public String getName() {
            return "async_test";
        }

        @Override
        public String getDescription() {
            return "Test async context propagation";
        }

        @Override
        public JsonSchema getInputSchema() {
            return new JsonSchema(
                "object", Map.of(), List.of(), null, null, null);
        }

        @Override
        public McpSchema.CallToolResult execute(Map<String, Object> arguments,
                                                Program currentProgram) {
            return McpSchema.CallToolResult.builder()
                .addContent(McpSchema.TextContent.builder("Result for " + currentProgram.getName()).build())
                .build();
        }

        @Override
        public boolean isLongRunning() {
            return true;
        }
    }
}
