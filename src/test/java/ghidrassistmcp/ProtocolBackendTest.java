package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ghidra.framework.model.DomainFile;
import ghidrassistmcp.resources.McpResource;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

class ProtocolBackendTest {
    private final TestBackend backend = new TestBackend();

    @AfterEach
    void shutdown() {
        backend.shutdown();
    }

    @Test
    void nullArgumentsAreAnEmptyObjectAndInvalidArgumentsAreErrors() {
        backend.registerTool(new TestTool("validation_test", false, false) {
            @Override
            public JsonSchema getInputSchema() {
                return new JsonSchema("object", Map.of("count", Map.of(
                    "type", "integer", "minimum", 1)), List.of("count"), false, null, null);
            }
        });
        assertTrue(backend.callTool("validation_test", null).isError());
        assertTrue(backend.callTool("validation_test", Map.of("count", 0)).isError());
        assertTrue(backend.callTool("validation_test", Map.of("count", 1, "typo", true)).isError());
        assertFalse(Boolean.TRUE.equals(backend.callTool("validation_test", Map.of("count", 1)).isError()));
    }

    @Test
    void explicitMissingOrAmbiguousTargetNeverExecutesAgainstActiveProgram() {
        Program first = program("same", "/a/same");
        Program second = program("same", "/b/same");
        backend.programs = List.of(first, second);
        backend.current = first;
        AtomicInteger executions = new AtomicInteger();
        backend.registerTool(new TestTool("target_test", true, false) {
            @Override
            public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                executions.incrementAndGet();
                return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder(program.getName()).build()).build();
            }
        });
        assertTrue(backend.callTool("target_test", Map.of("program_name", "missing")).isError());
        assertTrue(backend.callTool("target_test", Map.of("program_name", "same")).isError());
        assertEquals(0, executions.get());
        assertFalse(Boolean.TRUE.equals(backend.callTool("target_test", Map.of("program_name", "/b/same")).isError()));
        assertEquals(1, executions.get());
    }

    @Test
    void contextDecorationPreservesErrorStructuredContentMetadataAndNonTextContent() {
        backend.current = program("example", "/example");
        McpSchema.ImageContent image = new McpSchema.ImageContent(null, "AA==", "image/png", null);
        Map<String, Object> data = Map.of("reason", "test failure");
        Map<String, Object> meta = Map.of("test", "metadata");
        backend.registerTool(new TestTool("content_test", true, false) {
            @Override
            public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                return new McpSchema.CallToolResult(List.of(McpSchema.TextContent.builder("failure").build(), image),
                    data, true, McpSchema.ResultType.COMPLETE, meta);
            }
        });
        var result = backend.callTool("content_test", Map.of());
        assertTrue(result.isError());
        assertEquals(data, result.structuredContent());
        assertEquals(meta, result.meta());
        assertEquals(image, result.content().get(1));
        assertTrue(text(result).startsWith("[Context] Operating on: example"));
    }

    @Test
    void cachesAreIsolatedAcrossEqualFilenamesAndContextIsRefreshedOnHits() {
        Program first = program("same", "/a/same");
        Program second = program("same", "/b/same");
        backend.programs = List.of(first, second);
        backend.current = first;
        AtomicInteger executions = new AtomicInteger();
        backend.registerTool(new TestTool("cache_test", true, true) {
            @Override
            public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                executions.incrementAndGet();
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder(program.getDomainFile().getPathname()).build()).build();
            }
        });
        var initial = backend.callTool("cache_test", Map.of());
        backend.current = second;
        var other = backend.callTool("cache_test", Map.of());
        assertTrue(text(initial).endsWith("/a/same"));
        assertTrue(text(other).endsWith("/b/same"));
        assertEquals(2, executions.get());
        backend.callTool("cache_test", Map.of("program_name", "/a/same"));
        backend.current = first;
        var cached = backend.callTool("cache_test", Map.of("program_name", "/a/same"));
        assertFalse(text(cached).contains("Active window:"));
        assertEquals(3, executions.get());
    }

    @Test
    void errorsAreNotCached() {
        backend.current = program("example", "/example");
        AtomicInteger executions = new AtomicInteger();
        backend.registerTool(new TestTool("error_cache_test", true, true) {
            @Override
            public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                executions.incrementAndGet();
                return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("failed").build()).isError(true).build();
            }
        });
        backend.callTool("error_cache_test", Map.of());
        backend.callTool("error_cache_test", Map.of());
        assertEquals(2, executions.get());
    }

    @Test
    void legacyMultilineFailuresAreErrorsAndRetrievedCommentsRemainLiteralData() {
        backend.registerTool(new TestTool("legacy_failure_test", false, false) {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Failed to read function\nDetailed failure explanation").build()).build();
            }
        });
        assertTrue(backend.callTool("legacy_failure_test", Map.of()).isError());
        backend.registerTool(new TestTool("legacy_failure_test", false, false) {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Function example not found\nTry another address").build()).build();
            }
        });
        assertTrue(backend.callTool("legacy_failure_test", Map.of()).isError());
        backend.registerTool(new TestTool("get_comment", false, false) {
            @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
                return McpSchema.CallToolResult.builder()
                    .addContent(McpSchema.TextContent.builder("Error: documented behavior\nThis is literal comment content").build()).build();
            }
        });
        assertFalse(Boolean.TRUE.equals(backend.callTool("get_comment", Map.of()).isError()));
    }

    @Test
    void globalToolsDoNotClaimToOperateOnAnUnrelatedActiveProgram() {
        backend.current = program("example", "/example");
        backend.registerTool(new TestTool("global_context_test", false, false));
        String content = text(backend.callTool("global_context_test", Map.of()));
        assertTrue(content.startsWith("[Context] Active window: example"));
        assertFalse(content.contains("Operating on:"));
    }

    @Test
    void resourceSelectorsDecodePercentEscapesAndPreserveLiteralPlus() {
        Program plus = program("a+b", "/a+b");
        Program space = program("a b", "/a b");
        backend.current = space;
        backend.programs = List.of(plus, space);
        backend.getResourceRegistry().registerResource(new McpResource() {
            @Override public String getName() { return "test-selector"; }
            @Override public String getDescription() { return "Test resource selector"; }
            @Override public String getMimeType() { return "text/plain"; }
            @Override public String getUriPattern() { return "test://program/{name}"; }
            @Override public boolean canHandle(String uri) { return uri.startsWith("test://program/"); }
            @Override public Map<String, String> extractParams(String uri) {
                return Map.of("name", uri.substring("test://program/".length()));
            }
            @Override public String readContent(Program program, Map<String, String> params) {
                return program.getName();
            }
        });
        assertEquals("a+b", backend.readResource("test://program/a+b"));
        assertEquals("a+b", backend.readResource("test://program/a%2Bb"));
        assertEquals("a b", backend.readResource("test://program/a%20b"));
        assertThrows(io.modelcontextprotocol.modern.McpException.class,
            () -> backend.readResource("test://program/missing"));
    }

    private static String text(McpSchema.CallToolResult result) {
        return ((McpSchema.TextContent) result.content().get(0)).text();
    }

    private static Program program(String name, String path) {
        DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] { DomainFile.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getPathname", "getFileID" -> path;
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> path;
                default -> throw new UnsupportedOperationException(method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "getDomainFile" -> file;
                case "getModificationNumber" -> 0L;
                case "isClosed" -> false;
                case "addConsumer" -> true;
                case "release" -> null;
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> path;
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }

    private static class TestTool implements McpTool {
        private final String name;
        private final boolean needsProgram;
        private final boolean cacheable;
        TestTool(String name, boolean needsProgram, boolean cacheable) {
            this.name = name;
            this.needsProgram = needsProgram;
            this.cacheable = cacheable;
        }
        @Override public String getName() { return name; }
        @Override public String getDescription() { return "Test tool"; }
        @Override public boolean requiresProgramContext() { return needsProgram; }
        @Override public boolean isCacheable() { return cacheable; }
        @Override public JsonSchema getInputSchema() {
            return new JsonSchema("object", Map.of(), List.of(), false, null, null);
        }
        @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("ok").build()).build();
        }
    }

    private static class TestBackend extends GhidrAssistMCPBackend {
        Program current;
        List<Program> programs = List.of();
        @Override public Program getCurrentProgram() { return current; }
        @Override public List<Program> getAllOpenPrograms() { return programs; }
    }
}
