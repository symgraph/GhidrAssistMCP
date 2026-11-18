package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.framework.protocol.ghidra.Handler;
import ghidrassistmcp.project.ProjectController;
import ghidrassistmcp.tools.ProjectControlTool.Operation;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.modern.McpSchema;

class ProjectControlToolTest {
    @BeforeAll static void registerGhidraProtocol() { Handler.registerHandler(); }

    @TempDir Path directory;

    @Test void createDispatchesNormalizedDirectoryAndExactStemWithoutProgramContext() {
        Controller fixture = new Controller();
        ProjectControlTool tool = tool(Operation.CREATE, fixture);
        var result = tool.execute(Map.of("location", directory.resolve(".").toString(), "name", "Example project"), null);
        assertSuccess(tool, result);
        assertEquals(List.of(List.of("create", directory.toString(), "Example project")), fixture.calls);
        assertFalse(tool.requiresProgramContext());
        assertFalse(tool.supportsProgramSelection());
        assertTrue(tool.isProjectLifecycleOperation());
    }

    @Test void openUsesMarkerParentAndStemWithExplicitRestoreDefault() throws IOException {
        Path marker = Files.createFile(directory.resolve("example.gpr"));
        Controller fixture = new Controller();
        ProjectControlTool tool = tool(Operation.OPEN, fixture);
        assertSuccess(tool, tool.execute(Map.of("path", marker.toString()), null));
        assertSuccess(tool, tool.execute(Map.of("path", marker.toString(), "restore_state", true), null));
        assertEquals(List.of(List.of("open", directory.toString(), "example", false),
            List.of("open", directory.toString(), "example", true)), fixture.calls);
    }

    @Test void openingExistingMarkerPreservesItsLegalProjectStem() throws IOException {
        Path marker = Files.createFile(directory.resolve("legacy.rep.gpr"));
        Controller fixture = new Controller();
        ProjectControlTool tool = tool(Operation.OPEN, fixture);
        assertSuccess(tool, tool.execute(Map.of("path", marker.toString()), null));
        assertEquals(List.of(List.of("open", directory.toString(), "legacy.rep", false)), fixture.calls);
    }

    @Test void saveAndCloseDispatchWithoutAddingImplicitSaveOrDiscard() {
        Controller fixture = new Controller();
        ProjectControlTool save = tool(Operation.SAVE, fixture);
        ProjectControlTool close = tool(Operation.CLOSE, fixture);
        assertSuccess(save, save.execute(Map.of(), null));
        assertSuccess(close, close.execute(Map.of(), null));
        assertSuccess(close, close.execute(Map.of("save", true), null));
        assertSuccess(close, close.execute(Map.of("discard_changes", true), null));
        assertEquals(List.of(List.of("save"), List.of("close", false, false),
            List.of("close", true, false), List.of("close", false, true)), fixture.calls);
    }

    @Test void invalidCreateArgumentsNeverResolveControllerOrDispatch() {
        AtomicInteger resolved = new AtomicInteger();
        ProjectControlTool tool = new ProjectControlTool(Operation.CREATE, () -> { resolved.incrementAndGet(); return new Controller(); });
        List<Map<String, Object>> invalid = List.of(
            Map.of(), Map.of("location", "relative", "name", "example"),
            Map.of("location", directory.resolve("missing").toString(), "name", "example"),
            Map.of("location", directory.toString(), "name", ""),
            Map.of("location", directory.toString(), "name", "../example"),
            Map.of("location", directory.toString(), "name", "path\\example"),
            Map.of("location", directory.toString(), "name", "."),
            Map.of("location", directory.toString(), "name", "example.gpr"),
            Map.of("location", directory.toString(), "name", "example.rep"),
            Map.of("location", directory.toString(), "name", "example "),
            Map.of("location", directory.toString(), "name", "example", "overwrite", true));
        for (Map<String, Object> arguments : invalid) assertError(tool.execute(arguments, null));
        assertError(tool.execute(null, null));
        assertEquals(0, resolved.get());
    }

    @Test void invalidOpenAndCloseArgumentsFailBeforeControllerLookup() throws IOException {
        Path marker = Files.createFile(directory.resolve("example.gpr"));
        Path unnamed = Files.createFile(directory.resolve(".gpr"));
        AtomicInteger resolved = new AtomicInteger();
        Supplier<ProjectController> supplier = () -> { resolved.incrementAndGet(); return new Controller(); };
        ProjectControlTool open = new ProjectControlTool(Operation.OPEN, supplier);
        assertError(open.execute(Map.of("path", "example.gpr"), null));
        assertError(open.execute(Map.of("path", unnamed.toString()), null));
        assertError(open.execute(Map.of("path", directory.resolve("example.rep").toString()), null));
        assertError(open.execute(Map.of("path", directory.resolve("missing.gpr").toString()), null));
        assertError(open.execute(Map.of("path", marker.toString(), "restore_state", "true"), null));
        ProjectControlTool close = new ProjectControlTool(Operation.CLOSE, supplier);
        assertError(close.execute(Map.of("save", true, "discard_changes", true), null));
        assertError(close.execute(Map.of("save", 1), null));
        assertError(close.execute(Map.of("discard_changes", "false"), null));
        assertError(close.execute(Map.of("program_name", "other"), null));
        assertError(new ProjectControlTool(Operation.SAVE, supplier).execute(Map.of("path", marker.toString()), null));
        assertEquals(0, resolved.get());
    }

    @Test void controllerFailuresAndMissingStatusProduceTypedToolErrors() {
        ProjectControlTool unavailable = new ProjectControlTool(Operation.SAVE,
            () -> { throw new IllegalStateException("Ghidra project manager is unavailable"); });
        var result = unavailable.execute(Map.of(), null);
        assertError(result);
        assertTrue(((McpSchema.TextContent) result.content().getFirst()).text().contains("project manager is unavailable"));
        Controller failing = new Controller() {
            @Override public Map<String, Object> saveProject() throws Exception { throw new IOException("Cannot save changed file"); }
        };
        result = tool(Operation.SAVE, failing).execute(Map.of(), null);
        assertError(result);
        assertTrue(((McpSchema.TextContent) result.content().getFirst()).text().contains("Cannot save changed file"));
        Controller malformed = new Controller() {
            @Override public Map<String, Object> saveProject() { return Map.of("saved_files", 0); }
        };
        assertError(tool(Operation.SAVE, malformed).execute(Map.of(), null));
    }

    @Test void idempotentControllerStatusesArePreservedInStructuredResults() {
        Controller fixture = new Controller() {
            @Override public Map<String, Object> closeProject(boolean save, boolean discardChanges) {
                return Map.of("status", "already_closed", "name", "", "location", "", "project_path", "");
            }
        };
        ProjectControlTool tool = tool(Operation.CLOSE, fixture);
        var result = tool.execute(Map.of(), null);
        assertSuccess(tool, result);
        assertEquals("already_closed", ((Map<?, ?>) result.structuredContent()).get("status"));
    }

    private static ProjectControlTool tool(Operation operation, Controller controller) {
        return new ProjectControlTool(operation, () -> controller);
    }

    @SuppressWarnings("unchecked")
    private static void assertSuccess(ProjectControlTool tool, McpSchema.CallToolResult result) {
        assertFalse(Boolean.TRUE.equals(result.isError()), result.content().toString());
        Map<String, Object> content = (Map<String, Object>) result.structuredContent();
        assertNotNull(content);
        var validation = McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), content);
        assertTrue(validation.valid(), validation.errorMessage());
        assertEquals(1, result.content().size());
    }

    private static void assertError(McpSchema.CallToolResult result) {
        assertTrue(Boolean.TRUE.equals(result.isError()), result.content().toString());
        assertNull(result.structuredContent());
    }

    private static class Controller implements ProjectController {
        final List<List<Object>> calls = new ArrayList<>();
        @Override public Map<String, Object> createProject(String location, String name) throws Exception {
            calls.add(List.of("create", location, name));
            return result("created", location, name);
        }
        @Override public Map<String, Object> openProject(String location, String name, boolean restoreState) throws Exception {
            calls.add(List.of("open", location, name, restoreState));
            return result("opened", location, name);
        }
        @Override public Map<String, Object> saveProject() throws Exception {
            calls.add(List.of("save"));
            return Map.of("status", "saved", "name", "example", "location", "/projects", "project_path", "/projects/example.gpr", "saved_files", 2);
        }
        @Override public Map<String, Object> closeProject(boolean save, boolean discardChanges) throws Exception {
            calls.add(List.of("close", save, discardChanges));
            return Map.of("status", "closed", "location", "/projects", "name", "example",
                "project_path", "/projects/example.gpr", "saved_files", save ? 2 : 0, "discarded_changes", discardChanges);
        }
        private static Map<String, Object> result(String status, String location, String name) {
            return Map.of("status", status, "location", location, "name", name, "project_path", Path.of(location, name + ".gpr").toString());
        }
    }
}
