package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import ghidrassistmcp.GhidrAssistMCPBackend;
import io.modelcontextprotocol.spec.McpSchema;

class RationalizedToolCatalogTest {
    @Test void catalogHasExplicitUniqueNamesAndActionSpecificAnnotations() {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            var all = backend.getAllTools();
            var available = backend.getAvailableTools();
            assertEquals(101, all.size());
            assertEquals(94, available.size());
            assertEquals(101, all.stream().map(McpSchema.Tool::name).distinct().count());
            Map<String, McpSchema.Tool> tools = available.stream().collect(Collectors.toMap(McpSchema.Tool::name, t -> t));
            Set<String> hidden = Set.of("get_code", "types", "struct", "comments", "variables", "xrefs", "classes", "bookmarks", "analysis_options", "analysis_control", "project_files", "scripts", "get_function_signature");
            assertTrue(tools.keySet().stream().noneMatch(hidden::contains));
            assertTrue(tools.get("get_pseudocode").annotations().readOnlyHint());
            assertTrue(tools.get("get_pseudocode_batch").annotations().readOnlyHint());
            assertTrue(tools.get("get_pseudocode_batch").annotations().idempotentHint());
            assertNotNull(tools.get("get_pseudocode_batch").outputSchema());
            assertTrue(((Map<?, ?>) tools.get("get_pseudocode_batch").inputSchema()
                .get("properties")).containsKey("program_name"));
            assertTrue(tools.get("get_comment").annotations().readOnlyHint());
            assertFalse(tools.get("set_comment").annotations().readOnlyHint());
            assertTrue(tools.get("assemble_instructions").annotations().readOnlyHint());
            assertTrue(tools.get("patch_instructions").annotations().destructiveHint());
            assertNotNull(tools.get("get_function_hash").outputSchema());
            assertNotNull(tools.get("get_function_prototype").outputSchema());
            assertFalse(tools.containsKey("run_script"));
            for (String name : Set.of("create_project", "open_project", "save_project", "close_project")) {
                McpSchema.Tool tool = tools.get(name);
                assertNotNull(tool, name);
                assertFalse(tool.annotations().readOnlyHint(), name);
                assertNotNull(tool.outputSchema(), name);
                assertFalse(((Map<?, ?>) tool.inputSchema().get("properties")).containsKey("program_name"), name);
                assertFalse(((Map<?, ?>) tool.inputSchema().get("properties")).containsKey("async"), name);
            }
            assertFalse(tools.get("create_project").annotations().idempotentHint());
            assertTrue(tools.get("open_project").annotations().idempotentHint());
            assertTrue(tools.get("save_project").annotations().idempotentHint());
            assertTrue(tools.get("close_project").annotations().idempotentHint());
            assertTrue(tools.get("close_project").annotations().destructiveHint());
            assertFalse(tools.get("save_project").annotations().destructiveHint());
            assertTrue(tools.get("create_project").annotations().openWorldHint());
            assertTrue(tools.get("open_project").annotations().openWorldHint());
            assertEquals(Set.of("location", "name"), Set.copyOf((java.util.List<?>) tools.get("create_project").inputSchema().get("required")));
            assertEquals(Set.of("path"), Set.copyOf((java.util.List<?>) tools.get("open_project").inputSchema().get("required")));
            assertEquals(Map.of(), tools.get("save_project").inputSchema().get("properties"));
            assertEquals(Set.of("save", "discard_changes"), ((Map<?, ?>) tools.get("close_project").inputSchema().get("properties")).keySet());
            for (McpSchema.Tool tool : all) {
                @SuppressWarnings("unchecked")
                Map<String, Object> properties = (Map<String, Object>) tool.inputSchema().get("properties");
                assertFalse(properties.containsKey("action"), tool.name());
                assertFalse(properties.containsKey("format") && !tool.name().equals("export_program"), tool.name());
                assertTrue(properties.keySet().containsAll((java.util.List<?>) tool.inputSchema().get("required")), tool.name());
            }
            assertEquals(Set.of("structure_name", "field_offset", "data_type"), Set.copyOf((java.util.List<?>) tools.get("set_structure_field").inputSchema().get("required")));
            assertFalse(((Map<?, ?>) tools.get("open_program").inputSchema().get("properties")).containsKey("program_name"));
            assertFalse(((Map<?, ?>) tools.get("get_current_address").inputSchema().get("properties")).containsKey("program_name"));
        } finally {
            backend.shutdown();
        }
    }

    @Test void oldEnableStatesFanOutAndCanonicalSavedStateTakesPrecedence() {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            backend.updateToolEnabledStates(Map.of("get_code", false, "get_pseudocode", true));
            assertTrue(backend.isToolEnabled("get_pseudocode"));
            assertFalse(backend.isToolEnabled("get_disassembly"));
            assertFalse(backend.isToolEnabled("get_pcode"));
            assertFalse(backend.isToolEnabled("get_code"));
        } finally { backend.shutdown(); }
    }
}
