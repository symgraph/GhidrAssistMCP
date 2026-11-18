package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.spec.McpSchema;

class RenameSymbolBatchToolTest {
    @Test void compactJsonPreservesAllFieldsFailureMessagesAndEscaping() throws Exception {
        Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] { Program.class }, (proxy, method, args) -> {
                if (method.getName().equals("getName")) return "test-program";
                throw new UnsupportedOperationException("Unexpected program access: " + method);
            });
        String identifier = "old \"name\"\nline";
        String newName = "new\\name";
        var response = new RenameSymbolBatchTool(null).execute(Map.of("renames", List.of(
            "malformed", Map.of(), Map.of("target_type", "bogus", "identifier", identifier,
                "new_name", newName, "variable_name", "local"))), program);

        assertEquals(1, response.content().size());
        String text = assertInstanceOf(McpSchema.TextContent.class, response.content().get(0)).text();
        assertNull(response.structuredContent(), "The existing text-only protocol must not change");
        assertFalse(text.contains("\n"), "Formatting must not add literal line breaks");

        ObjectMapper json = new ObjectMapper();
        var expected = json.valueToTree(Map.of(
            "program", "test-program", "total", 3, "succeeded", 0, "failed", 3,
            "results", List.of(
                Map.of("index", 0, "success", false, "message", "Item is not an object/map"),
                Map.of("index", 1, "success", false, "message",
                    "target_type parameter is required ('function', 'data', or 'variable')"),
                Map.of("index", 2, "target_type", "bogus", "identifier", identifier,
                    "new_name", newName, "variable_name", "local", "success", false,
                    "message", "Invalid target_type. Use 'function', 'data', or 'variable'"))));
        var actual = json.readTree(text);
        assertEquals(expected, actual, "Every existing report and per-item field must survive");
        assertEquals(actual.toString(), text, "Return compact JSON without changing its values");
    }
}
