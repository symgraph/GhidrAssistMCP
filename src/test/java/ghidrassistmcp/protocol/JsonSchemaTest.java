package ghidrassistmcp.protocol;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

class JsonSchemaTest {
    @Test void mapUsesWireKeywordsAndOmitsAbsentComponents() {
        Map<String, Object> defs = Map.of("item", Map.of("type", "string"));
        JsonSchema schema = new JsonSchema("object", Map.of("name", Map.of("$ref", "#/$defs/item")),
            List.of("name"), false, defs, null);
        assertEquals(List.of("type", "properties", "required", "additionalProperties", "$defs"),
            List.copyOf(schema.toMap().keySet()));
        assertEquals(defs, schema.toMap().get("$defs"));
        assertEquals(Map.of("type", "object"),
            new JsonSchema("object", null, null, null, null, null).toMap());
    }

    @Test void nestedSchemasSerializeInTheSameWireForm() throws Exception {
        JsonSchema nested = new JsonSchema("string", null, null, null, Map.of(), null);
        JsonSchema schema = new JsonSchema("object", Map.of("name", nested), List.of("name"), false, null, null);
        assertEquals("{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\",\"$defs\":{}}},"
            + "\"required\":[\"name\"],\"additionalProperties\":false}",
            new ObjectMapper().writeValueAsString(schema.toMap()));
    }
}
