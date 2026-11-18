package ghidrassistmcp.protocol;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A tool's input schema. The modern SDK types schemas as plain maps; this record keeps
 * the classic SDK's components and wire form so tool contracts stay declarative. Nested
 * schemas, such as property values, serialize through Jackson in the same form.
 */
@JsonInclude(JsonInclude.Include.NON_ABSENT)
public record JsonSchema(String type, Map<String, Object> properties, List<String> required,
        Boolean additionalProperties, @JsonProperty("$defs") Map<String, Object> defs,
        Map<String, Object> definitions) {

    /** The JSON object form, omitting absent components as the classic SDK did. */
    public Map<String, Object> toMap() {
        Map<String, Object> schema = new LinkedHashMap<>();
        putIfPresent(schema, "type", type);
        putIfPresent(schema, "properties", properties);
        putIfPresent(schema, "required", required);
        putIfPresent(schema, "additionalProperties", additionalProperties);
        putIfPresent(schema, "$defs", defs);
        putIfPresent(schema, "definitions", definitions);
        return schema;
    }

    private static void putIfPresent(Map<String, Object> schema, String key, Object value) {
        if (value != null) {
            schema.put(key, value);
        }
    }
}
