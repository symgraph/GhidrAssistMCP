package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/** An advertised, operation-specific contract over an existing implementation. */
public final class ExplicitTool implements McpTool {
    private final McpTool delegate;
    private final String name;
    private final String description;
    private final Map<String, Object> fixed = new LinkedHashMap<>();
    private final Map<String, String> aliases = new LinkedHashMap<>();
    private List<String> parameters;
    private List<String> required;
    private List<String> alternatives = List.of();
    private boolean readOnly;
    private boolean destructive;
    private boolean idempotent;
    private boolean longRunning;
    private boolean programSelection = true;
    private boolean programContext = true;

    public ExplicitTool(McpTool delegate, String name, String description) {
        this.delegate = delegate;
        this.name = name;
        this.description = description;
        readOnly = delegate.isReadOnly();
        destructive = delegate.isDestructive();
        idempotent = delegate.isIdempotent();
        longRunning = delegate.isLongRunning();
    }

    public ExplicitTool select(String key, Object value) { fixed.put(key, value); return this; }
    public ExplicitTool parameters(String... names) { parameters = List.of(names); return this; }
    public ExplicitTool required(String... names) { required = List.of(names); return this; }
    public ExplicitTool oneOfParameters(String... names) { alternatives = List.of(names); return this; }
    public ExplicitTool alias(String advertised, String implementation) {
        aliases.put(advertised, implementation); return this;
    }
    public ExplicitTool readOnly() {
        readOnly = true; destructive = false; idempotent = true; return this;
    }
    public ExplicitTool mutation(boolean mayDestroy, boolean repeatable) {
        readOnly = false; destructive = mayDestroy; idempotent = repeatable; return this;
    }
    public ExplicitTool longRunning(boolean value) { longRunning = value; return this; }
    public ExplicitTool context(boolean selection, boolean requiredProgram) {
        programSelection = selection; programContext = requiredProgram; return this;
    }

    @Override public String getName() { return name; }
    @Override public String getLegacyName() { return delegate.getName(); }
    @Override public String getDescription() { return description; }
    @Override public boolean isReadOnly() { return readOnly; }
    @Override public boolean isDestructive() { return destructive; }
    @Override public boolean isIdempotent() { return idempotent; }
    @Override public boolean isOpenWorld() { return delegate.isOpenWorld(); }
    @Override public boolean isLongRunning() { return longRunning; }
    @Override public boolean supportsRequestMonitoring() { return delegate.supportsRequestMonitoring(); }
    @Override public boolean isCacheable() { return readOnly && delegate.isCacheable(); }
    @Override public boolean supportsProgramSelection() { return programSelection; }
    @Override public boolean requiresProgramContext() { return programContext; }
    @Override public boolean requiresProgramContext(Map<String, Object> arguments) {
        return programContext && delegate.requiresProgramContext(translate(arguments));
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        McpSchema.JsonSchema source = delegate.getInputSchema();
        Map<String, Object> original = source.properties() == null ? Map.of() : source.properties();
        Map<String, Object> properties = new LinkedHashMap<>();
        List<String> names = parameters == null ? new ArrayList<>(original.keySet()) : parameters;
        for (String key : names) {
            String implementation = aliases.getOrDefault(key, key);
            if (!fixed.containsKey(implementation) && original.containsKey(implementation)) {
                properties.put(key, describeParameter(key, original.get(implementation)));
            }
        }
        List<String> requiredNames = required == null
            ? source.required() == null ? List.of() : source.required().stream()
                .filter(properties::containsKey).toList()
            : required;
        return new McpSchema.JsonSchema("object", properties, requiredNames, false,
            source.defs(), source.definitions());
    }

    private Object describeParameter(String key, Object schema) {
        Map<String, Object> property = new LinkedHashMap<>();
        if (schema instanceof Map<?, ?> raw) {
            raw.forEach((k, v) -> property.put(String.valueOf(k), v));
        } else if (schema instanceof McpSchema.JsonSchema typed) {
            property.put("type", typed.type());
        } else {
            return schema;
        }
        if (key.equals("function")) {
            property.put("description", "Function name, C++ qualified name, or entry/containing address (for example 0x401000).");
        }
        if (key.equals("address")) {
            property.put("description", "Target address as a hexadecimal string, for example 0x401000.");
        }
        if (key.equals("structure_name")) {
            property.put("description", "Name of the target structure data type.");
        }
        if (key.equals("field_offset")) {
            property.put("description", "Offset of the structure field in bytes.");
            property.put("minimum", 0);
        }
        if (key.equals("field_name")) {
            property.put("description", name.equals("get_structure_field_xrefs")
                ? "Existing field name to find references for; provide field_name or field_offset."
                : "Name to assign to the structure field or gap.");
        }
        if (key.equals("offset")) {
            property.putIfAbsent("minimum", 0); property.putIfAbsent("default", 0);
        }
        if (key.equals("limit")) {
            property.putIfAbsent("minimum", 1); property.putIfAbsent("maximum", 10000);
            property.putIfAbsent("default", 100);
        }
        if (key.equals("length")) {
            property.put("type", "integer"); property.putIfAbsent("minimum", 1);
            property.putIfAbsent("maximum", name.equals("get_hexdump") ? 65536 : 4096);
        }
        return property;
    }

    /** Fixed operation discriminators cannot be overridden by client arguments. */
    private Map<String, Object> translate(Map<String, Object> arguments) {
        Map<String, Object> translated = new HashMap<>(arguments);
        for (Map.Entry<String, String> alias : aliases.entrySet()) {
            if (arguments.containsKey(alias.getKey())) {
                translated.remove(alias.getKey());
                translated.put(alias.getValue(), arguments.get(alias.getKey()));
            }
        }
        translated.putAll(fixed);
        return translated;
    }

    private McpSchema.CallToolResult validate(Map<String, Object> arguments) {
        McpSchema.JsonSchema schema = getInputSchema();
        for (String key : schema.required()) {
            Object value = arguments.get(key);
            if (value == null || value instanceof String text && text.isBlank() && !key.equals("comment")) {
                return error("Missing required parameter: " + key);
            }
        }
        if (!alternatives.isEmpty() && alternatives.stream().noneMatch(key -> arguments.get(key) != null &&
                (!(arguments.get(key) instanceof String value) || !value.isBlank()))) {
            return error("Provide one of: " + String.join(", ", alternatives));
        }
        for (String key : arguments.keySet()) {
            if (!schema.properties().containsKey(key) &&
                    !(programSelection && key.equals("program_name"))) {
                return error("Unknown parameter for " + name + ": " + key);
            }
            Object descriptor = schema.properties().get(key);
            if (descriptor instanceof Map<?, ?> property) {
                Object value = arguments.get(key);
                String type = String.valueOf(property.get("type"));
                boolean validType = switch (type) {
                    case "string" -> value instanceof String;
                    case "boolean" -> value instanceof Boolean;
                    case "integer", "number" -> value instanceof Number;
                    case "array" -> value instanceof List<?>;
                    case "object" -> value instanceof Map<?, ?>;
                    default -> true;
                };
                if (!validType) return error(key + " must have type " + type);
                if (property.get("enum") instanceof List<?> values && !values.contains(value)) {
                    return error("Invalid value for " + key + ": " + value);
                }
            }
            if (descriptor instanceof Map<?, ?> property && arguments.get(key) instanceof Number number) {
                double value = number.doubleValue();
                if ("integer".equals(property.get("type")) && (!Double.isFinite(value) || value != Math.rint(value))) {
                    return error(key + " must be an integer");
                }
                if (property.get("minimum") instanceof Number min && value < min.doubleValue() ||
                        property.get("maximum") instanceof Number max && value > max.doubleValue()) {
                    return error(key + " is outside its allowed range");
                }
            }
        }
        return null;
    }

    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().isError(true).addTextContent(message).build();
    }

    @Override
    public String getCacheDiscriminator(Map<String, Object> arguments, Program program,
            GhidrAssistMCPBackend backend) {
        return delegate.getCacheDiscriminator(translate(arguments), program, backend);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        McpSchema.CallToolResult failure = validate(arguments);
        return failure == null ? delegate.execute(translate(arguments), program) : failure;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
            GhidrAssistMCPBackend backend) {
        McpSchema.CallToolResult failure = validate(arguments);
        return failure == null ? delegate.execute(translate(arguments), program, backend) : failure;
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        McpSchema.CallToolResult failure = validate(arguments);
        return failure == null ? delegate.execute(translate(arguments), program, backend, task) : failure;
    }
}
