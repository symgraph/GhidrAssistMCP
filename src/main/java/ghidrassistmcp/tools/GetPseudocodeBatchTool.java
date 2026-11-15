package ghidrassistmcp.tools;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Read several complete decompilations without repeating a tool call and task handle per function. */
public final class GetPseudocodeBatchTool implements McpTool {
    private static final Pattern LINE_END = Pattern.compile("\\R");
    private final SessionFactory sessions;

    public GetPseudocodeBatchTool(DecompilerService service) {
        this(productionSessions(Objects.requireNonNull(service)));
    }

    // Keep the native decompiler behind a small seam so validation, paging and cancellation
    // can be tested without opening a Ghidra database or spawning a native process.
    GetPseudocodeBatchTool(SessionFactory sessions) {
        this.sessions = Objects.requireNonNull(sessions);
    }

    @Override public String getName() { return "get_pseudocode_batch"; }
    @Override public boolean isLongRunning() { return true; }
    @Override public boolean supportsRequestMonitoring() { return true; }
    // A partially successful batch can contain transient failures. Reuse aliases inside
    // this request, but do not replay those failures from the cross-request cache.
    @Override public boolean isCacheable() { return false; }
    @Override public boolean isIdempotent() { return true; }
    @Override public String getDescription() {
        return "Decompile a nonempty list of functions in the same program, in request order. Returns full code by default, " +
            "once in text, with per-function identity, completeness and errors in structured metadata. " +
            "Optional 1-based start_line/max_lines explicitly page each function; omitted max_lines returns all remaining lines.";
    }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "functions", Map.of("type", "array", "minItems", 1,
                "items", Map.of("type", "string", "minLength", 1),
                "description", "Function names, qualified names, or entry/containing addresses"),
            "start_line", Map.of("type", "integer", "minimum", 1, "maximum", Integer.MAX_VALUE, "default", 1,
                "description", "First source line to return for each function (1-based)"),
            "max_lines", Map.of("type", "integer", "minimum", 1, "maximum", Integer.MAX_VALUE,
                "description", "Optional maximum lines per function; omitted means all remaining lines")),
            List.of("functions"), false, null, null);
    }
    @Override public Map<String, Object> getOutputSchema() {
        return Map.of("type", "object", "properties", Map.of(
            "program", Map.of("type", "object", "properties", Map.of(
                "name", Map.of("type", "string"), "project_path", Map.of("type", "string")),
                "required", List.of("name"), "additionalProperties", false),
            "total", Map.of("type", "integer", "minimum", 1),
            "succeeded", Map.of("type", "integer", "minimum", 0),
            "failed", Map.of("type", "integer", "minimum", 0),
            "cancelled", Map.of("type", "integer", "minimum", 0),
            "results", Map.of("type", "array", "minItems", 1,
                "items", itemSchema())),
            "required", List.of("program", "total", "succeeded", "failed", "cancelled", "results"),
            "additionalProperties", false);
    }
    private static Map<String, Object> itemSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("index", Map.of("type", "integer", "minimum", 0));
        properties.put("identifier", Map.of("type", "string"));
        properties.put("name", Map.of("type", List.of("string", "null")));
        properties.put("address", Map.of("type", List.of("string", "null")));
        properties.put("status", Map.of("enum", List.of("success", "error", "cancelled")));
        for (String key : List.of("decompilation_complete", "complete", "truncated")) {
            properties.put(key, Map.of("type", "boolean"));
        }
        for (String key : List.of("total_lines", "start_line", "end_line")) {
            properties.put(key, Map.of("type", List.of("integer", "null"), "minimum", 1));
        }
        properties.put("returned_lines", Map.of("type", "integer", "minimum", 0));
        properties.put("error", Map.of("type", "object", "properties", Map.of(
            "code", Map.of("type", "string"), "message", Map.of("type", "string")),
            "required", List.of("code", "message"), "additionalProperties", false));
        return Map.of("type", "object", "properties", properties, "required", List.of(
            "index", "identifier", "name", "address", "status", "decompilation_complete",
            "complete", "truncated", "total_lines", "start_line", "end_line", "returned_lines"),
            "additionalProperties", false);
    }

    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        return execute(arguments, program, TaskMonitor.DUMMY);
    }
    @Override public McpSchema.CallToolResult executeMonitored(Map<String, Object> arguments, Program program,
            GhidrAssistMCPBackend backend, TaskMonitor monitor) {
        return execute(arguments, program, monitor == null ? TaskMonitor.DUMMY : monitor);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        return execute(arguments, program, task == null ? TaskMonitor.DUMMY
            : new McpTaskMonitor(task, 0, 100, "Decompiling functions"));
    }

    private McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
            TaskMonitor monitor) {
        if (program == null) return error("No program currently loaded");
        if (program.isClosed()) return error("Program is closed");
        if (!(arguments.get("functions") instanceof List<?> requested) || requested.isEmpty()) {
            return error("functions must contain at least one function identifier");
        }
        List<String> identifiers = new ArrayList<>(requested.size());
        for (Object value : requested) {
            if (!(value instanceof String identifier) || identifier.isBlank()) {
                return error("Every functions item must be a nonblank string");
            }
            identifiers.add(identifier);
        }
        int firstLine;
        Integer maxLines;
        try {
            firstLine = positiveInteger(arguments, "start_line", 1);
            maxLines = positiveInteger(arguments, "max_lines", null);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        }

        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("name", program.getName());
        if (program.getDomainFile() != null) {
            identity.put("project_path", program.getDomainFile().getPathname());
        }
        StringBuilder text = new StringBuilder("Program: ").append(program.getName());
        if (identity.containsKey("project_path")) text.append(" (").append(identity.get("project_path")).append(')');
        text.append('\n');
        List<Map<String, Object>> items = new ArrayList<>(identifiers.size());
        Map<Address, Decompilation> decompiled = new HashMap<>();
        BatchSession session = null;
        String initializationError = null;
        int succeeded = 0;
        int cancelled = 0;
        try (BatchProgressMonitor progress = new BatchProgressMonitor(monitor, identifiers.size())) {
            for (int index = 0; index < identifiers.size(); index++) {
                String identifier = identifiers.get(index);
                TaskMonitor nativeMonitor = progress.beginItem(index, identifier);
                Map<String, Object> item = item(index, identifier);
                items.add(item);
                if (progress.isCancelled()) {
                    fail(item, "cancelled", "cancelled", "Decompilation cancelled");
                    cancelled++;
                } else {
                    try {
                        ghidra.program.model.listing.Function function = FunctionLookup.findByName(program, identifier);
                        if (function == null) {
                            fail(item, "error", "not_found", "Function not found");
                        } else {
                            item.put("name", function.getName(true));
                            item.put("address", function.getEntryPoint().toString());
                            if (session == null && initializationError == null) {
                                try { session = sessions.open(program); }
                                catch (Exception e) { initializationError = message(e); }
                            }
                            if (initializationError != null) {
                                fail(item, "error", "decompiler_initialization", initializationError);
                            } else {
                                Decompilation result = decompiled.get(function.getEntryPoint());
                                if (result == null) {
                                    result = session.decompile(function, nativeMonitor);
                                    decompiled.put(function.getEntryPoint(), result);
                                }
                                if (progress.isCancelled()) {
                                    fail(item, "cancelled", "cancelled", "Decompilation cancelled");
                                    cancelled++;
                                } else if (result.errorCode() != null) {
                                    fail(item, "error", result.errorCode(), result.error());
                                } else if (result.code() == null || result.code().isBlank()) {
                                    fail(item, "error", "empty_code", "No decompiled code available");
                                } else {
                                    if (appendCode(text, item, result.code(), firstLine, maxLines)) succeeded++;
                                }
                            }
                        }
                    } catch (Exception e) {
                        if (progress.isCancelled()) {
                            fail(item, "cancelled", "cancelled", "Decompilation cancelled");
                            cancelled++;
                        } else fail(item, "error", "decompilation_error", message(e));
                    }
                }
                if (!"success".equals(item.get("status"))) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> failure = (Map<String, String>) item.get("error");
                    text.append(index).append(": ").append(identifier).append(" [")
                        .append(item.get("status")).append("] ").append(failure.get("code"))
                        .append(": ").append(failure.get("message")).append('\n');
                }
                progress.completeItem();
            }
        } finally {
            if (session != null) session.close();
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("program", identity);
        metadata.put("total", identifiers.size());
        metadata.put("succeeded", succeeded);
        metadata.put("failed", identifiers.size() - succeeded - cancelled);
        metadata.put("cancelled", cancelled);
        metadata.put("results", items);
        // Source appears only here, never duplicated in structuredContent.
        return McpSchema.CallToolResult.builder().addTextContent(text.toString())
            .structuredContent(metadata).isError(succeeded == 0 || cancelled != 0).build();
    }

    private static Map<String, Object> item(int index, String identifier) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("index", index);
        result.put("identifier", identifier);
        result.put("name", null);
        result.put("address", null);
        result.put("status", "error");
        result.put("decompilation_complete", false);
        result.put("complete", false);
        result.put("truncated", false);
        result.put("total_lines", null);
        result.put("start_line", null);
        result.put("end_line", null);
        result.put("returned_lines", 0);
        return result;
    }
    private static void fail(Map<String, Object> item, String status, String code, String message) {
        item.put("status", status);
        item.put("error", Map.of("code", code, "message", message));
    }
    private static boolean appendCode(StringBuilder text, Map<String, Object> item, String code,
            int firstLine, Integer maxLines) {
        List<Integer> starts = new ArrayList<>();
        starts.add(0);
        Matcher endings = LINE_END.matcher(code);
        while (endings.find()) if (endings.end() < code.length()) starts.add(endings.end());
        int total = starts.size();
        item.put("decompilation_complete", true);
        item.put("total_lines", total);
        if (firstLine > total) {
            item.put("truncated", true);
            fail(item, "error", "line_out_of_range", "start_line " + firstLine + " exceeds total_lines " + total);
            return false;
        }
        int lastLine = maxLines == null ? total : (int) Math.min(total, (long) firstLine + maxLines - 1);
        boolean truncated = firstLine != 1 || lastLine != total;
        item.put("status", "success");
        item.put("complete", !truncated);
        item.put("truncated", truncated);
        item.put("start_line", firstLine);
        item.put("end_line", lastLine);
        item.put("returned_lines", lastLine - firstLine + 1);
        String page = code.substring(starts.get(firstLine - 1), lastLine == total ? code.length() : starts.get(lastLine));
        text.append(item.get("index")).append(": ").append(item.get("name")).append(" @ ")
            .append(item.get("address")).append(" [lines ").append(firstLine).append('-')
            .append(lastLine).append('/').append(total).append(truncated ? "; truncated]\n" : "; complete]\n")
            .append(page);
        if (!page.endsWith("\n") && !page.endsWith("\r")) text.append('\n');
        return true;
    }
    private static Integer positiveInteger(Map<String, Object> arguments, String name, Integer defaultValue) {
        if (!arguments.containsKey(name)) return defaultValue;
        Object value = arguments.get(name);
        try {
            if (value instanceof Number number) {
                int integer = new BigDecimal(number.toString()).intValueExact();
                if (integer >= 1) return integer;
            }
        } catch (ArithmeticException | NumberFormatException ignored) {
            // Reject fractional/oversized values and NaN/Infinity without coercion.
        }
        throw new IllegalArgumentException(name + " must be an integer between 1 and " + Integer.MAX_VALUE);
    }
    private static String message(Exception error) {
        return error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage();
    }
    private static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().addTextContent(message).isError(true).build();
    }

    @FunctionalInterface interface SessionFactory { BatchSession open(Program program); }
    interface BatchSession extends AutoCloseable {
        Decompilation decompile(ghidra.program.model.listing.Function function, TaskMonitor monitor) throws Exception;
        @Override void close();
    }
    record Decompilation(String code, String errorCode, String error) {
        static Decompilation success(String code) { return new Decompilation(code, null, null); }
        static Decompilation failure(String code, String error) { return new Decompilation(null, code, error); }
    }
    private static SessionFactory productionSessions(DecompilerService service) {
        return program -> {
            DecompilerSession session = service.open(program);
            return new BatchSession() {
                @Override public Decompilation decompile(ghidra.program.model.listing.Function function,
                        TaskMonitor monitor) {
                    DecompileResults result = session.decompiler().decompileFunction(function,
                        session.options().getDefaultTimeout(), monitor);
                    if (result == null) return Decompilation.failure("decompilation_error", "Decompiler returned no result");
                    if (result.isTimedOut()) return Decompilation.failure("timeout", "Decompilation timed out");
                    if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                        String error = result.getErrorMessage();
                        return Decompilation.failure("decompilation_error",
                            error == null || error.isBlank() ? "Decompilation did not complete" : error);
                    }
                    return Decompilation.success(result.getDecompiledFunction().getC());
                }
                @Override public void close() { session.close(); }
            };
        };
    }
}
