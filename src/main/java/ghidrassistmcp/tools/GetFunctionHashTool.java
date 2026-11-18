package ghidrassistmcp.tools;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

/** A real digest of function bytes, distinct from masked matching patterns and C prototypes. */
public final class GetFunctionHashTool implements McpTool {
    @Override public String getName() { return "get_function_hash"; }
    @Override public String getLegacyName() { return "get_function_signature"; }
    @Override public boolean isCacheable() { return true; }
    @Override public boolean isIdempotent() { return true; }
    @Override public boolean isLongRunning() { return true; }
    @Override public String getDescription() {
        return "Compute SHA-256 over every byte in the function body, visiting all body ranges in ascending address order. " +
            "Returns the digest, byte count, and range count. Use get_function_byte_pattern for the masked prefix pattern or get_function_prototype for its C declaration.";
    }
    @Override public JsonSchema getInputSchema() {
        return new JsonSchema("object", Map.of("function", Map.of("type", "string",
            "description", "Function name, qualified name, entry address, or address inside its body")),
            List.of("function"), false, null, null);
    }
    @Override public Map<String, Object> getOutputSchema() {
        return Map.of("type", "object", "properties", Map.of("name", Map.of("type", "string"), "address", Map.of("type", "string"),
                "algorithm", Map.of("type", "string", "const", "SHA-256"),
                "hash", Map.of("type", "string", "pattern", "^[0-9a-f]{64}$"),
                "bytes_hashed", Map.of("type", "integer", "minimum", 1),
                "range_count", Map.of("type", "integer", "minimum", 1),
                "byte_order", Map.of("type", "string", "const", "ascending_body_address")),
            "required", List.of("name", "address", "algorithm", "hash", "bytes_hashed", "range_count", "byte_order"), "additionalProperties", false);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        return hash(arguments, program, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        return hash(arguments, program, task);
    }
    private McpSchema.CallToolResult hash(Map<String, Object> arguments, Program program, McpTask task) {
        if (program == null) return error("No program currently loaded");
        if (!(arguments.get("function") instanceof String identifier) || identifier.isBlank()) {
            return error("Missing required parameter: function");
        }
        Function function = resolve(program, identifier);
        if (function == null) return error("Function not found: " + identifier);
        if (function.isExternal() || function.getBody().isEmpty()) {
            return error("Function has no readable body bytes: " + identifier);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            long hashed = 0;
            int ranges = 0;
            long total = function.getBody().getNumAddresses();
            AddressRangeIterator iterator = function.getBody().getAddressRanges(true);
            while (iterator.hasNext()) {
                AddressRange range = iterator.next();
                long remaining = range.getLength();
                Address address = range.getMinAddress();
                ranges++;
                while (remaining > 0) {
                    if (Thread.currentThread().isInterrupted() || task != null && task.getStatus() == McpTask.Status.CANCELLED) {
                        return error("Function hashing cancelled");
                    }
                    int count = (int) Math.min(buffer.length, remaining);
                    int read = program.getMemory().getBytes(address, buffer, 0, count);
                    if (read != count) return error("Unable to read complete function body at " + address);
                    digest.update(buffer, 0, read);
                    hashed += read;
                    remaining -= read;
                    if (remaining > 0) address = address.add(read);
                    if (task != null) task.updateProgress((int) (100.0 * hashed / total), "Hashing function bytes");
                }
            }
            Map<String, Object> result = Map.of("name", function.getName(true),
                "address", function.getEntryPoint().toString(), "algorithm", "SHA-256",
                "hash", HexFormat.of().formatHex(digest.digest()), "bytes_hashed", hashed,
                "range_count", ranges, "byte_order", "ascending_body_address");
            return McpSchema.CallToolResult.builder().structuredContent(result)
                .addContent(McpSchema.TextContent.builder(new ObjectMapper().writeValueAsString(result)).build()).build();
        } catch (Exception e) {
            return error("Error hashing function bytes: " + e.getMessage());
        }
    }
    static Function resolve(Program program, String identifier) {
        try {
            Address address = program.getAddressFactory().getAddress(identifier);
            if (address != null) {
                Function function = program.getFunctionManager().getFunctionAt(address);
                if (function != null) return function;
                function = program.getFunctionManager().getFunctionContaining(address);
                if (function != null) return function;
            }
        } catch (Exception ignored) {
            // A name is not necessarily an address.
        }
        return FunctionLookup.findByQualifiedName(program, identifier);
    }
    private static McpSchema.CallToolResult error(String text) {
        return McpSchema.CallToolResult.builder().isError(true).addContent(McpSchema.TextContent.builder(text).build()).build();
    }
}
