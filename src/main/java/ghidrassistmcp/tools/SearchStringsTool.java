package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.modern.McpSchema;
import ghidrassistmcp.protocol.JsonSchema;

public class SearchStringsTool implements McpTool {

    @Override
    public boolean isCacheable() { return true; }

    @Override
    public String getName() { return "search_strings"; }

    @Override
    public String getDescription() { return "Search for strings matching a pattern in the program"; }

    @Override
    public JsonSchema getInputSchema() {
        return new JsonSchema("object",
            Map.of(
                "pattern", Map.of("type", "string", "description", "Search pattern to match against string content"),
                "case_sensitive", Map.of("type", "boolean", "description", "Case sensitive search (default false)"),
                "limit", Map.of("type", "integer", "description", "Maximum results (default 100)")
            ),
            List.of("pattern"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("No program currently loaded").build()).build();
        }

        String pattern = (String) arguments.get("pattern");
        if (pattern == null || pattern.isEmpty()) {
            return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder("pattern is required").build()).build();
        }

        boolean caseSensitive = Boolean.TRUE.equals(arguments.get("case_sensitive"));
        int limit = 100;
        if (arguments.get("limit") instanceof Number) limit = ((Number) arguments.get("limit")).intValue();

        String searchPattern = caseSensitive ? pattern : pattern.toLowerCase();

        StringBuilder result = new StringBuilder();
        result.append("Strings matching \"").append(pattern).append("\":\n\n");

        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext() && count < limit) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String stringValue = data.getDefaultValueRepresentation();
                String text = extractStringText(stringValue);
                if (text != null) {
                    String compareText = caseSensitive ? text : text.toLowerCase();
                    if (compareText.contains(searchPattern)) {
                        String display = stringValue.length() > 80 ? stringValue.substring(0, 77) + "..." : stringValue;
                        result.append("@ ").append(data.getAddress()).append(": ").append(display).append("\n");
                        count++;
                    }
                }
            }
        }

        if (count == 0) {
            result.append("No strings found matching: ").append(pattern);
        } else {
            result.append("\nFound ").append(count).append(" matching strings");
        }

        return McpSchema.CallToolResult.builder().addContent(McpSchema.TextContent.builder(result.toString()).build()).build();
    }

    private static String extractStringText(String repr) {
        if (repr == null) return null;
        int first = repr.indexOf('"');
        int last = repr.lastIndexOf('"');
        if (first >= 0 && last > first) return repr.substring(first + 1, last);
        return repr;
    }
}
