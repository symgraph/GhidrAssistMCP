package ghidrassistmcp;

import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Stateless MCP 2026-07-28 requests: each one carries its own _meta and mirrored headers. */
final class ModernMcpRequests {
    static final String PROTOCOL_VERSION = "2026-07-28";
    static final String SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo";
    private static final ObjectMapper JSON = new ObjectMapper();

    private ModernMcpRequests() {
    }

    /** A request when id is non-null, otherwise a notification; params._meta entries are kept. */
    static Map<String, Object> message(Object id, String method, Map<String, ?> params) {
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("io.modelcontextprotocol/protocolVersion", PROTOCOL_VERSION);
        meta.put("io.modelcontextprotocol/clientCapabilities", Map.of());
        meta.put("io.modelcontextprotocol/clientInfo", Map.of("name", "integration-test", "version", "1.0"));
        Map<String, Object> withMeta = new LinkedHashMap<>(params);
        if (params.get("_meta") instanceof Map<?, ?> extra) {
            extra.forEach((key, value) -> meta.put(String.valueOf(key), value));
        }
        withMeta.put("_meta", meta);
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("jsonrpc", "2.0");
        if (id != null) {
            message.put("id", id);
        }
        message.put("method", method);
        message.put("params", withMeta);
        return message;
    }

    static HttpRequest request(URI endpoint, Map<String, Object> message, Duration timeout) throws Exception {
        String method = (String) message.get("method");
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint).timeout(timeout)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Method", method)
            .header("MCP-Protocol-Version", PROTOCOL_VERSION)
            .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(message)));
        Map<?, ?> params = (Map<?, ?>) message.get("params");
        Object name = switch (method) {
            case "tools/call", "prompts/get" -> params.get("name");
            case "resources/read" -> params.get("uri");
            default -> null;
        };
        if (name != null) {
            request.header("Mcp-Name", name.toString());
        }
        return request.build();
    }

    /** A result without the fields the modern server adds to every response. */
    static JsonNode withoutProtocolFields(JsonNode result) {
        ObjectNode copy = result.deepCopy();
        copy.remove("resultType");
        if (copy.get("_meta") instanceof ObjectNode meta) {
            meta.remove(SERVER_INFO_KEY);
            if (meta.isEmpty()) {
                copy.remove("_meta");
            }
        }
        return copy;
    }
}
