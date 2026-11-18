package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Exercises the real HTTP transport with no CodeBrowser or loaded program. */
class StreamableHttpIntegrationTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5)).build();
    private GhidrAssistMCPBackend backend;
    private GhidrAssistMCPServer server;
    private URI endpoint;
    private String sessionId;
    private int requestId;

    @BeforeEach
    void startServerWithoutProgram() throws Exception {
        backend = new GhidrAssistMCPBackend();
        server = new GhidrAssistMCPServer("127.0.0.1", 0, backend);
        server.start();
        endpoint = URI.create("http://127.0.0.1:" + server.getBoundPort() + "/mcp");

        HttpResponse<String> initialized = send("initialize", Map.of(
            "protocolVersion", "2025-11-25",
            "capabilities", Map.of(),
            "clientInfo", Map.of("name", "integration-test", "version", "1.0")), true);
        assertEquals(200, initialized.statusCode(), initialized.body());
        assertEquals("2025-11-25", json(initialized).path("result")
            .path("protocolVersion").asText());
        assertEquals("3.1.0", json(initialized).path("result")
            .path("serverInfo").path("version").asText());
        sessionId = initialized.headers().firstValue("Mcp-Session-Id").orElse(null);
        HttpResponse<String> ready = send("notifications/initialized", Map.of(), false);
        assertTrue(ready.statusCode() == 200 || ready.statusCode() == 202, ready.body());
    }

    @AfterEach
    void stopServer() throws Exception {
        if (server != null) {
            server.stop();
        }
        if (backend != null) {
            backend.shutdown();
        }
    }

    @Test
    void discoversExplicitToolsBeforeOpeningAProgram() throws Exception {
        Set<String> names = toolNames();
        assertTrue(names.containsAll(Set.of("get_pseudocode", "get_disassembly",
            "get_function_hash", "get_function_byte_pattern", "get_function_prototype",
            "list_project_files", "open_program", "create_project", "open_project",
            "save_project", "close_project")), names.toString());
        assertFalse(names.contains("get_code"));
        assertFalse(names.contains("get_function_signature"));
        assertFalse(names.contains("scripts"));
    }

    @Test
    void readBeforeProgramOpenReturnsToolError() throws Exception {
        HttpResponse<String> response = send("tools/call", Map.of(
            "name", "get_pseudocode", "arguments", Map.of("function", "main")), true);
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(json(response).path("result").path("isError").asBoolean(), response.body());
    }

    @Test
    void projectControlsReturnToolErrorsWithoutAGuiAndLeaveServerReachable() throws Exception {
        for (String tool : new String[] {"save_project", "close_project"}) {
            HttpResponse<String> response = send("tools/call", Map.of(
                "name", tool, "arguments", Map.of()), true);
            assertEquals(200, response.statusCode(), response.body());
            JsonNode result = json(response).path("result");
            assertTrue(result.path("isError").asBoolean(), response.body());
            assertFalse(result.path("content").toString().contains("No program is open."), response.body());
        }
        assertTrue(toolNames().contains("open_project"));
    }

    @Test
    void resourcesAreTemplatesAndUnknownProgramsFail() throws Exception {
        HttpResponse<String> templates = send("resources/templates/list", Map.of(), true);
        assertEquals(200, templates.statusCode(), templates.body());
        assertEquals(6, json(templates).path("result").path("resourceTemplates").size());
        HttpResponse<String> resources = send("resources/list", Map.of(), true);
        assertEquals(200, resources.statusCode(), resources.body());
        for (JsonNode resource : json(resources).path("result").path("resources")) {
            assertFalse(resource.path("uri").asText().contains("{"));
        }
        HttpResponse<String> missing = send("resources/read", Map.of(
            "uri", "ghidra://program/missing/info"), true);
        assertEquals(200, missing.statusCode(), missing.body());
        assertTrue(json(missing).path("error").isObject(), missing.body());
    }

    @Test
    void rejectsAnUntrustedBrowserOrigin() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(10))
            .header("Origin", "https://untrusted.example")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString("{}"))
            .build();
        assertEquals(403, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void projectDeletionWithoutAProjectReturnsAnError() throws Exception {
        HttpResponse<String> response = send("tools/call", Map.of(
            "name", "delete_project_file", "arguments", Map.of("path", "/missing", "confirm", true)), true);
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(json(response).path("result").path("isError").asBoolean(), response.body());
    }

    @Test
    void toolSettingsUpdateAnExistingClientConnection() throws Exception {
        assertTrue(toolNames().contains("get_pseudocode"));
        backend.setToolEnabled("get_pseudocode", false);
        server.refreshToolCatalog();
        assertFalse(toolNames().contains("get_pseudocode"));
        backend.setToolEnabled("get_pseudocode", true);
        server.refreshToolCatalog();
        assertTrue(toolNames().contains("get_pseudocode"));
    }

    private Set<String> toolNames() throws Exception {
        HttpResponse<String> response = send("tools/list", Map.of(), true);
        assertEquals(200, response.statusCode(), response.body());
        Set<String> names = new HashSet<>();
        for (JsonNode tool : json(response).path("result").path("tools")) {
            names.add(tool.path("name").asText());
        }
        return names;
    }

    private HttpResponse<String> send(String method, Map<String, ?> params,
            boolean hasId) throws Exception {
        Map<String, Object> message = new java.util.LinkedHashMap<>();
        message.put("jsonrpc", "2.0");
        if (hasId) {
            message.put("id", ++requestId);
        }
        message.put("method", method);
        message.put("params", params);
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(message)));
        if (sessionId != null) {
            request.header("Mcp-Session-Id", sessionId);
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private JsonNode json(HttpResponse<String> response) throws Exception {
        String body = response.body();
        if (response.headers().firstValue("Content-Type").orElse("")
                .startsWith("text/event-stream")) {
            String data = body.lines().filter(line -> line.startsWith("data:"))
                .map(line -> line.substring(5).trim())
                .reduce((left, right) -> right).orElseThrow();
            return mapper.readTree(data);
        }
        return mapper.readTree(body);
    }
}
