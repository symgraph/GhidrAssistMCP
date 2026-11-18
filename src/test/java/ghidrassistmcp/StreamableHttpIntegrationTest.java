package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Exercises the real HTTP transport with no CodeBrowser or loaded program. */
class StreamableHttpIntegrationTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(10);
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5)).build();
    private GhidrAssistMCPBackend backend;
    private GhidrAssistMCPServer server;
    private URI endpoint;
    private int requestId;

    @BeforeEach
    void startServerWithoutProgram() throws Exception {
        backend = new GhidrAssistMCPBackend();
        server = new GhidrAssistMCPServer("127.0.0.1", 0, backend);
        server.start();
        endpoint = URI.create("http://127.0.0.1:" + server.getBoundPort() + "/mcp");
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
    void discoverAdvertisesTheModernRevisionAndServerVersion() throws Exception {
        HttpResponse<String> discovered = send("server/discover", Map.of());
        assertEquals(200, discovered.statusCode(), discovered.body());
        JsonNode result = json(discovered).path("result");
        assertEquals(List.of(ModernMcpRequests.PROTOCOL_VERSION),
            mapper.convertValue(result.path("supportedVersions"), List.class));
        assertTrue(result.path("capabilities").path("tools").path("listChanged").asBoolean(), discovered.body());
        assertTrue(result.path("instructions").asText().contains("get_task_status"), discovered.body());
        assertEquals("3.0.0", result.path("_meta").path(ModernMcpRequests.SERVER_INFO_KEY)
            .path("version").asText(), discovered.body());
    }

    @Test
    void legacyInitializeIsRejectedWithTheSupportedVersions() throws Exception {
        String body = mapper.writeValueAsString(Map.of("jsonrpc", "2.0", "id", 1, "method", "initialize",
            "params", Map.of("protocolVersion", "2025-11-25", "capabilities", Map.of(),
                "clientInfo", Map.of("name", "legacy-client", "version", "1.0"))));
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(endpoint).timeout(TIMEOUT)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(400, response.statusCode(), response.body());
        JsonNode error = json(response).path("error");
        assertEquals(-32022, error.path("code").asInt(), response.body());
        assertEquals(List.of(ModernMcpRequests.PROTOCOL_VERSION),
            mapper.convertValue(error.path("data").path("supported"), List.class), response.body());
    }

    @Test
    void legacySseEndpointsAreGone() throws Exception {
        URI origin = endpoint.resolve("/");
        HttpResponse<String> sse = client.send(HttpRequest.newBuilder(origin.resolve("/sse")).timeout(TIMEOUT)
            .header("Accept", "text/event-stream").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(404, sse.statusCode(), sse.body());
        HttpResponse<String> stream = client.send(HttpRequest.newBuilder(endpoint).timeout(TIMEOUT)
            .header("Accept", "text/event-stream").GET().build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(405, stream.statusCode(), stream.body());
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
            "name", "get_pseudocode", "arguments", Map.of("function", "main")));
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(json(response).path("result").path("isError").asBoolean(), response.body());
    }

    @Test
    void unknownToolIsAProtocolError() throws Exception {
        HttpResponse<String> response = send("tools/call", Map.of(
            "name", "get_code", "arguments", Map.of()));
        assertEquals(400, response.statusCode(), response.body());
        assertEquals(-32602, json(response).path("error").path("code").asInt(), response.body());
    }

    @Test
    void projectControlsReturnToolErrorsWithoutAGuiAndLeaveServerReachable() throws Exception {
        for (String tool : new String[] {"save_project", "close_project"}) {
            HttpResponse<String> response = send("tools/call", Map.of(
                "name", tool, "arguments", Map.of()));
            assertEquals(200, response.statusCode(), response.body());
            JsonNode result = json(response).path("result");
            assertTrue(result.path("isError").asBoolean(), response.body());
            assertFalse(result.path("content").toString().contains("No program is open."), response.body());
        }
        assertTrue(toolNames().contains("open_project"));
    }

    @Test
    void resourcesAreTemplatesAndUnknownProgramsFail() throws Exception {
        HttpResponse<String> templates = send("resources/templates/list", Map.of());
        assertEquals(200, templates.statusCode(), templates.body());
        assertEquals(6, json(templates).path("result").path("resourceTemplates").size());
        HttpResponse<String> resources = send("resources/list", Map.of());
        assertEquals(200, resources.statusCode(), resources.body());
        assertEquals(0, json(resources).path("result").path("resources").size(), resources.body());
        for (String uri : new String[] {"ghidra://program/missing/info", "ghidra://unknown"}) {
            HttpResponse<String> missing = send("resources/read", Map.of("uri", uri));
            assertEquals(400, missing.statusCode(), missing.body());
            JsonNode error = json(missing).path("error");
            assertEquals(-32602, error.path("code").asInt(), missing.body());
            assertEquals(uri, error.path("data").path("uri").asText(), missing.body());
        }
    }

    @Test
    void promptsAreListedAndRendered() throws Exception {
        HttpResponse<String> prompts = send("prompts/list", Map.of());
        assertEquals(200, prompts.statusCode(), prompts.body());
        assertEquals(7, json(prompts).path("result").path("prompts").size(), prompts.body());
        HttpResponse<String> prompt = send("prompts/get", Map.of(
            "name", "analyze_function", "arguments", Map.of("function_name", "main")));
        assertEquals(200, prompt.statusCode(), prompt.body());
        assertTrue(json(prompt).path("result").path("messages").size() > 0, prompt.body());
    }

    @Test
    void rejectsAnUntrustedBrowserOrigin() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(endpoint)
            .timeout(TIMEOUT)
            .header("Origin", "https://untrusted.example")
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString("{}"))
            .build();
        assertEquals(403, client.send(request, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void acceptsTheBoundLocalBrowserOrigin() throws Exception {
        Map<String, Object> message = ModernMcpRequests.message(++requestId, "tools/list", Map.of());
        HttpRequest request = HttpRequest.newBuilder(ModernMcpRequests.request(endpoint, message, TIMEOUT),
            (name, value) -> true).header("Origin", "http://localhost:" + server.getBoundPort()).build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
    }

    @Test
    void projectDeletionWithoutAProjectReturnsAnError() throws Exception {
        HttpResponse<String> response = send("tools/call", Map.of(
            "name", "delete_project_file", "arguments", Map.of("path", "/missing", "confirm", true)));
        assertEquals(200, response.statusCode(), response.body());
        assertTrue(json(response).path("result").path("isError").asBoolean(), response.body());
    }

    @Test
    void toolSettingsApplyToTheNextRequest() throws Exception {
        assertTrue(toolNames().contains("get_pseudocode"));
        backend.setToolEnabled("get_pseudocode", false);
        assertFalse(toolNames().contains("get_pseudocode"));
        backend.setToolEnabled("get_pseudocode", true);
        assertTrue(toolNames().contains("get_pseudocode"));
    }

    @Test
    void catalogRefreshNotifiesListeningClients() throws Exception {
        ExecutorService events = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "listen-test-reader");
            thread.setDaemon(true);
            return thread;
        });
        InputStream stream = null;
        try {
            Map<String, Object> listen = ModernMcpRequests.message(++requestId, "subscriptions/listen",
                Map.of("notifications", Map.of("toolsListChanged", true)));
            HttpResponse<InputStream> response = client.send(ModernMcpRequests.request(endpoint, listen,
                Duration.ofSeconds(30)), HttpResponse.BodyHandlers.ofInputStream());
            assertEquals(200, response.statusCode());
            stream = response.body();
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
            JsonNode acknowledged = mapper.readTree(readData(events, reader));
            assertEquals("notifications/subscriptions/acknowledged", acknowledged.path("method").asText(),
                acknowledged.toString());
            assertTrue(acknowledged.path("params").path("notifications").path("toolsListChanged").asBoolean(),
                acknowledged.toString());

            server.refreshToolCatalog();
            JsonNode changed = mapper.readTree(readData(events, reader));
            assertEquals("notifications/tools/list_changed", changed.path("method").asText(), changed.toString());
        } finally {
            if (stream != null) stream.close();
            events.shutdownNow();
        }
    }

    private Set<String> toolNames() throws Exception {
        HttpResponse<String> response = send("tools/list", Map.of());
        assertEquals(200, response.statusCode(), response.body());
        Set<String> names = new HashSet<>();
        for (JsonNode tool : json(response).path("result").path("tools")) {
            names.add(tool.path("name").asText());
        }
        return names;
    }

    private HttpResponse<String> send(String method, Map<String, ?> params) throws Exception {
        return client.send(ModernMcpRequests.request(endpoint,
            ModernMcpRequests.message(++requestId, method, params), TIMEOUT), HttpResponse.BodyHandlers.ofString());
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

    private static String readData(ExecutorService events, BufferedReader reader) throws Exception {
        return events.submit(() -> {
            for (String line; (line = reader.readLine()) != null;) {
                if (line.startsWith("data:")) return line.substring(5).trim();
            }
            throw new IllegalStateException("Event stream closed before the expected event");
        }).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    }
}
