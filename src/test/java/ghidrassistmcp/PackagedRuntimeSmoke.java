package ghidrassistmcp;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;

/** No SDK imports: all calls target the actual relocated classes in the packaged jar. */
public final class PackagedRuntimeSmoke {
    // Stateless MCP 2026-07-28: every request names its revision and client capabilities.
    private static final String META = "\"_meta\":{"
        + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
        + "\"io.modelcontextprotocol/clientCapabilities\":{},"
        + "\"io.modelcontextprotocol/clientInfo\":{\"name\":\"packaged-smoke\",\"version\":\"1\"}}";

    public static void main(String[] arguments) throws Exception {
        // Force the host's shared Jackson classes to load before any extension classes.
        try {
            Class<?> hostParser = Class.forName("com.fasterxml.jackson.core.JsonParser");
            String hostSource = hostParser.getProtectionDomain().getCodeSource().getLocation().toString();
            require(!hostSource.contains("GhidrAssistMCP"), "Host parser must come from Ghidra: " + hostSource);
            System.out.println("Host JsonParser: " + hostSource);
        } catch (ClassNotFoundException absent) {
            // Ghidra 12.1 no longer supplies the older Jackson 2 parser. Its real
            // host classpath must still run the private, self-contained runtime.
            System.out.println("Host has no shared Jackson 2 parser");
        }
        String[] dependencies = {
            "ghidrassistmcp.internal.jackson2.core.JsonParser",
            "ghidrassistmcp.internal.jackson2.databind.ObjectMapper",
            "ghidrassistmcp.internal.mcp.spec.McpSchema",
            "ghidrassistmcp.internal.mcp.modern.server.McpServer",
            "ghidrassistmcp.internal.networknt.schema.SchemaRegistry",
            "ghidrassistmcp.internal.jetty.server.Server",
            "ghidrassistmcp.internal.slf4j.Logger",
            "ghidrassistmcp.internal.reactor.core.publisher.Mono",
            "ghidrassistmcp.internal.servlet.http.HttpServlet"
        };
        URI artifact = Path.of(System.getProperty("mcp.packagedJar")).toUri();
        for (String dependency : dependencies) {
            Class<?> type = Class.forName(dependency);
            URI source = type.getProtectionDomain().getCodeSource().getLocation().toURI();
            require(Path.of(source).equals(Path.of(artifact)), "Dependency escaped packaged jar: " + dependency);
        }
        Class<?> backendClass = Class.forName("ghidrassistmcp.GhidrAssistMCPBackend");
        Object backend = backendClass.getConstructor().newInstance();
        Class<?> serverClass = Class.forName("ghidrassistmcp.GhidrAssistMCPServer");
        Object server = serverClass.getConstructor(String.class, int.class,
            Class.forName("ghidrassistmcp.McpBackend")).newInstance("127.0.0.1", 0, backend);
        try {
            serverClass.getMethod("start").invoke(server);
            int port = (Integer) serverClass.getMethod("getBoundPort").invoke(server);
            URI endpoint = URI.create("http://127.0.0.1:" + port + "/mcp");
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            HttpResponse<String> discovered = send(client, endpoint, "server/discover", null,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{" + META + "}}");
            require(discovered.statusCode() == 200, discovered.body());
            require(compact(discovered.body()).contains("\"supportedVersions\":[\"2026-07-28\"]"), discovered.body());
            HttpResponse<String> tools = send(client, endpoint, "tools/list", null,
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{" + META + "}}");
            require(tools.statusCode() == 200, tools.body());
            require(tools.body().contains("get_pseudocode") && tools.body().contains("get_function_hash"), tools.body());
            HttpResponse<String> result = send(client, endpoint, "tools/call", "get_pseudocode",
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{"
                + "\"name\":\"get_pseudocode\",\"arguments\":{\"function\":\"example\"}," + META + "}}");
            require(result.statusCode() == 200 && compact(result.body()).contains("\"isError\":true"), result.body());
            System.out.println("PACKAGED_RUNTIME_OK");
        } finally {
            try {
                serverClass.getMethod("stop").invoke(server);
            } finally {
                backendClass.getMethod("shutdown").invoke(backend);
            }
        }
    }

    private static HttpResponse<String> send(HttpClient client, URI endpoint, String method, String name,
            String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5)).header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("Mcp-Method", method)
            .header("MCP-Protocol-Version", "2026-07-28");
        if (name != null) {
            request.header("Mcp-Name", name);
        }
        return client.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString());
    }

    private static String compact(String value) { return value.replaceAll("\\s+", ""); }
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
