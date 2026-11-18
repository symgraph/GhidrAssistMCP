/*
 *
 */
package ghidrassistmcp;

import java.time.Duration;
import java.util.List;
import java.util.EnumSet;
import java.net.URI;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee11.servlet.ServletContextHandler;
import org.eclipse.jetty.ee11.servlet.ServletHolder;
import org.eclipse.jetty.ee11.servlet.FilterHolder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.modern.McpException;
import io.modelcontextprotocol.modern.McpSchema.CacheScope;
import io.modelcontextprotocol.modern.McpSchema.CallToolOutcome;
import io.modelcontextprotocol.modern.McpSchema.CallToolRequest;
import io.modelcontextprotocol.modern.McpSchema.CallToolResult;
import io.modelcontextprotocol.modern.McpSchema.GetPromptResult;
import io.modelcontextprotocol.modern.McpSchema.Implementation;
import io.modelcontextprotocol.modern.McpSchema.Prompt;
import io.modelcontextprotocol.modern.McpSchema.PromptArgument;
import io.modelcontextprotocol.modern.McpSchema.ReadResourceResult;
import io.modelcontextprotocol.modern.McpSchema.ResourceTemplate;
import io.modelcontextprotocol.modern.McpSchema.TextResourceContents;
import io.modelcontextprotocol.modern.McpSchema.Tool;
import io.modelcontextprotocol.modern.server.McpRequestContext;
import io.modelcontextprotocol.modern.server.McpServer;
import io.modelcontextprotocol.modern.server.McpSyncResponse;
import io.modelcontextprotocol.modern.server.feature.McpChangeFeed;
import io.modelcontextprotocol.modern.server.feature.McpSyncPrompt;
import io.modelcontextprotocol.modern.server.feature.McpSyncPromptRepository;
import io.modelcontextprotocol.modern.server.feature.McpSyncResource;
import io.modelcontextprotocol.modern.server.feature.McpSyncResourceRepository;
import io.modelcontextprotocol.modern.server.feature.McpSyncTool;
import io.modelcontextprotocol.modern.server.feature.McpSyncToolRepository;
import io.modelcontextprotocol.modern.server.feature.PromptsFeature;
import io.modelcontextprotocol.modern.server.feature.PromptsPage;
import io.modelcontextprotocol.modern.server.feature.ResourceTemplatesPage;
import io.modelcontextprotocol.modern.server.feature.ResourcesFeature;
import io.modelcontextprotocol.modern.server.feature.ResourcesPage;
import io.modelcontextprotocol.modern.server.feature.ServerChange;
import io.modelcontextprotocol.modern.server.feature.ToolsFeature;
import io.modelcontextprotocol.modern.server.feature.ToolsPage;
import io.modelcontextprotocol.modern.server.transport.HttpServletMcpTransport;
import io.modelcontextprotocol.server.transport.ServerHttpHeaderValidator;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpSchema;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.protocol.McpProgressMonitor;

/**
 * Stateless MCP {@code 2026-07-28} server over Streamable HTTP at {@code /mcp}.
 * The backend keeps the SDK's classic schema types; this class converts them at the
 * protocol boundary and delegates all business logic to McpBackend.
 */
public class GhidrAssistMCPServer {

    private static final String MCP_ENDPOINT = "/mcp";
    private static final String INSTRUCTIONS =
        "Use explicit verb-noun tools such as get_pseudocode and get_disassembly. " +
        "Use list_project_files and open_program to begin; list_open_programs shows open targets. " +
        "Pass a unique program_name Project Path when several programs are open. " +
        "Modification tools change the Ghidra database. Long operations return a task handle; " +
        "poll get_task_status to retrieve their result.";

    private final McpBackend backend;
    private final GhidrAssistMCPProvider provider;
    private Server jettyServer;
    private HttpServletMcpTransport transport;
    private McpChangeFeed changes;
    private JacksonMcpJsonMapper mapper;
    private final Runnable catalogListener = this::refreshToolCatalog;
    private final String host;
    private final int port;

    public GhidrAssistMCPServer(String host, int port, McpBackend backend) {
        this(host, port, backend, null);
    }

    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this.host = host;
        this.port = port;
        this.backend = backend;
        this.provider = provider;
    }

    public synchronized void start() throws Exception {
        Msg.info(this, "Starting MCP Server initialization...");

        try {
            // Create Jetty server
            Msg.info(this, "Creating Jetty server on port " + port);
            jettyServer = new Server();

            ServerConnector connector = new ServerConnector(jettyServer);
            connector.setHost(host);
            connector.setPort(port);
            jettyServer.addConnector(connector);

            // Create servlet context
            Msg.info(this, "Setting up servlet context");
            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
            context.setContextPath("/");
            jettyServer.setHandler(context);
            // This filter is the only origin check; the transport's own validator is disabled.
            FilterHolder originFilter = new FilterHolder((request, response, chain) -> {
                HttpServletRequest httpRequest = (HttpServletRequest) request;
                String origin = httpRequest.getHeader("Origin");
                if (origin != null && !isAllowedOrigin(origin, httpRequest)) {
                    ((HttpServletResponse) response).sendError(403, "Origin is not allowed");
                    return;
                }
                chain.doFilter(request, response);
            });
            originFilter.setAsyncSupported(true);
            context.addFilter(originFilter, "/*", EnumSet.of(DispatcherType.REQUEST));

            // Custom ObjectMapper that ignores unknown properties
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            mapper = new JacksonMcpJsonMapper(objectMapper);
            changes = new McpChangeFeed();

            // Repositories read the backend on every request, so catalog changes need no rebuild.
            Msg.info(this, "Building MCP server with backend tools");
            var serverBuilder = McpServer.builder()
                .serverInfo(convert(backend.getServerInfo(), Implementation.class))
                .instructions(INSTRUCTIONS)
                .jsonMapper(mapper)
                .feature(ToolsFeature.ofSync(new ToolRepository(), mapper,
                    McpJsonDefaults.getSchemaValidator(), 0L, CacheScope.PRIVATE))
                .subscriptions(changes);

            // Register MCP resources and prompts if backend supports them
            if (backend instanceof GhidrAssistMCPBackend ghidraBackend) {
                serverBuilder.feature(ResourcesFeature.ofSync(new ResourceRepository(ghidraBackend), mapper,
                    0L, CacheScope.PRIVATE));
                serverBuilder.feature(PromptsFeature.ofSync(new PromptRepository(ghidraBackend), mapper,
                    0L, CacheScope.PRIVATE));
            }

            transport = HttpServletMcpTransport.builder(serverBuilder.build())
                .jsonMapper(mapper)
                .endpoint(MCP_ENDPOINT)
                .httpHeaderValidator(ServerHttpHeaderValidator.NOOP)
                .keepAliveInterval(Duration.ofSeconds(15))
                .build();
            if (backend instanceof GhidrAssistMCPBackend ghidraBackend) {
                ghidraBackend.addToolCatalogListener(catalogListener);
            }

            ServletHolder mcpServletHolder = new ServletHolder("mcp-transport", transport);
            mcpServletHolder.setAsyncSupported(true);
            context.addServlet(mcpServletHolder, MCP_ENDPOINT);
            Msg.info(this, "Registered MCP servlet mapping: " + MCP_ENDPOINT);

            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();

            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP endpoint: http://" + host + ":" + port + MCP_ENDPOINT);
                Msg.info(this, "Server state: " + jettyServer.getState());

                // Log server startup to UI
                if (provider != null) {
                    provider.logSession("Jetty server listening on port " + port);
                    provider.logSession("Registered " + backend.getAvailableTools().size() + " MCP tools");
                    provider.logSession("Ready for MCP client connections");
                }
            } else {
                Msg.error(this, "Failed to start Jetty server - server not in started state");
            }

        } catch (Exception e) {
            Msg.error(this, "Exception during MCP Server startup: " + e.getMessage(), e);
            try {
                stop();
            } catch (Exception stopError) {
                e.addSuppressed(stopError);
            }
            throw e;
        }
    }

    public synchronized void stop() throws Exception {
        if (backend instanceof GhidrAssistMCPBackend ghidraBackend) {
            ghidraBackend.removeToolCatalogListener(catalogListener);
        }
        Exception failure = null;
        if (transport != null) {
            try {
                // Ends open subscriptions/listen streams before Jetty closes their connections.
                transport.closeGracefully();
            } catch (Exception error) {
                failure = error;
            }
        }
        transport = null;
        changes = null;
        if (jettyServer != null) {
            try {
                jettyServer.stop();
                Msg.info(this, "GhidrAssistMCP Server stopped");
            } catch (Exception error) {
                if (failure == null) {
                    failure = error;
                } else {
                    failure.addSuppressed(error);
                }
            } finally {
                jettyServer = null;
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    /** Port assigned by Jetty, including an ephemeral test port requested as zero. */
    public int getBoundPort() {
        if (jettyServer == null || jettyServer.getConnectors().length == 0) {
            return -1;
        }
        return ((ServerConnector) jettyServer.getConnectors()[0]).getLocalPort();
    }

    /** Tell subscribed clients to re-list tools; tools/list always reads the live catalog. */
    public synchronized void refreshToolCatalog() {
        if (changes != null) {
            changes.broadcast(new ServerChange.ToolsListChanged());
        }
    }

    /** Monitored tools return their final result on the originating protocol request. */
    private McpSyncResponse<CallToolOutcome> callTool(String name, McpRequestContext ctx,
            CallToolRequest request) {
        Object token = ctx.progressToken();
        Map<String, Object> arguments = request.arguments();
        if (!backend.supportsRequestMonitoring(name)) {
            return McpSyncResponse.result(toolResult(backend.callTool(name, arguments)));
        }
        if (!McpProgressMonitor.supportsToken(token)) {
            return McpSyncResponse.result(toolResult(
                backend.callToolMonitored(name, arguments, TaskMonitor.DUMMY)));
        }
        return McpSyncResponse.streaming(notifier -> {
            try (McpProgressMonitor monitor = new McpProgressMonitor(token, progress ->
                    notifier.progress(progress.progress(), progress.total(), progress.message()))) {
                return toolResult(backend.callToolMonitored(name, arguments, monitor));
            }
        });
    }

    private CallToolResult toolResult(McpSchema.CallToolResult result) {
        return convert(result, CallToolResult.class);
    }

    /** Classic and modern schema records share their wire form, so convert through JSON. */
    private <T> T convert(Object value, Class<T> type) {
        return mapper.convertValue(value, type);
    }

    /** Native MCP clients omit Origin; browser clients must use the bound local origin. */
    private boolean isAllowedOrigin(String value, HttpServletRequest request) {
        try {
            URI origin = URI.create(value);
            String originHost = origin.getHost();
            boolean loopbackBinding = "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host) || "::1".equals(host);
            boolean allowedHost = host.equalsIgnoreCase(originHost)
                || (loopbackBinding && ("localhost".equalsIgnoreCase(originHost)
                    || "127.0.0.1".equals(originHost) || "[::1]".equals(originHost)
                    || "::1".equals(originHost)));
            int originPort = origin.getPort() >= 0 ? origin.getPort()
                : "https".equalsIgnoreCase(origin.getScheme()) ? 443 : 80;
            return allowedHost && originPort == request.getLocalPort()
                && request.getScheme().equalsIgnoreCase(origin.getScheme())
                && origin.getRawUserInfo() == null && origin.getRawQuery() == null
                && origin.getRawFragment() == null
                && (origin.getRawPath() == null || origin.getRawPath().isEmpty());
        } catch (IllegalArgumentException error) {
            return false;
        }
    }

    public void setCurrentProgram(Program program) {
        backend.onProgramActivated(program);
    }

    /** Enabled backend tools, read live so settings changes apply to the next request. */
    private final class ToolRepository implements McpSyncToolRepository {
        @Override
        public ToolsPage list(McpRequestContext ctx, String cursor) {
            return ToolsPage.of(backend.getAvailableTools().stream()
                .map(tool -> convert(tool, Tool.class)).toList());
        }

        @Override
        public McpSyncTool find(McpRequestContext ctx, String name) {
            for (McpSchema.Tool tool : backend.getAvailableTools()) {
                if (tool.name().equals(name)) {
                    return McpSyncTool.of(convert(tool, Tool.class),
                        (callContext, request) -> callTool(name, callContext, request));
                }
            }
            return null;
        }
    }

    /** Program resources are URI templates; there are no concrete resources to list. */
    private final class ResourceRepository implements McpSyncResourceRepository {
        private final GhidrAssistMCPBackend ghidraBackend;

        ResourceRepository(GhidrAssistMCPBackend ghidraBackend) {
            this.ghidraBackend = ghidraBackend;
        }

        @Override
        public ResourcesPage list(McpRequestContext ctx, String cursor) {
            return ResourcesPage.of(List.of());
        }

        @Override
        public ResourceTemplatesPage listTemplates(McpRequestContext ctx, String cursor) {
            return ResourceTemplatesPage.of(ghidraBackend.getAvailableResources().stream()
                .map(resource -> ResourceTemplate.builder(resource.getUriPattern(), resource.getName())
                    .description(resource.getDescription())
                    .mimeType(resource.getMimeType())
                    .build())
                .toList());
        }

        @Override
        public McpSyncResource find(McpRequestContext ctx, String uri) {
            McpResource resource = ghidraBackend.getResourceRegistry().findResource(uri);
            if (resource == null) {
                return null;
            }
            return McpSyncResource.of((readContext, request) -> {
                String content;
                try {
                    content = ghidraBackend.readResource(uri);
                } catch (McpError notFound) {
                    content = null;
                }
                if (content == null) {
                    throw McpException.invalidParams("Unknown resource: " + uri, Map.of("uri", uri));
                }
                return McpSyncResponse.result(ReadResourceResult.builder(List.of(
                    TextResourceContents.builder(uri, content).mimeType(resource.getMimeType()).build()))
                    .build());
            });
        }
    }

    private final class PromptRepository implements McpSyncPromptRepository {
        private final GhidrAssistMCPBackend ghidraBackend;

        PromptRepository(GhidrAssistMCPBackend ghidraBackend) {
            this.ghidraBackend = ghidraBackend;
        }

        @Override
        public PromptsPage list(McpRequestContext ctx, String cursor) {
            return PromptsPage.of(ghidraBackend.getAvailablePrompts().stream()
                .map(this::definition).toList());
        }

        @Override
        public McpSyncPrompt find(McpRequestContext ctx, String name) {
            for (McpPrompt prompt : ghidraBackend.getAvailablePrompts()) {
                if (prompt.getName().equals(name)) {
                    return McpSyncPrompt.of(definition(prompt), (getContext, request) -> {
                        Map<String, String> args = request.arguments() != null
                            ? new java.util.HashMap<>(request.arguments()) : new java.util.HashMap<>();
                        return McpSyncResponse.result(convert(ghidraBackend.generatePrompt(prompt, args),
                            GetPromptResult.class));
                    });
                }
            }
            return null;
        }

        private Prompt definition(McpPrompt prompt) {
            return Prompt.builder(prompt.getName())
                .description(prompt.getDescription())
                .arguments(prompt.getArguments().stream()
                    .map(argument -> convert(argument, PromptArgument.class)).toList())
                .build();
        }
    }
}
