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
import java.util.function.BiFunction;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee11.servlet.ServletContextHandler;
import org.eclipse.jetty.ee11.servlet.ServletHolder;
import org.eclipse.jetty.ee11.servlet.FilterHolder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.protocol.McpProgressMonitor;

/**
 * Refactored MCP Server implementation that uses the backend architecture.
 * This class handles HTTP transport and delegates business logic to McpBackend.
 */
public class GhidrAssistMCPServer {
    
    private final McpBackend backend;
    private final GhidrAssistMCPProvider provider;
    private Server jettyServer;
    private McpSyncServer sseServer;
    private McpSyncServer streamableServer;
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
            context.addFilter(new FilterHolder((request, response, chain) -> {
                HttpServletRequest httpRequest = (HttpServletRequest) request;
                String origin = httpRequest.getHeader("Origin");
                if (origin != null && !isAllowedOrigin(origin, httpRequest)) {
                    ((HttpServletResponse) response).sendError(403, "Origin is not allowed");
                    return;
                }
                chain.doFilter(request, response);
            }), "/*", EnumSet.of(DispatcherType.REQUEST));
            
            // Create MCP transport provider using custom ObjectMapper that ignores unknown properties
            Msg.info(this, "Creating MCP transport provider");
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            JacksonMcpJsonMapper mapper = new JacksonMcpJsonMapper(objectMapper);
            String messageEndpoint = "/message";
            String mcpEndpoint = "/mcp";

            HttpServletSseServerTransportProvider sseTransportProvider =
                HttpServletSseServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .messageEndpoint(messageEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            HttpServletStreamableServerTransportProvider streamableTransportProvider =
                HttpServletStreamableServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .mcpEndpoint(mcpEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .build();

            // Build MCP server using backend for configuration
            Msg.info(this, "Building MCP server with backend tools");
            var sseServerBuilder = McpServer.sync(sseTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities())
                .instructions("Use explicit verb-noun tools such as get_pseudocode and get_disassembly. " +
                    "Use list_project_files and open_program to begin; list_open_programs shows open targets. " +
                    "Pass a unique program_name Project Path when several programs are open. " +
                    "Modification tools change the Ghidra database. Long operations return a task handle; " +
                    "poll get_task_status to retrieve their result.");

            var streamableServerBuilder = McpServer.sync(streamableTransportProvider)
                .serverInfo(backend.getServerInfo())
                .capabilities(backend.getCapabilities())
                .instructions("Use explicit verb-noun tools such as get_pseudocode and get_disassembly. " +
                    "Use list_project_files and open_program to begin; list_open_programs shows open targets. " +
                    "Pass a unique program_name Project Path when several programs are open. " +
                    "Modification tools change the Ghidra database. Long operations return a task handle; " +
                    "poll get_task_status to retrieve their result.");

            // Register each tool individually with its own handler
            for (McpSchema.Tool toolSchema : backend.getAvailableTools()) {
                String toolName = toolSchema.name();
                BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> toolHandler =
                    (exchange, request) -> callTool(toolName, exchange, request);

                sseServerBuilder.toolCall(toolSchema, toolHandler);
                streamableServerBuilder.toolCall(toolSchema, toolHandler);
                Msg.info(this, "Registered tool with MCP server: " + toolName);
            }

            // Register MCP resources and prompts if backend supports them
            if (backend instanceof GhidrAssistMCPBackend) {
                GhidrAssistMCPBackend ghidraBackend = (GhidrAssistMCPBackend) backend;
                registerResources(sseServerBuilder, streamableServerBuilder, ghidraBackend);
                registerPrompts(sseServerBuilder, streamableServerBuilder, ghidraBackend);
            }

            sseServer = sseServerBuilder.build();
            streamableServer = streamableServerBuilder.build();
            if (backend instanceof GhidrAssistMCPBackend ghidraBackend) {
                ghidraBackend.addToolCatalogListener(catalogListener);
            }
            
            // Register MCP servlet - use root path since transport provider handles routing internally
            Msg.info(this, "Registering MCP servlet");
            
            try {
                ServletHolder mcpSseServletHolder = new ServletHolder("mcp-sse-transport", sseTransportProvider);
                mcpSseServletHolder.setAsyncSupported(true);
                context.addServlet(mcpSseServletHolder, "/sse");
                context.addServlet(mcpSseServletHolder, messageEndpoint);

                ServletHolder mcpStreamableServletHolder = new ServletHolder("mcp-streamable-transport", streamableTransportProvider);
                mcpStreamableServletHolder.setAsyncSupported(true);
                context.addServlet(mcpStreamableServletHolder, "/mcp/*");
                Msg.info(this, "Registered MCP SSE servlet mapping: /*");
                Msg.info(this, "Registered MCP Streamable servlet mapping: /mcp/*");
                
                // Log configuration
                Msg.info(this, "Transport provider class: " + sseTransportProvider.getClass().getName());
                Msg.info(this, "Message endpoint configured as: " + messageEndpoint);
                Msg.info(this, "SSE endpoint will be: /sse (default)");
                Msg.info(this, "Expected client URLs:");
                Msg.info(this, "  SSE: http://" + host + ":" + port + "/sse");
                Msg.info(this, "  Messages: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "Streamable HTTP transport provider class: " + streamableTransportProvider.getClass().getName());
                Msg.info(this, "Streamable MCP endpoint: http://" + host + ":" + port + mcpEndpoint);
                
            } catch (Exception e) {
                Msg.error(this, "Failed to register MCP servlet", e);
                throw e;
            }
            
            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();
            
            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP SSE endpoint: http://" + host + ":" + port + "/sse");
                Msg.info(this, "MCP message endpoint: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "MCP Streamable endpoint: http://" + host + ":" + port + mcpEndpoint);
                Msg.info(this, "Server state: " + jettyServer.getState());
                
                // Log all registered servlets
                var servletHandler = context.getServletHandler();
                var servletMappings = servletHandler.getServletMappings();
                Msg.info(this, "Registered servlet mappings:");
                for (var mapping : servletMappings) {
                    Msg.info(this, "  " + mapping.getServletName() + " -> " + String.join(", ", mapping.getPathSpecs()));
                }
                
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
        for (McpSyncServer server : new McpSyncServer[] { sseServer, streamableServer }) {
            if (server != null) {
                try {
                    server.closeGracefully();
                } catch (Exception error) {
                    if (failure == null) {
                        failure = error;
                    } else {
                        failure.addSuppressed(error);
                    }
                }
            }
        }
        sseServer = null;
        streamableServer = null;
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

    /** Refresh enabled tools in both live transports; SDK emits list-changed notifications. */
    public synchronized void refreshToolCatalog() {
        List<McpSchema.Tool> available = backend.getAvailableTools();
        for (McpSyncServer server : new McpSyncServer[] { sseServer, streamableServer }) {
            if (server == null) {
                continue;
            }
            var existing = new java.util.HashSet<String>();
            for (McpSchema.Tool tool : server.listTools()) {
                existing.add(tool.name());
                if (available.stream().noneMatch(candidate -> candidate.name().equals(tool.name()))) {
                    server.removeTool(tool.name());
                }
            }
            for (McpSchema.Tool tool : available) {
                if (!existing.contains(tool.name())) {
                    server.addTool(new McpServerFeatures.SyncToolSpecification(tool,
                        (exchange, request) -> callTool(tool.name(), exchange, request)));
                }
            }
        }
    }

    /** Monitored tools return their final result on the originating protocol request. */
    private McpSchema.CallToolResult callTool(String name, McpSyncServerExchange exchange,
            McpSchema.CallToolRequest request) {
        Object token = request.progressToken();
        if (!backend.supportsRequestMonitoring(name)) {
            return backend.callTool(name, request.arguments());
        }
        if (!McpProgressMonitor.supportsToken(token)) {
            return backend.callToolMonitored(name, request.arguments(), TaskMonitor.DUMMY);
        }
        try (McpProgressMonitor monitor = new McpProgressMonitor(token, exchange::progressNotification)) {
            return backend.callToolMonitored(name, request.arguments(), monitor);
        }
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

    /**
     * Register MCP prompts with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerPrompts(McpServer.SyncSpecification sseServerBuilder,
                                  McpServer.SyncSpecification streamableServerBuilder,
                                  GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpPrompt> prompts = ghidraBackend.getAvailablePrompts();
            java.util.List<McpServerFeatures.SyncPromptSpecification> promptSpecs = new java.util.ArrayList<>();

            for (McpPrompt prompt : prompts) {
                // Create McpSchema.Prompt for each prompt
                McpSchema.Prompt mcpPrompt = new McpSchema.Prompt(
                    prompt.getName(),
                    prompt.getDescription(),
                    prompt.getArguments()
                );

                // Create handler for getting the prompt
                BiFunction<McpSyncServerExchange, McpSchema.GetPromptRequest, McpSchema.GetPromptResult> promptHandler =
                    (exchange, request) -> {
                        Map<String, Object> rawArgs = request.arguments();
                        Map<String, String> args = new java.util.HashMap<>();
                        if (rawArgs != null) {
                            for (Map.Entry<String, Object> entry : rawArgs.entrySet()) {
                                args.put(entry.getKey(), entry.getValue() != null ? entry.getValue().toString() : null);
                            }
                        }
                        return ghidraBackend.generatePrompt(prompt, args);
                    };

                // Create specification
                McpServerFeatures.SyncPromptSpecification spec =
                    new McpServerFeatures.SyncPromptSpecification(mcpPrompt, promptHandler);
                promptSpecs.add(spec);
                Msg.info(this, "Prepared prompt for registration: " + prompt.getName());
            }

            // Register all prompts with both builders
            if (!promptSpecs.isEmpty()) {
                sseServerBuilder.prompts(promptSpecs);
                streamableServerBuilder.prompts(promptSpecs);
                Msg.info(this, "Registered " + promptSpecs.size() + " MCP prompts");
            }

        } catch (Exception e) {
            Msg.warn(this, "Failed to register MCP prompts: " + e.getMessage(), e);
        }
    }

    /**
     * Register MCP resources with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerResources(McpServer.SyncSpecification sseServerBuilder,
                                   McpServer.SyncSpecification streamableServerBuilder,
                                   GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpResource> resources = ghidraBackend.getAvailableResources();
            java.util.List<McpServerFeatures.SyncResourceTemplateSpecification> resourceSpecs = new java.util.ArrayList<>();

            for (McpResource resource : resources) {
                // Create McpSchema.Resource for each resource
                McpSchema.ResourceTemplate mcpResource = McpSchema.ResourceTemplate.builder()
                    .uriTemplate(resource.getUriPattern())
                    .name(resource.getName())
                    .description(resource.getDescription())
                    .mimeType(resource.getMimeType())
                    .build();

                // Create handler for reading the resource
                BiFunction<McpSyncServerExchange, McpSchema.ReadResourceRequest, McpSchema.ReadResourceResult> readHandler =
                    (exchange, request) -> {
                        String uri = request.uri();
                        String content = ghidraBackend.readResource(uri);

                        if (content == null) {
                            throw McpError.RESOURCE_NOT_FOUND.apply(uri);
                        }

                        McpSchema.ResourceContents contents = new McpSchema.TextResourceContents(
                            uri,
                            resource.getMimeType(),
                            content
                        );

                        return new McpSchema.ReadResourceResult(List.of(contents));
                    };

                // Create specification
                McpServerFeatures.SyncResourceTemplateSpecification spec =
                    new McpServerFeatures.SyncResourceTemplateSpecification(mcpResource, readHandler);
                resourceSpecs.add(spec);
                Msg.info(this, "Prepared resource for registration: " + resource.getName());
            }

            // Register all resources with both builders
            if (!resourceSpecs.isEmpty()) {
                sseServerBuilder.resourceTemplates(resourceSpecs);
                streamableServerBuilder.resourceTemplates(resourceSpecs);
                Msg.info(this, "Registered " + resourceSpecs.size() + " MCP resources");
            }

        } catch (Exception e) {
            Msg.warn(this, "Failed to register MCP resources: " + e.getMessage(), e);
        }
    }
}
