/* 
 * 
 */
package ghidrassistmcp;

import java.util.List;
import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Interface for the MCP backend that handles tool management and execution.
 * This provides separation between the HTTP transport layer and business logic.
 */
public interface McpBackend {
    
    /**
     * Register a new MCP tool
     */
    void registerTool(McpTool tool);
    
    /**
     * Unregister an MCP tool by name
     */
    void unregisterTool(String toolName);
    
    /**
     * Get list of all available tools
     */
    List<McpSchema.Tool> getAvailableTools();
    
    /**
     * Execute a tool with given arguments
     */
    McpSchema.CallToolResult callTool(String toolName, Map<String, Object> arguments);

    /** Opt-in tools finish on the originating MCP request, with or without a progress token. */
    default boolean supportsRequestMonitoring(String toolName) { return false; }

    default McpSchema.CallToolResult callToolMonitored(String toolName,
            Map<String, Object> arguments, TaskMonitor monitor) {
        return callTool(toolName, arguments);
    }
    
    /**
     * Notify backend when a program is activated
     */
    void onProgramActivated(Program program);
    
    /**
     * Notify backend when a program is deactivated
     */
    void onProgramDeactivated(Program program);
    
    /**
     * Get server implementation info
     */
    McpSchema.Implementation getServerInfo();
    
    /**
     * Get server capabilities
     */
    McpSchema.ServerCapabilities getCapabilities();
}
