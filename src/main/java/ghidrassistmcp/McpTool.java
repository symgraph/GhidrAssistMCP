/* 
 * 
 */
package ghidrassistmcp;

import java.util.Map;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Interface for individual MCP tools that can be registered with the backend.
 */
public interface McpTool {

    /**
     * Get the tool name (used for MCP tool calls)
     */
    String getName();

    /**
     * Get the tool description
     */
    String getDescription();

    /**
     * Get the input schema for this tool
     */
    McpSchema.JsonSchema getInputSchema();

    /**
     * Execute the tool with given arguments and current program context
     */
    McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram);

    /**
     * Execute the tool with given arguments, program context, and backend reference for multi-program access.
     * Tools that need to access all open programs or query programs by name should override this method.
     * Tools that need UI context (current address, current function) can access the active plugin via
     * backend.getActivePlugin().
     */
    default McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        // Default implementation delegates to the original method for backward compatibility
        return execute(arguments, currentProgram);
    }

    /**
     * Execute the tool with async task context for progress reporting.
     */
    default McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                             GhidrAssistMCPBackend backend, McpTask task) {
        return execute(arguments, currentProgram, backend);
    }

    // ==================== MCP 2025-11-25 Tool Annotations ====================

    /**
     * Indicates whether the tool performs read-only operations.
     * Read-only tools do not modify the program or any external state.
     * Default: true (most Ghidra analysis tools are read-only)
     */
    default boolean isReadOnly() {
        return true;
    }

    /**
     * Indicates whether the tool is destructive.
     * Destructive tools may delete data, remove functions, or cause irreversible changes.
     * Default: false
     */
    default boolean isDestructive() {
        return false;
    }

    /**
     * Indicates whether the tool is idempotent.
     * Idempotent tools produce the same result when called multiple times with the same arguments.
     * Default: false (conservative default for modification tools)
     */
    default boolean isIdempotent() {
        return false;
    }

    /**
     * Indicates whether the tool interacts with external systems (open-world).
     * Open-world tools may make network requests, access external databases, etc.
     * Default: false (Ghidra tools typically operate on local program data)
     */
    default boolean isOpenWorld() {
        return false;
    }

    // ==================== Async Task Support ====================

    /**
     * Indicates whether the tool is potentially long-running and should be executed asynchronously.
     * Long-running tools return a task ID immediately and execute in the background.
     * Default: false
     */
    default boolean isLongRunning() {
        return false;
    }

    // ==================== Caching Support ====================

    /**
     * Indicates whether the tool's results can be cached.
     * Cacheable tools should return consistent results for the same inputs
     * as long as the program hasn't been modified.
     * Default: false (conservative default)
     */
    default boolean isCacheable() {
        return false;
    }
}
