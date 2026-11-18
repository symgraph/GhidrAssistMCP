/* 
 * 
 */
package ghidrassistmcp;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpProgramContext;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Interface for individual MCP tools that can be registered with the backend.
 */
public interface McpTool {

    /**
     * Get the tool name (used for MCP tool calls)
     */
    String getName();

    /** Original catalog name used to migrate persisted enable/disable settings. */
    default String getLegacyName() { return getName(); }

    /** Whether this operation accepts a selector for an already open program. */
    default boolean supportsProgramSelection() { return true; }

    /** Project create/open/save/close operations require exclusive MCP admission. */
    default boolean isProjectLifecycleOperation() {
        return false;
    }

    /** Whether execution needs a loaded program rather than project/server context. */
    default boolean requiresProgramContext() { return true; }

    /** Operations spanning all open programs do not require a current browser program. */
    default boolean requiresProgramContext(Map<String, Object> arguments) {
        return requiresProgramContext();
    }

    /**
     * Get the tool description
     */
    String getDescription();

    /**
     * Get the input schema for this tool
     */
    McpSchema.JsonSchema getInputSchema();

    /** Optional machine-readable schema for structuredContent returned by this tool. */
    default Map<String, Object> getOutputSchema() { return null; }

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

    /** Whether protocol calls return the full result in flight, with optional progress notifications. */
    default boolean supportsRequestMonitoring() { return false; }

    /** Execute in the originating request; the owning worker retains all program leases. */
    default McpSchema.CallToolResult executeMonitored(Map<String, Object> arguments,
            Program currentProgram, GhidrAssistMCPBackend backend, TaskMonitor monitor) {
        // This carrier is deliberately not submitted to the task manager: existing
        // task-aware tools can publish progress while the original RPC stays open.
        AtomicBoolean forwarding = new AtomicBoolean(true);
        McpTask progress = new McpTask(getName(), arguments, backend == null
                ? McpProgramContext.empty() : backend.captureProgramContext(currentProgram)) {
            @Override public synchronized void updateProgress(int percent, String message) {
                if (!forwarding.get() || getStatus() != Status.RUNNING) return;
                super.updateProgress(percent, message);
                monitor.setMessage(message);
                monitor.setProgress(getProgressPercent());
            }
        };
        progress.markStarted();
        monitor.initialize(100);
        try {
            McpSchema.CallToolResult result = execute(arguments, currentProgram, backend, progress);
            synchronized (progress) { forwarding.set(false); }
            // A returned tool error still means the work has finished; let the backend
            // preserve its error/result contract. Exceptions do not invent completion.
            if (result != null) {
                monitor.setMessage(Boolean.TRUE.equals(result.isError()) ? "Finished with errors" : "Completed");
                monitor.setProgress(100);
            }
            return result;
        } finally {
            synchronized (progress) { forwarding.set(false); }
        }
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
     * Legacy dispatch returns a task ID immediately and executes in the background.
     * Protocol calls to tools supporting request monitoring instead stay in flight.
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

    /**
     * Additional state that affects a cacheable result but is not represented by tool arguments
     * or the program modification number.
     */
    default String getCacheDiscriminator(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend) {
        return "";
    }
}
