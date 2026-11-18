/*
 * MCP Prompt Registry for managing available prompts.
 */
package ghidrassistmcp.prompts;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import io.modelcontextprotocol.modern.McpSchema;

/**
 * Registry for MCP prompts that can be queried by clients.
 */
public class McpPromptRegistry {

    private final Map<String, McpPrompt> prompts = new ConcurrentHashMap<>();

    /**
     * Register a prompt
     */
    public void registerPrompt(McpPrompt prompt) {
        prompts.put(prompt.getName(), prompt);
        Msg.info(this, "Registered MCP prompt: " + prompt.getName());
    }

    /**
     * Unregister a prompt
     */
    public void unregisterPrompt(String name) {
        McpPrompt removed = prompts.remove(name);
        if (removed != null) {
            Msg.info(this, "Unregistered MCP prompt: " + name);
        }
    }

    /**
     * Get a prompt by name
     */
    public McpPrompt getPrompt(String name) {
        return prompts.get(name);
    }

    /**
     * Get all registered prompts
     */
    public List<McpPrompt> getAllPrompts() {
        return new ArrayList<>(prompts.values());
    }

    /**
     * Execute a prompt and return the result
     */
    public McpSchema.GetPromptResult executePrompt(String name, Map<String, String> arguments, Program program) {
        McpPrompt prompt = prompts.get(name);
        if (prompt == null) {
            Msg.warn(this, "Prompt not found: " + name);
            return McpSchema.GetPromptResult.builder(List.of(new McpSchema.PromptMessage(
                    McpSchema.Role.USER,
                    McpSchema.TextContent.builder("Error: Prompt not found: " + name).build()
                ))).description("Error: Prompt not found: " + name).build();
        }

        return prompt.generatePrompt(arguments, program);
    }

    /**
     * Get the number of registered prompts
     */
    public int getPromptCount() {
        return prompts.size();
    }
}
